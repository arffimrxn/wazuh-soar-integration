#!/var/ossec/framework/python/bin/python3
import sys
import os
import json
import shutil
from datetime import datetime
from fpdf import FPDF

LOG_FILE = "/var/ossec/logs/active-responses.log"
QUARANTINE_DIR = "/var/ossec/quarantine"
REPORT_DIR = "/var/ossec/logs/incident_reports"

def write_log(message):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        with open(LOG_FILE, "a") as f:
            f.write(f"{now} quarantine-killswitch: {message}\n")
    except Exception:
        pass

def generate_incident_pdf(target_file, agent_name, positives, total, file_hash):
    try:
        pdf = FPDF()
        pdf.add_page()
        pdf.set_auto_page_break(auto=True, margin=15)
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        pdf.set_font("Arial", 'B', 16)
        pdf.set_text_color(200, 0, 0)
        pdf.cell(200, 10, "CRITICAL INCIDENT: AUTOMATED REMEDIATION REPORT", ln=True, align='C')
        pdf.set_text_color(0, 0, 0)
        pdf.ln(5)
        
        pdf.set_font("Arial", 'B', 12)
        pdf.cell(50, 8, "Timestamp:")
        pdf.set_font("Arial", '', 12)
        pdf.cell(150, 8, timestamp, ln=True)
        
        pdf.set_font("Arial", 'B', 12)
        pdf.cell(50, 8, "Affected Endpoint:")
        pdf.set_font("Arial", '', 12)
        pdf.cell(150, 8, agent_name, ln=True)
        pdf.ln(5)
        
        pdf.set_font("Arial", 'B', 14)
        pdf.cell(200, 10, "Threat Intelligence (VirusTotal Data)", ln=True)
        
        pdf.set_font("Arial", 'B', 12)
        pdf.cell(50, 8, "Target File Path:")
        pdf.set_font("Arial", '', 12)
        pdf.multi_cell(140, 8, str(target_file))
        
        pdf.set_font("Arial", 'B', 12)
        pdf.cell(50, 8, "Detection Rate:")
        pdf.set_font("Arial", '', 12)
        pdf.set_text_color(200, 0, 0)
        pdf.cell(150, 8, f"{positives} / {total} Engines Flagged Malicious", ln=True)
        pdf.set_text_color(0, 0, 0)
        
        pdf.set_font("Arial", 'B', 12)
        pdf.cell(50, 8, "File Hash:")
        pdf.set_font("Arial", '', 10)
        pdf.multi_cell(140, 8, str(file_hash))
        
        # The Hyperlink Generation Block
        if file_hash and file_hash != "N/A":
            vt_link = f"https://www.virustotal.com/gui/file/{file_hash}"
            pdf.set_font("Arial", 'B', 12)
            pdf.cell(50, 8, "Analysis Link:")
            pdf.set_font("Arial", 'U', 11) 
            pdf.set_text_color(0, 0, 255)  
            pdf.cell(150, 8, "Click here to view full VirusTotal report", link=vt_link, ln=True)
            pdf.set_text_color(0, 0, 0)    
            
        pdf.ln(5)
        
        pdf.set_font("Arial", 'B', 14)
        pdf.cell(200, 10, "SOAR Remediation Action", ln=True)
        pdf.set_font("Arial", 'B', 12)
        pdf.set_text_color(0, 128, 0) 
        pdf.cell(200, 8, "SUCCESS: TARGET PAYLOAD QUARANTINED. PERMISSIONS STRIPPED TO 000.", ln=True)
        pdf.set_text_color(0, 0, 0)
        
        report_filename = f"Incident_Report_{agent_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        report_path = os.path.join(REPORT_DIR, report_filename)
        pdf.output(report_path)
        write_log(f"SUCCESS: Tactical PDF Report compiled at {report_path}")
        
    except Exception as e:
        write_log(f"Error compiling tactical PDF file: {e}")

def main():
    write_log("Active Response quarantine protocol initiated via system trigger.")

    try:
        input_str = sys.stdin.readline()
        if not input_str:
            sys.exit(1)
        payload = json.loads(input_str)
    except Exception as e:
        write_log(f"Error parsing raw JSON execution string: {e}")
        sys.exit(1)

    try:
        alert = payload.get("parameters", {}).get("alert", {})
        
        agent_name = alert.get("agent", {}).get("name", "Unknown_Asset")
        vt_data = alert.get("data", {}).get("virustotal", {})
        syscheck_data = alert.get("syscheck", {})
        
        malicious_file = vt_data.get("source", {}).get("file")
        positives = vt_data.get("positives", "N/A")
        total = vt_data.get("total", "N/A")
        
        # --- WATERFALL HASH EXTRACTION ---
        extracted_hash = (
            vt_data.get("source", {}).get("sha256") or
            syscheck_data.get("sha256_after") or
            vt_data.get("source", {}).get("sha1") or
            vt_data.get("source", {}).get("md5", "N/A")
        )
        
        if malicious_file and os.path.exists(malicious_file):
            file_name = os.path.basename(malicious_file)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            quarantine_target = os.path.join(QUARANTINE_DIR, f"locked_{timestamp}_{file_name}")
            
            shutil.move(malicious_file, quarantine_target)
            os.chmod(quarantine_target, 0o000)
            write_log(f"SUCCESS: Neutralized threat. Moved to {quarantine_target}")
            
            # Pass the extracted hash into the PDF generator
            generate_incident_pdf(malicious_file, agent_name, positives, total, extracted_hash)
            
        else:
            write_log(f"Alert: Target file '{malicious_file}' not found on disk or already processed.")
            
    except Exception as e:
        write_log(f"Execution pipeline failure: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
