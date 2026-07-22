from typing import List, Dict, Any
import datetime
from app.core.logging import logger

class ReportService:
    def __init__(self):
        self.template_name = "report.html"

    async def generate_scan_pdf(self, scan_data: Dict[str, Any], findings: List[Dict[str, Any]]) -> bytes:
        """
        Generates a PDF report for a specific scan.
        In production, this utilizes WeasyPrint to convert HTML templates to PDF.
        """
        logger.info(f"Generating PDF report for scan: {scan_data.get('id')}")

        # Mock PDF generation by creating a text-based representation
        report_header = f"PENTESTAI SECURITY REPORT
"
        report_header += f"Generated: {datetime.datetime.now().isoformat()}
"
        report_header += f"Target: {scan_data.get('target_url')}
"
        report_header += "="*30 + "
"

        finding_details = ""
        for f in findings:
            finding_details += f"[-] Finding: {f.get('name')}
"
            finding_details += f"    Severity: {f.get('severity')}
"
            finding_details += f"    Description: {f.get('description')[:100]}...

"

        # Combine and return as bytes (simulating PDF output)
        full_report = report_header + finding_details
        return full_report.encode('utf-8')