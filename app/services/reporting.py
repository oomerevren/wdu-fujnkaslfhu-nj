
from typing import List, Dict, Any
from datetime import datetime

class ReportingService:
    COMPLIANCE_DETAILS = {
        'SOC2': {
            'SQLi': {
                'control': 'CC6.1 (Logical Access)',
                'description': 'The organization restricts logical access to information assets.',
                'remediation': 'Implement prepared statements and input validation.'
            },
            'XSS': {
                'control': 'CC7.1 (System Operations)',
                'description': 'The organization monitors system components for security vulnerabilities.',
                'remediation': 'Use context-aware output encoding.'
            }
        },
        'HIPAA': {
            'SQLi': {
                'control': '164.312(a)(1) (Access Control)',
                'description': 'Implement technical policies and procedures for electronic information systems.',
                'remediation': 'Apply database security patches and use ORM abstractions.'
            }
        }
    }

    def __init__(self):
        print('[Reporting-v2] Advanced Compliance Engine Initialized')

    def generate_professional_report(self, standard: str, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        standard = standard.upper()
        details = self.COMPLIANCE_DETAILS.get(standard, {})
        
        report_body = []
        for f in findings:
            f_type = f.get('type')
            mapping = details.get(f_type, {
                'control': 'General Security',
                'description': 'Basic security requirement',
                'remediation': 'Follow security best practices.'
            })
            
            report_body.append({
                'vulnerability': f_type,
                'severity': f.get('severity'),
                'control_id': mapping['control'],
                'audit_description': mapping['description'],
                'remediation_plan': mapping['remediation']
            })

        return {
            'header': {
                'title': f'PentestAI {standard} Compliance Assessment',
                'generated_at': datetime.utcnow().isoformat(),
                'status': 'AUDITOR_READY'
            },
            'body': report_body
        }

    async def export_to_html(self, report_data: Dict[str, Any]) -> str:
        # Simulation of complex HTML templating for professional reports
        html_output = f"<html><body><h1>{report_data['header']['title']}</h1>"
        for item in report_data['body']:
            html_output += f"<div class='finding'><h2>{item['vulnerability']}</h2><p>{item['remediation_plan']}</p></div>"
        html_output += "</body></html>"
        print(f"[Reporting] Professional HTML report generated ({len(html_output)} bytes)")
        return html_output
