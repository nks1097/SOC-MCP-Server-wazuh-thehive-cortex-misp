from typing import Dict, Any

class ReportGenerator:
    def __init__(self):
        pass

    def generate_technical_report(self, alert: Dict[str, Any], risk_score: int, iocs: list, case_id: str, misp_hits: int) -> str:
        report = f"# Technical Incident Report\n\n"
        report += f"## Alert Overview\n"
        report += f"- **Rule ID**: {alert.get('rule_id')}\n"
        report += f"- **Level**: {alert.get('rule_level')}\n"
        report += f"- **Description**: {alert.get('rule_description')}\n"
        report += f"- **Agent**: {alert.get('agent_name')} ({alert.get('agent_id')})\n"
        report += f"- **Risk Score**: {risk_score}/100\n\n"
        
        report += f"## Correlated Intelligence\n"
        report += f"- **MISP Hits**: {misp_hits}\n"
        report += f"- **TheHive Case**: {case_id or 'Not created'}\n\n"
        
        report += f"## Extracted IOCs\n"
        for ioc in iocs:
            report += f"- `{ioc['value']}` ({ioc['type']})\n"
            
        report += f"\n## Recommendations\n"
        if risk_score > 50:
            report += "- Isolate the agent immediately using Wazuh Active Response.\n"
            report += "- Block IPs identified in MISP at the perimeter firewall.\n"
            report += "- Trigger deeper memory analysis via Velociraptor.\n"
        else:
            report += "- Monitor the agent for further anomalous activity.\n"
            
        return report

    def generate_executive_report(self, alert: Dict[str, Any], risk_score: int) -> str:
        severity = "High" if risk_score > 70 else "Medium" if risk_score > 40 else "Low"
        
        report = f"# Executive Summary: Security Incident\n\n"
        report += f"Our Security Operations Center (SOC) detected an incident classified as **{severity} Risk** (Score: {risk_score}/100).\n\n"
        
        report += f"**Impacted Asset:** {alert.get('agent_name', 'Unknown')}\n"
        report += f"**Threat Description:** {alert.get('rule_description', 'Anomalous activity detected.')}\n\n"
        
        report += f"**Status:** The SOC AI agent has automatically correlated the threat against global threat intelligence databases (MISP) and initiated incident response protocols.\n\n"
        
        if risk_score > 50:
            report += f"**Actions Taken:** A case was automatically opened in the incident management system. The security team has been notified to execute containment procedures.\n"
        else:
            report += f"**Actions Taken:** The event is being monitored and was documented for historical correlation.\n"
            
        return report
