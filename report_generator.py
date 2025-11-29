"""
Automated PDF Report Generator
Generates security reports with custom logo
"""
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.pdfgen import canvas
from datetime import datetime
from typing import List, Dict
import os


class SecurityReportGenerator:
    """Generate professional security reports in PDF format"""
    
    def __init__(self, logo_path: str = "logo_copy.png"):
        self.logo_path = logo_path if os.path.exists(logo_path) else None
        self.styles = getSampleStyleSheet()
        
        # Custom styles
        self.title_style = ParagraphStyle(
            'CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1a1a1a'),
            spaceAfter=30,
            alignment=TA_CENTER
        )
        
        self.heading_style = ParagraphStyle(
            'CustomHeading',
            parent=self.styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#333333'),
            spaceAfter=12,
            spaceBefore=12
        )
        
        self.body_style = ParagraphStyle(
            'CustomBody',
            parent=self.styles['BodyText'],
            fontSize=10,
            textColor=colors.HexColor('#666666'),
            spaceAfter=12
        )
    
    def _add_header_footer(self, canvas, doc):
        """Add header and footer to each page"""
        canvas.saveState()
        
        # Header
        if self.logo_path:
            try:
                canvas.drawImage(self.logo_path, 50, letter[1] - 60, width=40, height=40, preserveAspectRatio=True)
            except:
                pass
        
        canvas.setFont('Helvetica-Bold', 12)
        canvas.drawString(100, letter[1] - 40, "Security Operations Center")
        canvas.setFont('Helvetica', 8)
        canvas.drawString(100, letter[1] - 52, "Automated Security Report")
        
        # Footer
        canvas.setFont('Helvetica', 8)
        canvas.drawString(50, 30, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        canvas.drawRightString(letter[0] - 50, 30, f"Page {doc.page}")
        
        canvas.restoreState()
    
    def generate_alert_report(self, alerts: List[Dict], output_path: str = "security_report.pdf"):
        """Generate comprehensive alert report"""
        doc = SimpleDocTemplate(output_path, pagesize=letter)
        story = []
        
        # Title
        story.append(Paragraph("Security Alert Report", self.title_style))
        story.append(Spacer(1, 0.3*inch))
        
        # Executive Summary
        story.append(Paragraph("Executive Summary", self.heading_style))
        
        critical_count = sum(1 for a in alerts if a.get('severity') == 'Critical')
        high_count = sum(1 for a in alerts if a.get('severity') == 'High')
        
        summary_text = f"""
        This report provides a comprehensive overview of security alerts detected by the Security Operations Center.
        <br/><br/>
        <b>Total Alerts:</b> {len(alerts)}<br/>
        <b>Critical:</b> {critical_count}<br/>
        <b>High:</b> {high_count}<br/>
        <b>Report Period:</b> Last 24 hours<br/>
        <b>Generated:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        """
        story.append(Paragraph(summary_text, self.body_style))
        story.append(Spacer(1, 0.3*inch))
        
        # Severity Distribution
        story.append(Paragraph("Severity Distribution", self.heading_style))
        
        severity_data = [
            ['Severity', 'Count', 'Percentage'],
            ['Critical', str(critical_count), f"{(critical_count/len(alerts)*100):.1f}%" if alerts else "0%"],
            ['High', str(high_count), f"{(high_count/len(alerts)*100):.1f}%" if alerts else "0%"],
            ['Medium', str(sum(1 for a in alerts if a.get('severity') == 'Medium')), 
             f"{(sum(1 for a in alerts if a.get('severity') == 'Medium')/len(alerts)*100):.1f}%" if alerts else "0%"],
            ['Low', str(sum(1 for a in alerts if a.get('severity') == 'Low')), 
             f"{(sum(1 for a in alerts if a.get('severity') == 'Low')/len(alerts)*100):.1f}%" if alerts else "0%"]
        ]
        
        severity_table = Table(severity_data, colWidths=[2*inch, 1.5*inch, 1.5*inch])
        severity_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#6366f1')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(severity_table)
        story.append(Spacer(1, 0.3*inch))
        
        # Critical Alerts Detail
        if critical_count > 0:
            story.append(PageBreak())
            story.append(Paragraph("Critical Alerts - Detailed Analysis", self.heading_style))
            
            for alert in alerts:
                if alert.get('severity') == 'Critical':
                    story.append(Paragraph(f"<b>{alert.get('title', 'Unknown Alert')}</b>", self.body_style))
                    
                    alert_details = f"""
                    <b>Severity:</b> {alert.get('severity', 'Unknown')}<br/>
                    <b>Time:</b> {alert.get('timestamp', 'Unknown')}<br/>
                    <b>Confidence:</b> {alert.get('confidence_score', 0):.0f}%<br/>
                    <b>Description:</b> {alert.get('description', 'No description available')}<br/>
                    <b>MITRE Techniques:</b> {', '.join(alert.get('mitre_techniques', [])[:5])}<br/>
                    <b>Affected Assets:</b> {', '.join(alert.get('affected_assets', ['Unknown']))}<br/>
                    """
                    story.append(Paragraph(alert_details, self.body_style))
                    story.append(Spacer(1, 0.2*inch))
        
        # All Alerts Table
        story.append(PageBreak())
        story.append(Paragraph("All Alerts Summary", self.heading_style))
        
        alert_data = [['Time', 'Alert', 'Severity', 'Confidence']]
        for alert in alerts[:20]:  # Limit to 20 for space
            alert_data.append([
                datetime.fromisoformat(alert.get('timestamp', '')).strftime('%m/%d %H:%M') if alert.get('timestamp') else 'N/A',
                alert.get('title', 'Unknown')[:40],
                alert.get('severity', 'Unknown'),
                f"{alert.get('confidence_score', 0):.0f}%"
            ])
        
        alert_table = Table(alert_data, colWidths=[1.2*inch, 3*inch, 1*inch, 1*inch])
        alert_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#6366f1')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('FONTSIZE', (0, 1), (-1, -1), 8)
        ]))
        story.append(alert_table)
        
        # Recommendations
        story.append(PageBreak())
        story.append(Paragraph("Recommendations", self.heading_style))
        
        recommendations = f"""
        Based on the analysis of {len(alerts)} security alerts, we recommend the following actions:
        <br/><br/>
        <b>1. Immediate Actions:</b><br/>
        - Investigate all {critical_count} critical alerts within the next 4 hours<br/>
        - Review and validate {high_count} high-severity alerts within 24 hours<br/>
        - Ensure all affected systems are isolated if compromise is confirmed<br/>
        <br/>
        <b>2. Short-term Actions (24-48 hours):</b><br/>
        - Conduct forensic analysis on critical incidents<br/>
        - Update firewall rules and access controls<br/>
        - Reset credentials for affected accounts<br/>
        <br/>
        <b>3. Long-term Improvements:</b><br/>
        - Implement additional monitoring for detected attack patterns<br/>
        - Conduct security awareness training<br/>
        - Review and update incident response procedures<br/>
        - Deploy additional security controls based on findings
        """
        story.append(Paragraph(recommendations, self.body_style))
        
        # Build PDF
        doc.build(story, onFirstPage=self._add_header_footer, onLaterPages=self._add_header_footer)
        
        return output_path
    
    def generate_incident_report(self, incident: Dict, output_path: str = "incident_report.pdf"):
        """Generate detailed incident report"""
        doc = SimpleDocTemplate(output_path, pagesize=letter)
        story = []
        
        # Title
        story.append(Paragraph(f"Incident Report: {incident.get('id', 'Unknown')}", self.title_style))
        story.append(Spacer(1, 0.3*inch))
        
        # Incident Overview
        story.append(Paragraph("Incident Overview", self.heading_style))
        
        overview = f"""
        <b>Incident ID:</b> {incident.get('id', 'Unknown')}<br/>
        <b>Type:</b> {incident.get('incident_type', 'Unknown')}<br/>
        <b>Severity:</b> {incident.get('severity', 'Unknown')}<br/>
        <b>Status:</b> {incident.get('status', 'Unknown')}<br/>
        <b>Detected:</b> {incident.get('timestamp', 'Unknown')}<br/>
        <b>Confidence:</b> {incident.get('confidence_score', 0):.0f}%<br/>
        <br/>
        <b>Description:</b><br/>
        {incident.get('description', 'No description available')}
        """
        story.append(Paragraph(overview, self.body_style))
        story.append(Spacer(1, 0.3*inch))
        
        # Build PDF
        doc.build(story, onFirstPage=self._add_header_footer, onLaterPages=self._add_header_footer)
        
        return output_path


# Example usage
if __name__ == '__main__':
    generator = SecurityReportGenerator(logo_path="logo_copy.png")
    
    # Sample alerts
    sample_alerts = [
        {
            'id': 'alert_001',
            'title': 'Brute Force Attack Detected',
            'severity': 'Critical',
            'timestamp': datetime.now().isoformat(),
            'confidence_score': 95,
            'description': 'Multiple failed login attempts detected from IP 192.168.1.100',
            'mitre_techniques': ['T1110', 'T1078'],
            'affected_assets': ['server-01']
        }
    ]
    
    output = generator.generate_alert_report(sample_alerts)
    print(f"Report generated: {output}")
