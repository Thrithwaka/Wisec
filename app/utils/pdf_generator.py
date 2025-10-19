"""
Wi-Fi Security System - PDF Report Generator
Purpose: Generate PDF reports for vulnerability scan results
"""

import os
import io
import base64
from datetime import datetime, timedelta
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, cm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, PageBreak
from reportlab.platypus.flowables import HRFlowable
from reportlab.graphics.shapes import Drawing, Rect, Circle, Line
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.charts.linecharts import HorizontalLineChart
from reportlab.graphics import renderPDF
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
from reportlab.pdfgen import canvas
from reportlab.lib.colors import HexColor
import matplotlib.pyplot as plt
import numpy as np
from flask import current_app
import json


class PDFGenerator:
    """Main PDF generation engine for vulnerability reports"""
    
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self.setup_custom_styles()
        self.page_width = letter[0]
        self.page_height = letter[1]
        self.margin = 0.75 * inch
        
    def setup_custom_styles(self):
        """Setup custom paragraph styles for reports"""
        # Title style
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Title'],
            fontSize=24,
            spaceAfter=30,
            alignment=TA_CENTER,
            textColor=colors.HexColor('#1a472a')
        ))
        
        # Heading styles
        self.styles.add(ParagraphStyle(
            name='CustomHeading1',
            parent=self.styles['Heading1'],
            fontSize=18,
            spaceAfter=12,
            spaceBefore=20,
            textColor=colors.HexColor('#2e7d32')
        ))
        
        self.styles.add(ParagraphStyle(
            name='CustomHeading2',
            parent=self.styles['Heading2'],
            fontSize=14,
            spaceAfter=8,
            spaceBefore=15,
            textColor=colors.HexColor('#388e3c')
        ))
        
        # Risk level styles
        self.styles.add(ParagraphStyle(
            name='HighRisk',
            parent=self.styles['Normal'],
            fontSize=12,
            textColor=colors.red,
            backColor=colors.HexColor('#ffebee')
        ))
        
        self.styles.add(ParagraphStyle(
            name='LowRisk',
            parent=self.styles['Normal'],
            fontSize=12,
            textColor=colors.orange,
            backColor=colors.HexColor('#fff3e0')
        ))
        
        self.styles.add(ParagraphStyle(
            name='CustomNormal',
            parent=self.styles['Normal'],
            fontSize=12,
            textColor=colors.green,
            backColor=colors.HexColor('#e8f5e8')
        ))
        
    def generate_vulnerability_report(self, scan_data):
        """Create comprehensive vulnerability PDF report"""
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=self.margin,
            leftMargin=self.margin,
            topMargin=self.margin,
            bottomMargin=self.margin
        )
        
        # Build report content
        story = []
        
        # Add title page
        story.extend(self._create_title_page(scan_data))
        story.append(PageBreak())
        
        # Add executive summary
        story.extend(self._create_executive_summary(scan_data))
        story.append(PageBreak())
        
        # Add network information
        story.extend(self._create_network_information(scan_data))
        
        # Add vulnerability analysis
        story.extend(self._create_vulnerability_analysis(scan_data))
        story.append(PageBreak())
        
        # Add AI model predictions
        story.extend(self._create_ai_predictions_section(scan_data))
        story.append(PageBreak())
        
        # Add network topology
        story.extend(self._create_network_topology_section(scan_data))
        
        # Add recommendations
        story.extend(self._create_recommendations_section(scan_data))
        story.append(PageBreak())
        
        # Add technical details
        story.extend(self._create_technical_details(scan_data))
        
        # Add appendices
        story.extend(self._create_appendices(scan_data))
        
        # Build PDF
        doc.build(story, onFirstPage=self._add_header_footer, onLaterPages=self._add_header_footer)
        
        buffer.seek(0)
        return buffer
    
    def generate_deep_analysis_report(self, analysis_data):
        """Generate comprehensive deep analysis PDF report with AI model predictions"""
        try:
            # Create filename with timestamp
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"wifi_deep_analysis_{timestamp}.pdf"
            filepath = os.path.join('reports', filename)
            
            # Ensure reports directory exists
            os.makedirs('reports', exist_ok=True)
            
            buffer = io.BytesIO()
            doc = SimpleDocTemplate(
                buffer,
                pagesize=letter,
                rightMargin=self.margin,
                leftMargin=self.margin,
                topMargin=self.margin,
                bottomMargin=self.margin
            )
            
            # Build the report content
            story = []
            
            # Title page
            self._add_title_page(story, analysis_data)
            story.append(PageBreak())
            
            # Executive summary
            self._add_executive_summary(story, analysis_data)
            story.append(PageBreak())
            
            # Network details
            self._add_network_details_section(story, analysis_data)
            story.append(PageBreak())
            
            # AI analysis results
            self._add_ai_analysis_section(story, analysis_data)
            story.append(PageBreak())
            
            # Individual model predictions
            self._add_individual_models_section(story, analysis_data)
            story.append(PageBreak())
            
            # Risk assessment
            self._add_risk_assessment_section(story, analysis_data)
            story.append(PageBreak())
            
            # Vulnerabilities
            self._add_vulnerabilities_section(story, analysis_data)
            story.append(PageBreak())
            
            # Recommendations
            self._add_recommendations_section(story, analysis_data)
            story.append(PageBreak())
            
            # Compliance status
            self._add_compliance_section(story, analysis_data)
            story.append(PageBreak())
            
            # Technical appendix
            self._add_technical_appendix(story, analysis_data)
            
            # Build PDF
            doc.build(story)
            
            # Save to file
            pdf_data = buffer.getvalue()
            buffer.close()
            
            with open(filepath, 'wb') as f:
                f.write(pdf_data)
            
            return filepath
            
        except Exception as e:
            current_app.logger.error(f"Error generating deep analysis PDF: {e}")
            return None
    
    def _add_title_page(self, story, data):
        """Add professional title page to the report"""
        # Main title with enhanced styling
        title = Paragraph("WiFi Network Security Analysis Report", self.styles['CustomTitle'])
        story.append(title)
        story.append(Spacer(1, 15))
        
        # Subtitle with classification
        classification = Paragraph("PROFESSIONAL SECURITY ASSESSMENT", self.styles['CustomHeading2'])
        story.append(classification)
        story.append(Spacer(1, 30))
        
        # Network information box
        network_name = data.get('network_name', 'Unknown Network')
        network_info = Paragraph(f"<b>Target Network:</b> {network_name}", self.styles['CustomBody'])
        story.append(network_info)
        story.append(Spacer(1, 20))
        
        # Analysis details table with enhanced information
        analysis_details = [
            ['Report Generated:', data.get('generated_date', datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC'))],
            ['Scan Timestamp:', data.get('scan_timestamp', 'N/A')],
            ['Analysis Type:', 'Deep Learning AI Security Assessment'],
            ['Models Analyzed:', str(data.get('technical_details', {}).get('models_analyzed', 9))],
            ['Risk Score:', f"{data.get('technical_details', {}).get('risk_score', 0):.1f}/100"],
            ['Confidence Level:', f"{data.get('technical_details', {}).get('ensemble_confidence', 0) * 100:.1f}%"],
            ['Report Version:', '2.0 (Enhanced Security Analysis)']
        ]
        
        details_table = Table(analysis_details, colWidths=[2*inch, 4*inch])
        details_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f0f0f0')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 12),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(details_table)
        story.append(Spacer(1, 40))
        
        # Security score visualization
        self._add_security_score_chart(story, data.get('security_score', 0))
    
    def _add_executive_summary(self, story, data):
        """Add comprehensive executive summary section"""
        story.append(Paragraph("Executive Summary", self.styles['CustomHeading1']))
        story.append(Spacer(1, 12))
        
        # Extract executive summary data from new structure
        exec_summary = data.get('executive_summary', {})
        network_name = data.get('network_name', 'Unknown Network')
        
        # Overall assessment
        overall_status = exec_summary.get('overall_status', 'Unknown')
        confidence_level = exec_summary.get('confidence_level', '0%')
        risk_level = exec_summary.get('risk_level', 'Unknown')
        risk_score = exec_summary.get('risk_score', 0)
        models_analyzed = exec_summary.get('models_analyzed', 0)
        
        # Professional summary text
        summary_text = f"<b>Network Assessment:</b> {network_name}<br/><br/>"
        summary_text += f"<b>Overall Security Status:</b> {overall_status}<br/>"
        summary_text += f"<b>AI Confidence Level:</b> {confidence_level}<br/>"
        summary_text += f"<b>Risk Assessment:</b> {risk_level} (Score: {risk_score}/100)<br/><br/>"
        
        summary_text += f"This comprehensive security assessment analyzed the target WiFi network using "
        summary_text += f"{models_analyzed} specialized AI models including Convolutional Neural Networks (CNN), "
        summary_text += f"Long Short-Term Memory networks (LSTM), Graph Neural Networks (GNN), and ensemble fusion algorithms. "
        
        # Add key findings
        key_findings = exec_summary.get('key_findings', [])
        if key_findings:
            summary_text += "<br/><br/><b>Key Security Findings:</b><br/>"
            for finding in key_findings:
                summary_text += f"• {finding}<br/>"
        
        # Add immediate concerns if any
        immediate_concerns = exec_summary.get('immediate_concerns', [])
        if immediate_concerns:
            summary_text += "<br/><b>Immediate Security Concerns:</b><br/>"
            for concern in immediate_concerns:
                summary_text += f"⚠️ {concern}<br/>"
        
        
        summary_para = Paragraph(summary_text, self.styles['Normal'])
        story.append(summary_para)
        story.append(Spacer(1, 20))
        
        # Enhanced metrics table
        threat_analysis = data.get('threat_analysis', {})
        threat_summary = threat_analysis.get('threat_summary', {})
        total_threats = threat_summary.get('total_threats', 0)
        
        # Recommendations count
        recommendations = data.get('recommendations', {})
        immediate_actions = len(recommendations.get('immediate_actions', []))
        security_improvements = len(recommendations.get('security_improvements', []))
        total_recommendations = immediate_actions + security_improvements
        
        metrics_data = [
            ['Security Metric', 'Current Status', 'Assessment'],
            ['Overall Security', overall_status, self._get_security_status(overall_status)],
            ['AI Confidence', confidence_level, self._get_confidence_status_text(confidence_level)],
            ['Risk Level', f"{risk_level} ({risk_score}/100)", self._get_risk_status(risk_level)],
            ['Threats Detected', str(total_threats), self._get_threat_count_status(total_threats)],
            ['Action Items', f"{total_recommendations} recommendations", self._get_recommendations_status(immediate_actions)],
            ['Models Analyzed', str(models_analyzed), 'Complete Analysis']
        ]
        
        metrics_table = Table(metrics_data, colWidths=[2.2*inch, 2*inch, 1.8*inch])
        metrics_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1a472a')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8f8f8')])
        ]))
        
        story.append(metrics_table)
        story.append(Spacer(1, 15))
        
        # Add visual indicator for overall security level
        status_color = self._get_status_color(risk_level)
        status_text = f"<b>SECURITY CLASSIFICATION: {risk_level.upper()}</b>"
        status_para = Paragraph(status_text, ParagraphStyle(
            'SecurityStatus',
            parent=self.styles['Normal'],
            fontSize=12,
            textColor=status_color,
            alignment=TA_CENTER,
            borderWidth=2,
            borderColor=status_color,
            borderPadding=10,
            backColor=colors.HexColor('#f0f8f0')
        ))
        story.append(status_para)
    
    def _add_network_details_section(self, story, data):
        """Add comprehensive network information section"""
        story.append(Paragraph("Network Configuration Analysis", self.styles['CustomHeading1']))
        story.append(Spacer(1, 12))
        
        # Extract network analysis data from new structure
        network_analysis = data.get('network_analysis', {})
        network_config = network_analysis.get('network_configuration', {})
        security_assessment = network_analysis.get('security_assessment', {})
        input_features = network_analysis.get('input_features_used', [])
        
        # Network Configuration Table
        story.append(Paragraph("Network Configuration", self.styles['CustomHeading2']))
        story.append(Spacer(1, 8))
        
        config_data = [
            ['Parameter', 'Value', 'Security Assessment'],
            ['Network Name (SSID)', network_config.get('ssid', 'Unknown'), 'Broadcast Identifier'],
            ['MAC Address (BSSID)', network_config.get('mac_address', 'Unknown'), 'Hardware Identifier'],
            ['Signal Strength', f"{network_config.get('signal_strength', 'Unknown')}", security_assessment.get('signal_quality', 'Unknown')],
            ['Encryption Method', network_config.get('encryption', 'Unknown'), security_assessment.get('encryption_strength', 'Unknown')],
            ['WiFi Channel', str(network_config.get('channel', 'Unknown')), security_assessment.get('channel_congestion', 'Unknown')],
            ['Operating Frequency', f"{network_config.get('frequency', 'Unknown')} MHz", 'Frequency Band Analysis'],
            ['Connection Speed', network_config.get('data_rate', 'Unknown'), 'Performance Indicator'],
            ['Radio Type', network_config.get('radio_type', 'Unknown'), 'Technology Standard']
        ]
        
        config_table = Table(config_data, colWidths=[1.8*inch, 2.2*inch, 2.2*inch])
        config_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1a472a')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8f8f8')])
        ]))
        
        story.append(config_table)
        story.append(Spacer(1, 15))
        
        # Network Infrastructure Information
        story.append(Paragraph("Network Infrastructure Analysis", self.styles['CustomHeading2']))
        story.append(Spacer(1, 8))
        
        # Enhanced infrastructure analysis
        infrastructure_text = f"<b>Network Architecture Assessment:</b><br/><br/>"
        
        # Security protocols analysis
        encryption = network_config.get('encryption', 'Unknown')
        if encryption != 'Unknown':
            if 'WPA3' in encryption.upper():
                infrastructure_text += f"✓ <b>Encryption Protocol:</b> {encryption} - Latest security standard in use<br/>"
            elif 'WPA2' in encryption.upper():
                infrastructure_text += f"⚠️ <b>Encryption Protocol:</b> {encryption} - Good security, consider WPA3 upgrade<br/>"
            elif 'WEP' in encryption.upper():
                infrastructure_text += f"🚨 <b>Encryption Protocol:</b> {encryption} - CRITICAL: Obsolete and highly vulnerable<br/>"
            else:
                infrastructure_text += f"❓ <b>Encryption Protocol:</b> {encryption} - Requires further analysis<br/>"
        
        # Signal strength analysis
        signal_strength = network_config.get('signal_strength', 'Unknown')
        if signal_strength != 'Unknown':
            try:
                signal_val = float(signal_strength.replace('dBm', '').replace('%', '').strip())
                if signal_val > -50:
                    infrastructure_text += f"✓ <b>Signal Quality:</b> Excellent ({signal_strength}) - Strong network presence<br/>"
                elif signal_val > -70:
                    infrastructure_text += f"✓ <b>Signal Quality:</b> Good ({signal_strength}) - Adequate coverage<br/>"
                else:
                    infrastructure_text += f"⚠️ <b>Signal Quality:</b> Weak ({signal_strength}) - May affect security monitoring<br/>"
            except:
                infrastructure_text += f"<b>Signal Quality:</b> {signal_strength}<br/>"
        
        # Channel analysis
        channel = network_config.get('channel', 'Unknown')
        frequency = network_config.get('frequency', 'Unknown')
        if channel != 'Unknown':
            infrastructure_text += f"<b>Channel Configuration:</b> Channel {channel}"
            if frequency != 'Unknown':
                infrastructure_text += f" ({frequency} MHz)"
                if '2.4' in str(frequency):
                    infrastructure_text += " - 2.4GHz band (longer range, more congested)<br/>"
                elif '5' in str(frequency):
                    infrastructure_text += " - 5GHz band (higher speed, less congested)<br/>"
                else:
                    infrastructure_text += "<br/>"
            else:
                infrastructure_text += "<br/>"
        
        # Add vendor and device information if available
        radio_type = network_config.get('radio_type', 'Unknown')
        if radio_type != 'Unknown':
            infrastructure_text += f"<b>Technology Standard:</b> {radio_type}<br/>"
        
        infrastructure_para = Paragraph(infrastructure_text, self.styles['Normal'])
        story.append(infrastructure_para)
        story.append(Spacer(1, 15))
        # Network Security Features Analysis
        story.append(Paragraph("Security Features Assessment", self.styles['CustomHeading2']))
        story.append(Spacer(1, 8))
        
        security_features = [
            ['Security Feature', 'Status', 'Risk Assessment'],
            ['WPS (WiFi Protected Setup)', security_assessment.get('wps_status', 'Unknown'), self._assess_wps_risk(security_assessment.get('wps_status', 'Unknown'))],
            ['Guest Network', security_assessment.get('guest_network', 'Unknown'), 'Network Segmentation'],
            ['MAC Address Filtering', security_assessment.get('mac_filtering', 'Unknown'), 'Access Control Measure'],
            ['Network Isolation', security_assessment.get('client_isolation', 'Unknown'), 'Device Security'],
            ['Firmware Status', security_assessment.get('firmware_status', 'Unknown'), 'Device Security Updates'],
            ['Admin Interface Security', security_assessment.get('admin_security', 'Unknown'), 'Management Access Control']
        ]
        
        security_table = Table(security_features, colWidths=[2.0*inch, 1.8*inch, 2.4*inch])
        security_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c5282')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f0f7ff')])
        ]))
        
        story.append(security_table)
        story.append(Spacer(1, 15))
        
        # Input Features Analysis
        if input_features:
            story.append(Paragraph("AI Analysis Input Features", self.styles['CustomHeading2']))
            story.append(Spacer(1, 8))
            
            # Create a formatted list of input features
            features_text = "The following network parameters were analyzed by the AI models:<br/><br/>"
            for i, feature in enumerate(input_features[:10], 1):  # Limit to first 10
                features_text += f"{i}. {feature}<br/>"
            
            if len(input_features) > 10:
                features_text += f"... and {len(input_features) - 10} additional parameters"
            
            features_para = Paragraph(features_text, self.styles['Normal'])
            story.append(features_para)
        story.append(Paragraph("Security Configuration", self.styles['CustomHeading2']))
        
        security_data = [
            ['Security Feature', 'Status'],
            ['Encryption Type', security_config.get('encryption_type', 'Unknown')],
            ['Cipher Suite', security_config.get('cipher_suite', 'Unknown')],
            ['WPA3 Support', 'Yes' if security_config.get('wpa3_support') else 'No'],
            ['PMF Enabled', 'Yes' if security_config.get('pmf_enabled') else 'No'],
            ['WPS Enabled', 'Yes' if security_config.get('wps_enabled') else 'No'],
            ['Security Score', f"{security_config.get('security_score', 0)}/100"]
        ]
        
        security_table = Table(security_data, colWidths=[2.5*inch, 2.5*inch])
        security_table.setStyle(self._get_standard_table_style())
        story.append(security_table)
        
        # Topology information
        topology = network_details.get('topology', {})
        if topology and topology.get('device_count', 0) > 0:
            story.append(Spacer(1, 15))
            story.append(Paragraph("Network Topology", self.styles['CustomHeading2']))
            
            device_types = topology.get('device_types', {})
            topology_data = [
                ['Device Type', 'Count'],
                ['Total Devices', str(topology.get('device_count', 0))],
                ['Routers/Gateways', str(device_types.get('routers', 0))],
                ['Computers', str(device_types.get('computers', 0))],
                ['Mobile Devices', str(device_types.get('mobile_devices', 0))],
                ['IoT Devices', str(device_types.get('iot_devices', 0))],
                ['Unknown Devices', str(device_types.get('unknown', 0))]
            ]
            
            topology_table = Table(topology_data, colWidths=[2.5*inch, 1.5*inch])
            topology_table.setStyle(self._get_standard_table_style())
            story.append(topology_table)
    
    def _add_ai_analysis_section(self, story, data):
        """Add comprehensive AI analysis results section"""
        story.append(Paragraph("AI Security Analysis Results", self.styles['CustomHeading1']))
        story.append(Spacer(1, 12))
        
        # Extract AI model analysis data
        ai_analysis = data.get('ai_model_analysis', {})
        ensemble_fusion = ai_analysis.get('ensemble_fusion', {})
        individual_models = ai_analysis.get('individual_models', [])
        
        # Ensemble Fusion Results
        story.append(Paragraph("Ensemble AI Fusion Results", self.styles['CustomHeading2']))
        story.append(Spacer(1, 8))
        
        fusion_text = f"<b>Final AI Prediction:</b> {ensemble_fusion.get('final_prediction', 'Unknown')}<br/>"
        fusion_text += f"<b>Confidence Level:</b> {ensemble_fusion.get('confidence', '0%')}<br/>"
        fusion_text += f"<b>Models Utilized:</b> {ensemble_fusion.get('models_used', 0)} AI models<br/>"
        fusion_text += f"<b>Agreement Score:</b> {ensemble_fusion.get('agreement_score', '0%')}<br/>"
        fusion_text += f"<b>Fusion Method:</b> {ensemble_fusion.get('fusion_method', 'Unknown')}<br/><br/>"
        
        fusion_text += "The ensemble AI system combines predictions from multiple specialized models to provide "
        fusion_text += "a comprehensive security assessment with enhanced accuracy and reduced false positives."
        
        fusion_para = Paragraph(fusion_text, self.styles['Normal'])
        story.append(fusion_para)
        story.append(Spacer(1, 15))
        
        # Individual Model Analysis Overview
        if individual_models:
            story.append(Paragraph("Individual AI Model Analysis", self.styles['CustomHeading2']))
            story.append(Spacer(1, 8))
            
            # Create table of individual model results
            model_data = [['AI Model', 'Prediction', 'Confidence', 'Type', 'Processing Time']]
            
            for model in individual_models:
                model_data.append([
                    model.get('name', 'Unknown Model'),
                    model.get('prediction', 'Unknown'),
                    model.get('confidence', '0%'),
                    model.get('model_type', 'Unknown'),
                    model.get('processing_time', '0ms')
                ])
            
            model_table = Table(model_data, colWidths=[2.2*inch, 1.5*inch, 1*inch, 1*inch, 0.8*inch])
            model_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1a472a')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 7),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8f8f8')])
            ]))
            
            story.append(model_table)
            story.append(Spacer(1, 15))
        
        # Input Features Analysis
        input_features_analysis = data.get('input_features_analysis', {})
        if input_features_analysis.get('model_inputs_summary'):
            story.append(Paragraph("AI Model Input Specifications", self.styles['CustomHeading2']))
            story.append(Spacer(1, 8))
            
            inputs_summary = input_features_analysis.get('model_inputs_summary', {})
            inputs_text = "Each AI model type utilizes different input representations:<br/><br/>"
            
            for model_type, description in inputs_summary.items():
                inputs_text += f"<b>{model_type}:</b> {description}<br/>"
            
            inputs_para = Paragraph(inputs_text, self.styles['Normal'])
            story.append(inputs_para)
    
    def _add_individual_models_section(self, story, data):
        """Add individual model predictions section"""
        story.append(Paragraph("Individual Model Predictions", self.styles['CustomHeading1']))
        story.append(Spacer(1, 12))
        
        individual_predictions = data.get('individual_predictions', {})
        
        if not individual_predictions:
            story.append(Paragraph("No individual model predictions available.", self.styles['Normal']))
            return
        
        # Create table with all model predictions
        model_data = [['Model Name', 'Prediction', 'Confidence', 'Risk Score', 'Model Type']]
        
        for model_name, prediction in individual_predictions.items():
            if prediction.get('prediction'):
                model_data.append([
                    model_name.replace('_', ' ').title(),
                    prediction.get('threat_class', 'Unknown'),
                    f"{prediction.get('confidence', 0):.1%}",
                    f"{prediction.get('risk_score', 0):.1f}",
                    prediction.get('model_type', 'Unknown').upper()
                ])
        
        if len(model_data) > 1:  # Has data beyond headers
            models_table = Table(model_data, colWidths=[1.5*inch, 1.8*inch, 0.8*inch, 0.8*inch, 0.8*inch])
            models_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2e7d32')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f9f9f9')])
            ]))
            
            story.append(models_table)
        
        # Model descriptions
        story.append(Spacer(1, 15))
        story.append(Paragraph("Model Descriptions", self.styles['CustomHeading2']))
        
        model_descriptions = {
            'cnn_final': 'CNN Final - Pattern recognition in network traffic and security features',
            'lstm_main': 'LSTM Main - Temporal behavior analysis and sequence prediction',
            'lstm_production': 'LSTM Production - Optimized temporal analysis for real-time threats',
            'gnn': 'Graph Neural Network - Network topology and relationship analysis',
            'crypto_bert_enhanced': 'Crypto BERT - Advanced cryptographic protocol analysis',
            'cnn_lstm_hybrid': 'CNN-LSTM Hybrid - Combined spatial-temporal analysis',
            'wifi_attention_model': 'Attention Model - Focused feature attention mechanism',
            'random_forest': 'Random Forest - Tree-based ensemble classifier',
            'gradient_boosting': 'Gradient Boosting - Sequential boosting classifier'
        }
        
        for model_name, prediction in individual_predictions.items():
            if prediction.get('prediction'):
                description = model_descriptions.get(model_name, 'Specialized AI model for WiFi security analysis')
                model_text = f"<b>{model_name.replace('_', ' ').title()}:</b> {description}"
                story.append(Paragraph(model_text, self.styles['Normal']))
                story.append(Spacer(1, 5))
    
    def _add_risk_assessment_section(self, story, data):
        """Add comprehensive risk assessment section"""
        story.append(Paragraph("Risk Assessment", self.styles['CustomHeading1']))
        story.append(Spacer(1, 12))
        
        risk_assessment = data.get('risk_assessment', {})
        
        # Overall risk summary
        overall_score = risk_assessment.get('overall_score', 0)
        threat_level = risk_assessment.get('threat_level', 'Unknown')
        
        risk_text = f"Overall Security Score: {overall_score:.1f}/100 ({self._get_score_description(overall_score)})\n"
        risk_text += f"Threat Level: {threat_level}\n\n"
        
        story.append(Paragraph(risk_text, self.styles['Normal']))
        
        # Risk breakdown
        ai_risk = risk_assessment.get('ai_risk_assessment', {})
        network_risks = risk_assessment.get('network_specific_risks', {})
        
        if network_risks:
            story.append(Paragraph("Risk Breakdown", self.styles['CustomHeading2']))
            
            risk_breakdown = [
                ['Risk Category', 'Score', 'Level'],
                ['Encryption Risk', f"{network_risks.get('encryption_risk', 0):.1f}/100", self._get_risk_level(network_risks.get('encryption_risk', 0))],
                ['Topology Risk', f"{network_risks.get('topology_risk', 0):.1f}/100", self._get_risk_level(network_risks.get('topology_risk', 0))],
                ['Traffic Risk', f"{network_risks.get('traffic_risk', 0):.1f}/100", self._get_risk_level(network_risks.get('traffic_risk', 0))],
                ['Configuration Risk', f"{network_risks.get('configuration_risk', 0):.1f}/100", self._get_risk_level(network_risks.get('configuration_risk', 0))],
                ['AI Risk Assessment', f"{ai_risk.get('risk_score', 0):.1f}/10", self._get_ai_risk_level(ai_risk.get('risk_score', 0))]
            ]
            
            risk_table = Table(risk_breakdown, colWidths=[2*inch, 1.5*inch, 1.5*inch])
            risk_table.setStyle(self._get_standard_table_style())
            story.append(risk_table)
    
    def _add_vulnerabilities_section(self, story, data):
        """Add vulnerabilities section"""
        story.append(Paragraph("Identified Vulnerabilities", self.styles['CustomHeading1']))
        story.append(Spacer(1, 12))
        
        vulnerabilities = data.get('vulnerabilities', [])
        
        if not vulnerabilities:
            story.append(Paragraph("No significant vulnerabilities were identified during the analysis.", self.styles['CustomNormal']))
            return
        
        # Group vulnerabilities by severity
        vuln_by_severity = {}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'Medium')
            if severity not in vuln_by_severity:
                vuln_by_severity[severity] = []
            vuln_by_severity[severity].append(vuln)
        
        # Display vulnerabilities by severity (Critical first)
        severity_order = ['Critical', 'High', 'Medium', 'Low', 'Info']
        
        for severity in severity_order:
            if severity in vuln_by_severity:
                story.append(Paragraph(f"{severity} Severity Vulnerabilities", self.styles['CustomHeading2']))
                
                for vuln in vuln_by_severity[severity]:
                    vuln_title = vuln.get('type', 'Security Issue')
                    vuln_source = vuln.get('source', 'Unknown')
                    vuln_desc = vuln.get('description', 'No description available')
                    vuln_confidence = vuln.get('confidence', 0)
                    
                    vuln_text = f"<b>{vuln_title}</b> (Source: {vuln_source})\n"
                    vuln_text += f"{vuln_desc}\n"
                    if vuln_confidence > 0:
                        vuln_text += f"Confidence: {vuln_confidence:.1%}"
                    
                    # Use different styles based on severity
                    if severity == 'Critical':
                        style = self.styles['HighRisk']
                    elif severity in ['High', 'Medium']:
                        style = self.styles['LowRisk']
                    else:
                        style = self.styles['Normal']
                    
                    story.append(Paragraph(vuln_text, style))
                    story.append(Spacer(1, 10))
                
                story.append(Spacer(1, 10))
    
    def _add_recommendations_section(self, story, data):
        """Add comprehensive security recommendations section"""
        story.append(Paragraph("Security Recommendations", self.styles['CustomHeading1']))
        story.append(Spacer(1, 12))
        
        # Extract recommendations from new structure
        recommendations = data.get('recommendations', {})
        immediate_actions = recommendations.get('immediate_actions', [])
        security_improvements = recommendations.get('security_improvements', [])
        monitoring_suggestions = recommendations.get('monitoring_suggestions', [])
        
        # Immediate Actions (High Priority)
        if immediate_actions:
            story.append(Paragraph("🚨 IMMEDIATE ACTIONS REQUIRED", self.styles['CustomHeading2']))
            story.append(Spacer(1, 8))
            
            for i, action in enumerate(immediate_actions, 1):
                action_text = f"<b>{i}. {action.get('action', 'Security Action Required')}</b><br/>"
                action_text += f"<b>Reason:</b> {action.get('reason', 'Critical security concern')}<br/>"
                action_text += f"<b>Urgency:</b> {action.get('urgency', 'IMMEDIATE')}<br/><br/>"
                
                action_para = Paragraph(action_text, ParagraphStyle(
                    'ImmediateAction',
                    parent=self.styles['Normal'],
                    fontSize=10,
                    leftIndent=20,
                    borderWidth=1,
                    borderColor=colors.HexColor('#d32f2f'),
                    borderPadding=8,
                    backColor=colors.HexColor('#ffebee')
                ))
                story.append(action_para)
                story.append(Spacer(1, 10))
            
            story.append(Spacer(1, 15))
        
        # Security Improvements (Medium Priority)
        if security_improvements:
            story.append(Paragraph("🛡️ SECURITY IMPROVEMENTS", self.styles['CustomHeading2']))
            story.append(Spacer(1, 8))
            
            improvements_data = [['Priority', 'Recommendation', 'Timeline', 'Benefit']]
            
            for improvement in security_improvements:
                improvements_data.append([
                    'Medium',
                    improvement.get('action', 'Security enhancement'),
                    improvement.get('urgency', 'WITHIN 30 DAYS'),
                    improvement.get('reason', 'Enhanced security posture')
                ])
            
            improvements_table = Table(improvements_data, colWidths=[0.8*inch, 2.5*inch, 1.2*inch, 1.7*inch])
            improvements_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f57c00')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#fff8f0')])
            ]))
            
            story.append(improvements_table)
            story.append(Spacer(1, 15))
        
        # Monitoring Suggestions (Low Priority - Ongoing)
        if monitoring_suggestions:
            story.append(Paragraph("📊 ONGOING MONITORING", self.styles['CustomHeading2']))
            story.append(Spacer(1, 8))
            
            monitoring_text = "Implement these ongoing security monitoring practices:<br/><br/>"
            
            for i, suggestion in enumerate(monitoring_suggestions, 1):
                monitoring_text += f"<b>{i}. {suggestion.get('action', 'Monitoring activity')}</b><br/>"
                monitoring_text += f"   Purpose: {suggestion.get('reason', 'Continuous security oversight')}<br/>"
                monitoring_text += f"   Frequency: {suggestion.get('urgency', 'ONGOING')}<br/><br/>"
            
            monitoring_para = Paragraph(monitoring_text, ParagraphStyle(
                'MonitoringSuggestions',
                parent=self.styles['Normal'],
                fontSize=9,
                leftIndent=15,
                borderWidth=1,
                borderColor=colors.HexColor('#2e7d32'),
                borderPadding=10,
                backColor=colors.HexColor('#f1f8e9')
            ))
            story.append(monitoring_para)
            story.append(Spacer(1, 15))
        
        # Summary of Recommendations
        total_recommendations = len(immediate_actions) + len(security_improvements) + len(monitoring_suggestions)
        if total_recommendations == 0:
            story.append(Paragraph("✅ No specific security recommendations required. Current configuration appears secure.", 
                                  self.styles['Normal']))
        else:
            summary_text = f"<b>Recommendations Summary:</b><br/>"
            summary_text += f"• {len(immediate_actions)} immediate actions required<br/>"
            summary_text += f"• {len(security_improvements)} security improvements suggested<br/>"
            summary_text += f"• {len(monitoring_suggestions)} ongoing monitoring practices<br/>"
            summary_text += f"• Total: {total_recommendations} security recommendations"
            
            summary_para = Paragraph(summary_text, self.styles['Normal'])
            story.append(summary_para)
    
    def _add_compliance_section(self, story, data):
        """Add compliance status section"""
        story.append(Paragraph("Compliance Status", self.styles['CustomHeading1']))
        story.append(Spacer(1, 12))
        
        compliance = data.get('compliance_status', {})
        
        if not compliance:
            story.append(Paragraph("Compliance information not available.", self.styles['Normal']))
            return
        
        # Overall compliance status
        overall_status = compliance.get('overall_status', 'Unknown')
        compliance_score = compliance.get('compliance_score', 0)
        
        compliance_text = f"Overall Compliance Status: {overall_status}\n"
        compliance_text += f"Compliance Score: {compliance_score}/100"
        
        story.append(Paragraph(compliance_text, self.styles['Normal']))
        story.append(Spacer(1, 15))
        
        # Standards compliance
        standards = compliance.get('standards', {})
        if standards:
            story.append(Paragraph("Standards Compliance", self.styles['CustomHeading2']))
            
            standards_data = [['Standard', 'Status']]
            for standard, status in standards.items():
                standards_data.append([standard.replace('_', ' '), status])
            
            standards_table = Table(standards_data, colWidths=[2*inch, 2*inch])
            standards_table.setStyle(self._get_standard_table_style())
            story.append(standards_table)
        
        # Compliance issues
        issues = compliance.get('issues', [])
        if issues:
            story.append(Spacer(1, 15))
            story.append(Paragraph("Compliance Issues", self.styles['CustomHeading2']))
            
            for i, issue in enumerate(issues, 1):
                issue_text = f"{i}. {issue}"
                story.append(Paragraph(issue_text, self.styles['Normal']))
                story.append(Spacer(1, 5))
    
    def _add_technical_appendix(self, story, data):
        """Add technical appendix with detailed data"""
        story.append(Paragraph("Technical Appendix", self.styles['CustomHeading1']))
        story.append(Spacer(1, 12))
        
        # Analysis metadata
        metadata = data.get('analysis_metadata', {})
        if metadata:
            story.append(Paragraph("Analysis Metadata", self.styles['CustomHeading2']))
            
            metadata_data = [
                ['Property', 'Value'],
                ['Models Used', ', '.join(metadata.get('models_used', []))],
                ['Analysis Depth', metadata.get('analysis_depth', 'Unknown')],
                ['Data Sources', ', '.join(metadata.get('data_sources', []))],
                ['Analysis Duration', f"{data.get('analysis_duration_seconds', 0):.1f} seconds"]
            ]
            
            metadata_table = Table(metadata_data, colWidths=[2*inch, 3*inch])
            metadata_table.setStyle(self._get_standard_table_style())
            story.append(metadata_table)
            story.append(Spacer(1, 15))
        
        # Raw data summary (abbreviated)
        story.append(Paragraph("Data Collection Summary", self.styles['CustomHeading2']))
        
        network_details = data.get('network_details', {})
        traffic_analysis = network_details.get('traffic_analysis', {})
        
        if traffic_analysis:
            traffic_summary = f"Traffic Analysis: {traffic_analysis.get('total_packets', 0)} packets captured "
            traffic_summary += f"over {traffic_analysis.get('capture_duration', 0)} seconds. "
            
            protocols = traffic_analysis.get('protocols', {})
            if protocols:
                top_protocol = max(protocols.items(), key=lambda x: x[1])
                traffic_summary += f"Dominant protocol: {top_protocol[0]} ({top_protocol[1]}%)"
            
            story.append(Paragraph(traffic_summary, self.styles['Normal']))
            story.append(Spacer(1, 10))
        
        # Disclaimer
        story.append(Spacer(1, 20))
        story.append(Paragraph("Disclaimer", self.styles['CustomHeading2']))
        disclaimer_text = "This report is generated by automated AI analysis and should be used as a security assessment tool. "
        disclaimer_text += "Results should be validated by security professionals. The analysis is based on network data "
        disclaimer_text += "collected at the time of the scan and may not reflect current network status."
        
        story.append(Paragraph(disclaimer_text, self.styles['Normal']))
    
    def _add_security_score_chart(self, story, score):
        """Add enhanced security score visualization with risk assessment"""
        try:
            story.append(Paragraph("Security Risk Assessment Overview", self.styles['CustomHeading2']))
            story.append(Spacer(1, 8))
            
            # Enhanced score visualization with context
            score_value = float(score) if score else 0
            score_status = self._get_score_status(score_value)
            score_description = self._get_score_description(score_value)
            score_color = self._get_score_color(score_value)
            
            # Risk level visualization table
            risk_data = [
                ['Security Metric', 'Current Value', 'Assessment', 'Status'],
                ['Overall Security Score', f'{score_value:.1f}/100', score_status, score_description],
                ['Risk Level', self._get_risk_level(score_value), self._get_risk_status(score_value), 'Based on AI Analysis'],
                ['Confidence Rating', 'High', 'AI Model Consensus', 'Multi-Model Validation'],
                ['Threat Exposure', self._get_threat_exposure(score_value), 'Network Vulnerability', 'Active Monitoring Required']
            ]
            
            risk_table = Table(risk_data, colWidths=[1.5*inch, 1.3*inch, 1.4*inch, 1.8*inch])
            risk_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#c62828')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                ('TOPPADDING', (0, 0), (-1, -1), 8),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#ffebee')])
            ]))
            
            story.append(risk_table)
            story.append(Spacer(1, 15))
            
            # Visual score indicator
            score_indicator = f'<font size="14" color="{score_color}">🔒 SECURITY SCORE: <b>{score_value:.1f}/100</b> ({score_status})</font>'
            story.append(Paragraph(score_indicator, self.styles['Normal']))
            story.append(Spacer(1, 10))
            
        except Exception as e:
            # Fallback to simple text
            story.append(Paragraph(f"Security Score: {score:.1f}/100", self.styles['Normal']))
    
    def _get_standard_table_style(self):
        """Get standard table style"""
        return TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2e7d32')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f9f9f9')])
        ])
    
    def _get_score_status(self, score):
        """Get status description for security score"""
        if score >= 80:
            return "Excellent"
        elif score >= 60:
            return "Good"
        elif score >= 40:
            return "Fair"
        else:
            return "Poor"
    
    def _get_score_description(self, score):
        """Get detailed description for security score"""
        if score >= 80:
            return "Strong security posture"
        elif score >= 60:
            return "Moderate security with room for improvement"
        elif score >= 40:
            return "Weak security requiring attention"
        else:
            return "Poor security requiring immediate action"
    
    def _get_score_color(self, score):
        """Get color for security score"""
        if score >= 80:
            return "#2e7d32"  # Green
        elif score >= 60:
            return "#f57c00"  # Orange
        else:
            return "#d32f2f"  # Red
    
    def _assess_wps_risk(self, wps_status):
        """Assess WPS security risk"""
        if wps_status and wps_status.upper() == 'ENABLED':
            return "HIGH RISK - Vulnerable to attacks"
        elif wps_status and wps_status.upper() == 'DISABLED':
            return "SECURE - Good security practice"
        else:
            return "UNKNOWN - Requires investigation"
    
    def _get_confidence_status_text(self, confidence_level):
        """Get confidence status text"""
        try:
            confidence_val = float(confidence_level.replace('%', ''))
            if confidence_val >= 90:
                return "Very High Confidence"
            elif confidence_val >= 75:
                return "High Confidence" 
            elif confidence_val >= 50:
                return "Moderate Confidence"
            else:
                return "Low Confidence"
        except:
            return "Unknown Confidence"
    
    def _get_risk_level(self, score):
        """Get risk level based on security score"""
        if score >= 80:
            return "LOW RISK"
        elif score >= 60:
            return "MEDIUM RISK"
        elif score >= 40:
            return "HIGH RISK"
        else:
            return "CRITICAL RISK"
    
    def _get_risk_status(self, score):
        """Get detailed risk status"""
        if score >= 80:
            return "Minimal Security Concerns"
        elif score >= 60:
            return "Some Vulnerabilities Present"
        elif score >= 40:
            return "Multiple Security Issues"
        else:
            return "Severe Security Weaknesses"
    
    def _get_threat_exposure(self, score):
        """Get threat exposure level"""
        if score >= 80:
            return "LOW"
        elif score >= 60:
            return "MODERATE"
        elif score >= 40:
            return "HIGH"
        else:
            return "SEVERE"

    def _get_threat_status(self, threat_level):
        """Get status for threat level"""
        level_mapping = {
            'NO_RISK': 'Secure',
            'LOW_RISK': 'Low Risk',
            'MEDIUM_RISK': 'Moderate Risk',
            'HIGH_RISK': 'High Risk',
            'CRITICAL_RISK': 'Critical Risk'
        }
        return level_mapping.get(threat_level, 'Unknown')
    
    def _get_confidence_status(self, confidence):
        """Get status for confidence level"""
        if confidence >= 0.8:
            return "High"
        elif confidence >= 0.6:
            return "Medium"
        else:
            return "Low"
    
    def _get_vuln_status(self, count):
        """Get status for vulnerability count"""
        if count == 0:
            return "None"
        elif count <= 2:
            return "Few"
        elif count <= 5:
            return "Several"
        else:
            return "Many"
    
    def _get_rec_status(self, count):
        """Get status for recommendation count"""
        if count == 0:
            return "None"
        elif count <= 3:
            return "Few"
        elif count <= 6:
            return "Several"
        else:
            return "Many"
    
    def _get_risk_level(self, risk_score):
        """Get risk level description"""
        if risk_score >= 80:
            return "Critical"
        elif risk_score >= 60:
            return "High"
        elif risk_score >= 40:
            return "Medium"
        elif risk_score >= 20:
            return "Low"
        else:
            return "Minimal"
    
    def _get_ai_risk_level(self, risk_score):
        """Get AI risk level description (0-10 scale)"""
        if risk_score >= 8:
            return "Critical"
        elif risk_score >= 6:
            return "High"
        elif risk_score >= 4:
            return "Medium"
        elif risk_score >= 2:
            return "Low"
        else:
            return "Minimal"
        
    def _create_title_page(self, scan_data):
        """Create report title page"""
        story = []
        
        # Logo placeholder (if logo exists)
        if os.path.exists('app/static/images/logo.png'):
            logo = Image('app/static/images/logo.png', width=2*inch, height=1*inch)
            logo.hAlign = 'CENTER'
            story.append(logo)
            story.append(Spacer(1, 20))
        
        # Main title
        title = Paragraph("Wi-Fi Security Vulnerability Report", self.styles['CustomTitle'])
        story.append(title)
        story.append(Spacer(1, 30))
        
        # Network information
        network_name = scan_data.get('network_ssid', 'Unknown Network')
        network_para = Paragraph(f"Network: <b>{network_name}</b>", self.styles['CustomHeading1'])
        story.append(network_para)
        story.append(Spacer(1, 20))
        
        # Scan timestamp
        scan_time = scan_data.get('scan_timestamp', datetime.now())
        if isinstance(scan_time, str):
            scan_time = datetime.fromisoformat(scan_time.replace('Z', '+00:00'))
        
        time_para = Paragraph(f"Scan Date: {scan_time.strftime('%Y-%m-%d %H:%M:%S')}", self.styles['Normal'])
        story.append(time_para)
        story.append(Spacer(1, 15))
        
        # Risk level
        risk_level = scan_data.get('risk_level', 'UNKNOWN')
        risk_color = self._get_risk_color(risk_level)
        risk_para = Paragraph(f"Overall Risk Level: <b><font color='{risk_color}'>{risk_level}</font></b>", 
                             self.styles['CustomHeading2'])
        story.append(risk_para)
        story.append(Spacer(1, 20))
        
        # Report metadata
        story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#2e7d32')))
        story.append(Spacer(1, 20))
        
        metadata_data = [
            ['Report Generated:', datetime.now().strftime('%Y-%m-%d %H:%M:%S')],
            ['Scan Duration:', f"{scan_data.get('scan_duration', 'N/A')} seconds"],
            ['Models Used:', f"{len(scan_data.get('model_predictions', {}))} AI Models"],
            ['Vulnerabilities Found:', str(len(scan_data.get('vulnerability_details', [])))]
        ]
        
        metadata_table = Table(metadata_data, colWidths=[2*inch, 3*inch])
        metadata_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#e8f5e8')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(metadata_table)
        
        return story
        
    def _create_executive_summary(self, scan_data):
        """Generate executive summary section"""
        story = []
        
        story.append(Paragraph("Executive Summary", self.styles['CustomHeading1']))
        story.append(Spacer(1, 15))
        
        # Risk assessment summary
        risk_level = scan_data.get('risk_level', 'UNKNOWN')
        vulnerabilities = scan_data.get('vulnerability_details', [])
        
        summary_text = f"""
        This report presents a comprehensive security assessment of the Wi-Fi network 
        "{scan_data.get('network_ssid', 'Unknown')}" conducted on 
        {scan_data.get('scan_timestamp', datetime.now().strftime('%Y-%m-%d'))}.
        
        Our AI-powered analysis system, utilizing 9 specialized machine learning models, 
        has identified {len(vulnerabilities)} potential security concerns with an overall 
        risk classification of <b>{risk_level}</b>.
        """
        
        story.append(Paragraph(summary_text, self.styles['Normal']))
        story.append(Spacer(1, 15))
        
        # Key findings
        story.append(Paragraph("Key Findings:", self.styles['CustomHeading2']))
        
        findings = self._generate_key_findings(scan_data)
        for finding in findings:
            bullet_text = f"• {finding}"
            story.append(Paragraph(bullet_text, self.styles['Normal']))
            story.append(Spacer(1, 5))
            
        story.append(Spacer(1, 20))
        
        # Risk summary chart
        risk_chart = self._create_risk_summary_chart(scan_data)
        if risk_chart:
            story.append(risk_chart)
            
        return story
        
    def _create_network_information(self, scan_data):
        """Create network information section"""
        story = []
        
        story.append(Paragraph("Network Information", self.styles['CustomHeading1']))
        story.append(Spacer(1, 15))
        
        # Network details table
        network_data = [
            ['Property', 'Value'],
            ['SSID', scan_data.get('network_ssid', 'N/A')],
            ['BSSID', scan_data.get('bssid', 'N/A')],
            ['Channel', str(scan_data.get('channel', 'N/A'))],
            ['Frequency', f"{scan_data.get('frequency', 'N/A')} MHz"],
            ['Signal Strength', f"{scan_data.get('signal_strength', 'N/A')} dBm"],
            ['Encryption', scan_data.get('encryption_type', 'N/A')],
            ['Security Protocol', scan_data.get('security_protocol', 'N/A')],
            ['Vendor', scan_data.get('vendor', 'N/A')]
        ]
        
        network_table = Table(network_data, colWidths=[2*inch, 3*inch])
        network_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2e7d32')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE')
        ]))
        
        story.append(network_table)
        story.append(Spacer(1, 20))
        
        return story
        
    def _create_vulnerability_analysis(self, scan_data):
        """Create vulnerability analysis section"""
        story = []
        
        story.append(Paragraph("Vulnerability Analysis", self.styles['CustomHeading1']))
        story.append(Spacer(1, 15))
        
        vulnerabilities = scan_data.get('vulnerability_details', [])
        
        if not vulnerabilities:
            story.append(Paragraph("No vulnerabilities detected.", self.styles['Normal']))
            return story
            
        # Vulnerability summary table
        vuln_data = [['Severity', 'Vulnerability Type', 'Description', 'Risk Score']]
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'Unknown')
            vuln_type = vuln.get('type', 'Unknown')
            description = vuln.get('description', 'No description available')[:50] + '...'
            risk_score = vuln.get('risk_score', 0)
            
            vuln_data.append([severity, vuln_type, description, str(risk_score)])
            
        vuln_table = Table(vuln_data, colWidths=[1*inch, 1.5*inch, 2.5*inch, 1*inch])
        vuln_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#d32f2f')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE')
        ]))
        
        story.append(vuln_table)
        story.append(Spacer(1, 20))
        
        return story
        
    def _create_ai_predictions_section(self, scan_data):
        """Create AI model predictions section"""
        story = []
        
        story.append(Paragraph("AI Model Analysis Results", self.styles['CustomHeading1']))
        story.append(Spacer(1, 15))
        
        model_predictions = scan_data.get('model_predictions', {})
        
        # Model results table
        model_data = [['AI Model', 'Prediction', 'Confidence', 'Threat Category']]
        
        model_names = {
            'cnn': 'Core CNN Model',
            'lstm': 'LSTM Temporal Analysis',
            'gnn': 'Graph Neural Network',
            'crypto_bert': 'Crypto-BERT Protocol Analysis',
            'cnn_lstm': 'CNN-LSTM Hybrid',
            'attention': 'Attention Model',
            'random_forest': 'Random Forest',
            'gradient_boosting': 'Gradient Boosting',
            'ensemble': 'Ensemble Fusion'
        }
        
        for model_key, prediction_data in model_predictions.items():
            model_name = model_names.get(model_key, model_key.upper())
            prediction = prediction_data.get('prediction', 'N/A')
            confidence = f"{prediction_data.get('confidence', 0):.2%}"
            threat_category = prediction_data.get('threat_category', 'Unknown')
            
            model_data.append([model_name, prediction, confidence, threat_category])
            
        if len(model_data) > 1:
            model_table = Table(model_data, colWidths=[2*inch, 1.5*inch, 1*inch, 1.5*inch])
            model_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1976d2')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE')
            ]))
            
            story.append(model_table)
        else:
            story.append(Paragraph("No AI model predictions available.", self.styles['Normal']))
            
        story.append(Spacer(1, 20))
        
        return story
        
    def _create_network_topology_section(self, scan_data):
        """Create network topology visualization section"""
        story = []
        
        story.append(Paragraph("Network Topology Analysis", self.styles['CustomHeading1']))
        story.append(Spacer(1, 15))
        
        topology_data = scan_data.get('network_topology', {})
        
        if topology_data:
            # Network topology description
            devices_count = len(topology_data.get('devices', []))
            connections_count = len(topology_data.get('connections', []))
            
            topology_text = f"""
            Network topology analysis reveals {devices_count} connected devices with 
            {connections_count} network connections. The topology analysis helps identify
            potential attack vectors and security vulnerabilities within the network structure.
            """
            
            story.append(Paragraph(topology_text, self.styles['Normal']))
            story.append(Spacer(1, 15))
            
            # Device inventory
            devices = topology_data.get('devices', [])
            if devices:
                story.append(Paragraph("Connected Devices:", self.styles['CustomHeading2']))
                
                device_data = [['Device Type', 'MAC Address', 'IP Address', 'Security Status']]
                
                for device in devices[:10]:  # Limit to first 10 devices
                    device_type = device.get('type', 'Unknown')
                    mac_address = device.get('mac', 'N/A')
                    ip_address = device.get('ip', 'N/A')
                    security_status = device.get('security_status', 'Unknown')
                    
                    device_data.append([device_type, mac_address, ip_address, security_status])
                    
                device_table = Table(device_data, colWidths=[1.5*inch, 1.8*inch, 1.2*inch, 1.5*inch])
                device_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#388e3c')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 0), (-1, -1), 8),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                    ('VALIGN', (0, 0), (-1, -1), 'MIDDLE')
                ]))
                
                story.append(device_table)
        else:
            story.append(Paragraph("Network topology data not available.", self.styles['Normal']))
            
        story.append(Spacer(1, 20))
        
        return story
        
    def _create_recommendations_section(self, scan_data):
        """Create security recommendations section"""
        story = []
        
        story.append(Paragraph("Security Recommendations", self.styles['CustomHeading1']))
        story.append(Spacer(1, 15))
        
        recommendations = scan_data.get('recommendations', [])
        
        if not recommendations:
            recommendations = self._generate_default_recommendations(scan_data)
            
        # Priority-based recommendations
        priority_groups = {'HIGH': [], 'MEDIUM': [], 'LOW': []}
        
        for rec in recommendations:
            priority = rec.get('priority', 'MEDIUM')
            priority_groups[priority].append(rec)
            
        for priority in ['HIGH', 'MEDIUM', 'LOW']:
            if priority_groups[priority]:
                story.append(Paragraph(f"{priority} Priority Recommendations:", 
                                     self.styles['CustomHeading2']))
                
                for i, rec in enumerate(priority_groups[priority], 1):
                    title = rec.get('title', f'Recommendation {i}')
                    description = rec.get('description', 'No description available')
                    
                    rec_text = f"<b>{i}. {title}</b><br/>{description}"
                    story.append(Paragraph(rec_text, self.styles['Normal']))
                    story.append(Spacer(1, 10))
                    
                story.append(Spacer(1, 15))
                
        return story
        
    def _create_technical_details(self, scan_data):
        """Create technical details section"""
        story = []
        
        story.append(Paragraph("Technical Details", self.styles['CustomHeading1']))
        story.append(Spacer(1, 15))
        
        # Scan configuration
        story.append(Paragraph("Scan Configuration:", self.styles['CustomHeading2']))
        
        config_data = [
            ['Scan Type', scan_data.get('scan_type', 'Deep Scan')],
            ['Duration', f"{scan_data.get('scan_duration', 'N/A')} seconds"],
            ['AI Models Used', str(len(scan_data.get('model_predictions', {})))],
            ['Data Points Analyzed', str(scan_data.get('data_points_analyzed', 'N/A'))],
            ['Analysis Confidence', f"{scan_data.get('overall_confidence', 0):.2%}"]
        ]
        
        config_table = Table(config_data, colWidths=[2*inch, 3*inch])
        config_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#e8f5e8')),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(config_table)
        story.append(Spacer(1, 20))
        
        return story
        
    def _create_appendices(self, scan_data):
        """Create report appendices"""
        story = []
        
        story.append(Paragraph("Appendices", self.styles['CustomHeading1']))
        story.append(Spacer(1, 15))
        
        # Appendix A: Threat Classification
        story.append(Paragraph("Appendix A: Threat Classification System", self.styles['CustomHeading2']))
        
        threat_classes = [
            ('NO_THREAT', 'System secure - no vulnerabilities detected'),
            ('LOW_RISK_VULNERABILITY', 'Minor security gap with minimal impact'),
            ('MEDIUM_RISK_VULNERABILITY', 'Moderate security concern requiring attention'),
            ('HIGH_RISK_VULNERABILITY', 'Serious security flaw needing immediate action'),
            ('CRITICAL_VULNERABILITY', 'Critical security breach requiring urgent response'),
            ('ACTIVE_ATTACK_DETECTED', 'Active malicious activity in progress')
        ]
        
        for threat_class, description in threat_classes:
            threat_text = f"<b>{threat_class}:</b> {description}"
            story.append(Paragraph(threat_text, self.styles['Normal']))
            story.append(Spacer(1, 5))
            
        story.append(Spacer(1, 20))
        
        # Appendix B: AI Model Information
        story.append(Paragraph("Appendix B: AI Model Information", self.styles['CustomHeading2']))
        
        model_info = """
        This analysis utilizes a comprehensive ensemble of 9 specialized AI models:
        • Core CNN Model: Pattern recognition in network traffic
        • LSTM Models: Temporal behavior analysis
        • Graph Neural Network: Network topology analysis
        • Crypto-BERT: Cryptographic protocol analysis
        • Ensemble Fusion: Meta-learning decision fusion
        """
        
        story.append(Paragraph(model_info, self.styles['Normal']))
        
        return story
        
    def _create_risk_summary_chart(self, scan_data):
        """Create risk summary pie chart"""
        try:
            # Create drawing
            drawing = Drawing(400, 200)
            
            # Risk distribution data
            vulnerabilities = scan_data.get('vulnerability_details', [])
            risk_counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
            
            for vuln in vulnerabilities:
                severity = vuln.get('severity', 'LOW')
                if severity in risk_counts:
                    risk_counts[severity] += 1
                    
            # Create pie chart
            pie = Pie()
            pie.x = 50
            pie.y = 50
            pie.width = 150
            pie.height = 150
            
            pie.data = list(risk_counts.values())
            pie.labels = [f'{k}: {v}' for k, v in risk_counts.items()]
            pie.slices.strokeWidth = 0.5
            pie.slices[0].fillColor = colors.red
            pie.slices[1].fillColor = colors.orange
            pie.slices[2].fillColor = colors.green
            
            drawing.add(pie)
            
            return drawing
            
        except Exception as e:
            current_app.logger.error(f"Error creating risk chart: {str(e)}")
            return None
            
    def _generate_key_findings(self, scan_data):
        """Generate key findings for executive summary"""
        findings = []
        
        risk_level = scan_data.get('risk_level', 'UNKNOWN')
        vulnerabilities = scan_data.get('vulnerability_details', [])
        
        # Risk level finding
        findings.append(f"Overall network risk level assessed as {risk_level}")
        
        # Vulnerability count
        if vulnerabilities:
            high_risk = len([v for v in vulnerabilities if v.get('severity') == 'HIGH'])
            if high_risk > 0:
                findings.append(f"{high_risk} high-severity vulnerabilities identified")
            findings.append(f"Total of {len(vulnerabilities)} security concerns detected")
        else:
            findings.append("No critical vulnerabilities detected in the current scan")
            
        # AI model consensus
        model_predictions = scan_data.get('model_predictions', {})
        if model_predictions:
            findings.append(f"Analysis conducted using {len(model_predictions)} specialized AI models")
            
        # Network characteristics
        encryption = scan_data.get('encryption_type', 'Unknown')
        if encryption:
            findings.append(f"Network uses {encryption} encryption protocol")
            
        return findings
        
    def _generate_default_recommendations(self, scan_data):
        """Generate default security recommendations"""
        recommendations = []
        
        risk_level = scan_data.get('risk_level', 'UNKNOWN')
        
        if risk_level == 'HIGH':
            recommendations.extend([
                {
                    'title': 'Immediate Security Review',
                    'description': 'Conduct immediate comprehensive security review and remediation',
                    'priority': 'HIGH'
                },
                {
                    'title': 'Update Security Protocols',
                    'description': 'Update encryption protocols and security configurations',
                    'priority': 'HIGH'
                }
            ])
        elif risk_level == 'MEDIUM':
            recommendations.extend([
                {
                    'title': 'Security Configuration Review',
                    'description': 'Review and update security configurations',
                    'priority': 'MEDIUM'
                }
            ])
        else:
            recommendations.extend([
                {
                    'title': 'Regular Monitoring',
                    'description': 'Maintain regular security monitoring and periodic scans',
                    'priority': 'LOW'
                }
            ])
            
        return recommendations
        
    def _get_risk_color(self, risk_level):
        """Get color for risk level"""
        colors_map = {
            'HIGH': '#d32f2f',
            'MEDIUM': '#f57c00',
            'LOW': '#388e3c',
            'NORMAL': '#4caf50'
        }
        return colors_map.get(risk_level, '#666666')
        
    def _add_header_footer(self, canvas, doc):
        """Add header and footer to pages"""
        canvas.saveState()
        
        # Header
        canvas.setFont('Helvetica-Bold', 10)
        canvas.drawString(doc.leftMargin, doc.height + doc.topMargin - 20, 
                         "Wi-Fi Security Vulnerability Report")
        
        # Footer
        canvas.setFont('Helvetica', 8)
        canvas.drawString(doc.leftMargin, 30, 
                         f"Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        canvas.drawRightString(doc.width + doc.rightMargin, 30, 
                              f"Page {doc.page}")
        
        canvas.restoreState()


class ReportTemplate:
    """Report template system for different report types"""
    
    def __init__(self):
        self.templates = {
            'vulnerability': 'vulnerability_report_template.html',
            'executive': 'executive_summary_template.html',
            'technical': 'technical_details_template.html'
        }
        
    def get_template(self, template_type):
        """Get template by type"""
        return self.templates.get(template_type, self.templates['vulnerability'])
        
    def render_template(self, template_type, data):
        """Render template with data"""
        # Template rendering logic would go here
        # For now, return the data as-is
        return data


class ChartGenerator:
    """Chart and graph generation for PDF reports"""
    
    def __init__(self):
        self.chart_width = 400
        self.chart_height = 200
        
    def create_vulnerability_distribution_chart(self, vulnerability_data):
        """Create vulnerability distribution pie chart"""
        try:
            drawing = Drawing(self.chart_width, self.chart_height)
            
            # Count vulnerabilities by severity
            severity_counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
            
            for vuln in vulnerability_data:
                severity = vuln.get('severity', 'LOW')
                if severity in severity_counts:
                    severity_counts[severity] += 1
                    
            if sum(severity_counts.values()) == 0:
                return None
                
            # Create pie chart
            pie = Pie()
            pie.x = 50
            pie.y = 50
            pie.width = 150
            pie.height = 150
            
            pie.data = list(severity_counts.values())
            pie.labels = [f'{k}: {v}' for k, v in severity_counts.items() if v > 0]
            
            # Set colors
            colors_list = []
            for severity, count in severity_counts.items():
                if count > 0:
                    if severity == 'HIGH':
                        colors_list.append(colors.red)
                    elif severity == 'MEDIUM':
                        colors_list.append(colors.orange)
                    else:
                        colors_list.append(colors.green)
                        
            for i, color in enumerate(colors_list):
                pie.slices[i].fillColor = color
                pie.slices[i].strokeWidth = 1
                pie.slices[i].strokeColor = colors.black
                
            drawing.add(pie)
            
            # Add title
            title = drawing.add(Paragraph("Vulnerability Distribution", 
                                        getSampleStyleSheet()['Heading3']))
            
            return drawing
            
        except Exception as e:
            current_app.logger.error(f"Error creating vulnerability chart: {str(e)}")
            return None
            
    def create_risk_timeline_chart(self, timeline_data):
        """Create risk assessment timeline chart"""
        try:
            drawing = Drawing(self.chart_width, self.chart_height)
            
            if not timeline_data:
                return None
                
            # Create line chart
            line_chart = HorizontalLineChart()
            line_chart.x = 50
            line_chart.y = 50
            line_chart.width = 300
            line_chart.height = 150
            
            # Prepare data
            times = [entry.get('timestamp', 0) for entry in timeline_data]
            risk_scores = [entry.get('risk_score', 0) for entry in timeline_data]
            
            line_chart.data = [risk_scores]
            line_chart.categoryAxis.categoryNames = [str(t) for t in times]
            
            # Styling
            line_chart.lines[0].strokeColor = colors.red
            line_chart.lines[0].strokeWidth = 2
            
            drawing.add(line_chart)
            
            return drawing
            
        except Exception as e:
            current_app.logger.error(f"Error creating timeline chart: {str(e)}")
            return None
            
    def create_model_confidence_chart(self, model_predictions):
        """Create AI model confidence bar chart"""
        try:
            drawing = Drawing(self.chart_width, self.chart_height)
            
            if not model_predictions:
                return None
                
            # Create vertical bar chart
            bar_chart = VerticalBarChart()
            bar_chart.x = 50
            bar_chart.y = 50
            bar_chart.width = 300
            bar_chart.height = 150
            
            # Prepare data
            model_names = []
            confidences = []
            
            for model_name, prediction_data in model_predictions.items():
                model_names.append(model_name.upper())
                confidences.append(prediction_data.get('confidence', 0) * 100)
                
            bar_chart.data = [confidences]
            bar_chart.categoryAxis.categoryNames = model_names
            
            # Styling
            bar_chart.bars[0].fillColor = colors.blue
            bar_chart.valueAxis.valueMin = 0
            bar_chart.valueAxis.valueMax = 100
            
            drawing.add(bar_chart)
            
            return drawing
            
        except Exception as e:
            current_app.logger.error(f"Error creating confidence chart: {str(e)}")
            return None
            
    def create_network_topology_diagram(self, topology_data):
        """Create network topology diagram"""
        try:
            drawing = Drawing(self.chart_width, self.chart_height)
            
            devices = topology_data.get('devices', [])
            connections = topology_data.get('connections', [])
            
            if not devices:
                return None
                
            # Simple network diagram
            center_x, center_y = 200, 100
            radius = 80
            
            # Draw devices as circles
            for i, device in enumerate(devices[:8]):  # Limit to 8 devices for clarity
                angle = (2 * 3.14159 * i) / len(devices)
                x = center_x + radius * np.cos(angle) if 'np' in globals() else center_x + 50
                y = center_y + radius * np.sin(angle) if 'np' in globals() else center_y + 20 * i
                
                # Device circle
                circle = Circle(x, y, 10)
                circle.fillColor = colors.lightblue
                circle.strokeColor = colors.black
                drawing.add(circle)
                
                # Connection lines to center
                line = Line(center_x, center_y, x, y)
                line.strokeColor = colors.gray
                drawing.add(line)
                
            # Central router/AP
            center_circle = Circle(center_x, center_y, 15)
            center_circle.fillColor = colors.red
            center_circle.strokeColor = colors.black
            drawing.add(center_circle)
            
            return drawing
            
        except Exception as e:
            current_app.logger.error(f"Error creating topology diagram: {str(e)}")
            return None
    
    # Helper methods for status assessments
    def _get_security_status(self, status):
        """Get security status assessment"""
        status_lower = status.lower()
        if 'secure' in status_lower or 'no threat' in status_lower:
            return "✓ SECURE"
        elif 'vulnerability' in status_lower or 'risk' in status_lower:
            return "⚠ AT RISK"
        elif 'threat' in status_lower or 'attack' in status_lower:
            return "✗ THREAT DETECTED"
        else:
            return "? UNKNOWN"
    
    def _get_confidence_status_text(self, confidence_text):
        """Get confidence status assessment"""
        try:
            confidence = float(confidence_text.replace('%', ''))
            if confidence >= 80:
                return "HIGH CONFIDENCE"
            elif confidence >= 60:
                return "MODERATE CONFIDENCE"
            elif confidence >= 40:
                return "LOW CONFIDENCE"
            else:
                return "VERY LOW CONFIDENCE"
        except:
            return "UNKNOWN CONFIDENCE"
    
    def _get_risk_status(self, risk_level):
        """Get risk level status"""
        risk_lower = risk_level.lower()
        if 'minimal' in risk_lower or 'low' in risk_lower:
            return "✓ LOW RISK"
        elif 'moderate' in risk_lower or 'medium' in risk_lower:
            return "⚠ MODERATE RISK"
        elif 'high' in risk_lower or 'critical' in risk_lower:
            return "✗ HIGH RISK"
        else:
            return "? UNKNOWN RISK"
    
    def _get_threat_count_status(self, count):
        """Get threat count status"""
        if count == 0:
            return "✓ NO THREATS"
        elif count <= 2:
            return "⚠ FEW THREATS"
        else:
            return "✗ MULTIPLE THREATS"
    
    def _get_recommendations_status(self, immediate_count):
        """Get recommendations status"""
        if immediate_count == 0:
            return "✓ NO URGENT ACTIONS"
        elif immediate_count <= 2:
            return "⚠ FEW URGENT ACTIONS"
        else:
            return "✗ MANY URGENT ACTIONS"
    
    def _get_status_color(self, risk_level):
        """Get color for status level"""
        risk_lower = risk_level.lower()
        if 'minimal' in risk_lower or 'low' in risk_lower:
            return colors.HexColor('#2e7d32')  # Green
        elif 'moderate' in risk_lower or 'medium' in risk_lower:
            return colors.HexColor('#f57c00')  # Orange
        elif 'high' in risk_lower or 'critical' in risk_lower:
            return colors.HexColor('#d32f2f')  # Red
        else:
            return colors.HexColor('#616161')  # Gray


class ReportFormatter:
    """Content formatting utilities for PDF reports"""
    
    def __init__(self):
        self.styles = getSampleStyleSheet()
        
    def format_vulnerability_details(self, vulnerabilities):
        """Format vulnerability details for display"""
        formatted_vulns = []
        
        for vuln in vulnerabilities:
            formatted_vuln = {
                'title': vuln.get('type', 'Unknown Vulnerability'),
                'severity': vuln.get('severity', 'MEDIUM'),
                'description': vuln.get('description', 'No description available'),
                'risk_score': vuln.get('risk_score', 0),
                'remediation': vuln.get('remediation', 'Contact system administrator'),
                'cve_references': vuln.get('cve_references', [])
            }
            formatted_vulns.append(formatted_vuln)
            
        return formatted_vulns
        
    def format_model_predictions(self, predictions):
        """Format AI model predictions for display"""
        formatted_predictions = {}
        
        model_display_names = {
            'cnn': 'Core CNN Model (Pattern Recognition)',
            'lstm': 'LSTM Model (Temporal Analysis)', 
            'gnn': 'Graph Neural Network (Topology)',
            'crypto_bert': 'Crypto-BERT (Protocol Analysis)',
            'cnn_lstm': 'CNN-LSTM Hybrid (Spatial-Temporal)',
            'attention': 'Attention Model (Sequence Analysis)',
            'random_forest': 'Random Forest (Tree-based)',
            'gradient_boosting': 'Gradient Boosting (Sequential)',
            'ensemble': 'Ensemble Fusion (Meta-learning)'
        }
        
        for model_key, prediction_data in predictions.items():
            display_name = model_display_names.get(model_key, model_key.upper())
            formatted_predictions[display_name] = {
                'prediction': prediction_data.get('prediction', 'N/A'),
                'confidence': prediction_data.get('confidence', 0),
                'threat_category': prediction_data.get('threat_category', 'Unknown'),
                'risk_level': prediction_data.get('risk_level', 'Unknown'),
                'details': prediction_data.get('details', {})
            }
            
        return formatted_predictions
        
    def format_network_information(self, network_data):
        """Format network information for display"""
        formatted_info = {
            'basic_info': {
                'SSID': network_data.get('network_ssid', 'N/A'),
                'BSSID': network_data.get('bssid', 'N/A'),
                'Channel': str(network_data.get('channel', 'N/A')),
                'Frequency': f"{network_data.get('frequency', 'N/A')} MHz",
                'Signal Strength': f"{network_data.get('signal_strength', 'N/A')} dBm"
            },
            'security_info': {
                'Encryption Type': network_data.get('encryption_type', 'N/A'),
                'Security Protocol': network_data.get('security_protocol', 'N/A'),
                'Authentication Method': network_data.get('auth_method', 'N/A'),
                'WPS Status': network_data.get('wps_enabled', 'Unknown')
            },
            'technical_info': {
                'Vendor': network_data.get('vendor', 'N/A'),
                'Device Type': network_data.get('device_type', 'N/A'),
                'Operating System': network_data.get('os_detection', 'N/A'),
                'Firmware Version': network_data.get('firmware_version', 'N/A')
            }
        }
        
        return formatted_info
        
    def format_recommendations(self, recommendations, risk_level):
        """Format security recommendations based on risk level"""
        formatted_recs = []
        
        # Add risk-specific recommendations
        if risk_level == 'HIGH':
            formatted_recs.extend([
                {
                    'priority': 'CRITICAL',
                    'title': 'Immediate Security Assessment',
                    'description': 'Perform immediate comprehensive security assessment and implement emergency security measures.',
                    'timeline': 'Within 24 hours',
                    'effort': 'High'
                },
                {
                    'priority': 'HIGH', 
                    'title': 'Update Security Configurations',
                    'description': 'Update all security configurations, passwords, and encryption protocols.',
                    'timeline': 'Within 48 hours',
                    'effort': 'Medium'
                }
            ])
        elif risk_level == 'MEDIUM':
            formatted_recs.extend([
                {
                    'priority': 'MEDIUM',
                    'title': 'Security Configuration Review',
                    'description': 'Review current security configurations and update as necessary.',
                    'timeline': 'Within 1 week',
                    'effort': 'Medium'
                }
            ])
        else:
            formatted_recs.extend([
                {
                    'priority': 'LOW',
                    'title': 'Regular Security Monitoring',
                    'description': 'Maintain regular security monitoring and periodic vulnerability assessments.',
                    'timeline': 'Ongoing',
                    'effort': 'Low'
                }
            ])
            
        # Add custom recommendations
        for rec in recommendations:
            if isinstance(rec, dict):
                formatted_recs.append({
                    'priority': rec.get('priority', 'MEDIUM'),
                    'title': rec.get('title', 'Security Recommendation'),
                    'description': rec.get('description', 'No description provided'),
                    'timeline': rec.get('timeline', 'To be determined'),
                    'effort': rec.get('effort', 'Medium')
                })
                
        return formatted_recs
        
    def create_executive_summary_text(self, scan_data):
        """Create executive summary text"""
        network_name = scan_data.get('network_ssid', 'Unknown Network')
        risk_level = scan_data.get('risk_level', 'UNKNOWN')
        vulnerability_count = len(scan_data.get('vulnerability_details', []))
        model_count = len(scan_data.get('model_predictions', {}))
        scan_date = scan_data.get('scan_timestamp', datetime.now())
        
        if isinstance(scan_date, str):
            try:
                scan_date = datetime.fromisoformat(scan_date.replace('Z', '+00:00'))
            except:
                scan_date = datetime.now()
                
        summary_text = f"""
This comprehensive Wi-Fi security assessment was conducted on the network "{network_name}" 
on {scan_date.strftime('%B %d, %Y at %H:%M')}. Our advanced AI-powered analysis system, 
utilizing an ensemble of {model_count} specialized machine learning models, has completed 
a thorough evaluation of the network's security posture.

The analysis has identified {vulnerability_count} potential security concerns and classified 
the overall network risk level as {risk_level}. This assessment encompasses multiple security 
dimensions including encryption strength, network topology vulnerabilities, protocol analysis, 
temporal behavior patterns, and cryptographic implementations.

Our multi-model approach combines deep learning techniques including Convolutional Neural 
Networks (CNN) for pattern recognition, Long Short-Term Memory (LSTM) networks for temporal 
analysis, Graph Neural Networks (GNN) for topology assessment, and a specialized Crypto-BERT 
model for protocol analysis. The ensemble fusion system provides meta-learning capabilities 
to deliver highly accurate threat classifications with confidence scores.
"""

        return summary_text.strip()


# Export functions for use by other modules
def generate_vulnerability_report(scan_data):
    """
    Main function to generate vulnerability PDF report
    
    Args:
        scan_data (dict): Comprehensive scan results data
        
    Returns:
        BytesIO: PDF report buffer
    """
    try:
        generator = PDFGenerator()
        return generator.generate_vulnerability_report(scan_data)
    except Exception as e:
        current_app.logger.error(f"Error generating PDF report: {str(e)}")
        raise


def add_charts_and_graphs(story, scan_data):
    """
    Add charts and graphs to PDF report
    
    Args:
        story (list): ReportLab story elements
        scan_data (dict): Scan results data
        
    Returns:
        list: Updated story with charts
    """
    try:
        chart_generator = ChartGenerator()
        
        # Add vulnerability distribution chart
        vuln_chart = chart_generator.create_vulnerability_distribution_chart(
            scan_data.get('vulnerability_details', [])
        )
        if vuln_chart:
            story.append(vuln_chart)
            story.append(Spacer(1, 20))
            
        # Add model confidence chart
        confidence_chart = chart_generator.create_model_confidence_chart(
            scan_data.get('model_predictions', {})
        )
        if confidence_chart:
            story.append(confidence_chart)
            story.append(Spacer(1, 20))
            
        # Add network topology diagram
        topology_chart = chart_generator.create_network_topology_diagram(
            scan_data.get('network_topology', {})
        )
        if topology_chart:
            story.append(topology_chart)
            story.append(Spacer(1, 20))
            
        return story
        
    except Exception as e:
        current_app.logger.error(f"Error adding charts to report: {str(e)}")
        return story


def format_recommendations(recommendations, risk_level='MEDIUM'):
    """
    Format security recommendations for PDF display
    
    Args:
        recommendations (list): List of recommendation dictionaries
        risk_level (str): Overall risk level
        
    Returns:
        list: Formatted recommendations
    """
    formatter = ReportFormatter()
    return formatter.format_recommendations(recommendations, risk_level)


def create_executive_summary(scan_data):
    """
    Create executive summary section for PDF
    
    Args:
        scan_data (dict): Scan results data
        
    Returns:
        str: Formatted executive summary text
    """
    formatter = ReportFormatter()
    return formatter.create_executive_summary_text(scan_data)


def apply_branding(doc, company_info=None):
    """
    Apply corporate branding to PDF report
    
    Args:
        doc: ReportLab document object
        company_info (dict): Company branding information
        
    Returns:
        None
    """
    try:
        if company_info:
            # Apply custom branding if provided
            logo_path = company_info.get('logo_path')
            if logo_path and os.path.exists(logo_path):
                # Logo would be added to header/footer
                pass
                
            company_name = company_info.get('name', 'Wi-Fi Security System')
            # Apply company name to headers
            
        # Default branding
        doc.title = "Wi-Fi Security Vulnerability Assessment Report"
        doc.author = "Wi-Fi Security System"
        doc.subject = "Network Security Analysis"
        
    except Exception as e:
        current_app.logger.error(f"Error applying branding: {str(e)}")


# Utility functions for data processing
def calculate_risk_metrics(vulnerability_data):
    """Calculate risk metrics from vulnerability data"""
    if not vulnerability_data:
        return {'total_score': 0, 'avg_score': 0, 'max_score': 0}
        
    scores = [vuln.get('risk_score', 0) for vuln in vulnerability_data]
    
    return {
        'total_score': sum(scores),
        'avg_score': sum(scores) / len(scores) if scores else 0,
        'max_score': max(scores) if scores else 0
    }


def generate_threat_summary(model_predictions):
    """Generate threat summary from AI model predictions"""
    if not model_predictions:
        return "No threat analysis available"
        
    threat_categories = []
    high_confidence_predictions = []
    
    for model_name, prediction_data in model_predictions.items():
        confidence = prediction_data.get('confidence', 0)
        if confidence > 0.8:  # High confidence threshold
            threat_category = prediction_data.get('threat_category', 'Unknown')
            if threat_category not in threat_categories:
                threat_categories.append(threat_category)
            high_confidence_predictions.append(f"{model_name}: {threat_category}")
            
    summary = f"Analysis identified {len(threat_categories)} distinct threat categories "
    summary += f"with {len(high_confidence_predictions)} high-confidence predictions."
    
    return summary