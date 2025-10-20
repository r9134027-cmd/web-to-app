import sys
import os
import json
import threading
from datetime import datetime
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QTextEdit, QProgressBar,
    QTabWidget, QScrollArea, QMessageBox, QFileDialog, QGroupBox,
    QGridLayout, QSplitter
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt5.QtGui import QFont, QTextCursor, QPalette, QColor, QPixmap, QIcon

from dotenv import load_dotenv
from recon import get_recon_data
from auth_check import check_authenticity, get_official_link
from pdf_generator import generate_pdf_report
from ai_threat_predictor import threat_predictor
from ai_threat_forecaster import threat_forecaster
from compliance_auditor import compliance_auditor
from vulnerability_correlator import vulnerability_correlator
from blockchain_analyzer import blockchain_analyzer
from visual_attack_mapper import visual_attack_mapper
from automated_remediation import automated_remediation
from graph_mapper import graph_mapper
from web3_scanner import web3_scanner
from owasp_checker import owasp_checker
from ip_geolocation import ip_geolocation
from wayback_analyzer import wayback_analyzer

load_dotenv()


class ScanWorker(QThread):
    progress_update = pyqtSignal(int, str)
    scan_complete = pyqtSignal(dict)
    scan_error = pyqtSignal(str)

    def __init__(self, domain):
        super().__init__()
        self.domain = domain
        self.is_running = True

    def run(self):
        try:
            self.progress_update.emit(5, "Starting comprehensive analysis...")

            auth_result = check_authenticity(f'https://{self.domain}')
            self.progress_update.emit(15, "Performing reconnaissance...")

            recon_data = get_recon_data(self.domain)
            self.progress_update.emit(35, "Analyzing threats with AI...")

            threat_analysis = threat_predictor.predict_threat_level(recon_data)
            self.progress_update.emit(50, "Creating relationship graph...")

            graph_data = graph_mapper.create_domain_graph(recon_data)
            self.progress_update.emit(65, "Scanning Web3 domains...")

            web3_analysis = web3_scanner.scan_web3_domain(self.domain)
            self.progress_update.emit(70, "Performing OWASP security checks...")

            owasp_analysis = owasp_checker.analyze_domain(self.domain)
            self.progress_update.emit(75, "Getting IP geolocation data...")

            geolocation_data = ip_geolocation.get_location_data(self.domain)
            self.progress_update.emit(77, "Analyzing Wayback Machine archives...")

            wayback_data = wayback_analyzer.analyze_domain(self.domain)
            self.progress_update.emit(82, "Generating threat forecasts...")

            threat_forecasting = threat_forecaster.forecast_threats(recon_data)
            self.progress_update.emit(85, "Conducting compliance audit...")

            compliance_audit = compliance_auditor.audit_compliance(self.domain)
            self.progress_update.emit(88, "Correlating vulnerabilities...")

            vulnerability_analysis = vulnerability_correlator.correlate_vulnerabilities(recon_data)
            self.progress_update.emit(90, "Analyzing blockchain domains...")

            blockchain_analysis = blockchain_analyzer.analyze_blockchain_domain(self.domain)
            self.progress_update.emit(92, "Creating attack surface map...")

            visual_attack_surface = visual_attack_mapper.create_attack_surface_map(
                recon_data, vulnerability_analysis
            )
            self.progress_update.emit(95, "Generating remediation playbook...")

            remediation_playbook = automated_remediation.generate_remediation_playbook(
                recon_data, vulnerability_analysis, threat_analysis
            )
            self.progress_update.emit(98, "Finalizing comprehensive report...")

            result = {
                'domain': self.domain,
                'timestamp': datetime.now().isoformat(),
                'authenticity': auth_result,
                'reconnaissance': recon_data,
                'threat_analysis': threat_analysis,
                'threat_forecasting': threat_forecasting,
                'compliance_audit': compliance_audit,
                'vulnerability_analysis': vulnerability_analysis,
                'blockchain_analysis': blockchain_analysis,
                'visual_attack_surface': visual_attack_surface,
                'remediation_playbook': remediation_playbook,
                'graph_data': graph_data,
                'web3_analysis': web3_analysis,
                'owasp_analysis': owasp_analysis,
                'geolocation': geolocation_data,
                'wayback_data': wayback_data,
                'official_link': get_official_link(self.domain) if not auth_result['is_genuine'] else None
            }

            self.progress_update.emit(100, "Analysis completed!")
            self.scan_complete.emit(result)

        except Exception as e:
            self.scan_error.emit(str(e))

    def stop(self):
        self.is_running = False


class DomainReconApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.current_results = None
        self.scan_worker = None
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("Domain Intelligent - Advanced Reconnaissance Platform")
        self.setMinimumSize(1400, 900)

        logo_path = os.path.join(os.path.dirname(__file__), 'assets', 'noBgWhite.png')
        if os.path.exists(logo_path):
            self.setWindowIcon(QIcon(logo_path))

        palette = QPalette()
        palette.setColor(QPalette.Window, QColor(17, 24, 39))
        palette.setColor(QPalette.WindowText, QColor(243, 244, 246))
        palette.setColor(QPalette.Base, QColor(31, 41, 55))
        palette.setColor(QPalette.AlternateBase, QColor(55, 65, 81))
        palette.setColor(QPalette.Text, QColor(243, 244, 246))
        palette.setColor(QPalette.Button, QColor(55, 65, 81))
        palette.setColor(QPalette.ButtonText, QColor(243, 244, 246))
        palette.setColor(QPalette.Highlight, QColor(59, 130, 246))
        palette.setColor(QPalette.HighlightedText, QColor(255, 255, 255))
        self.setPalette(palette)

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        central_widget.setStyleSheet("background-color: #111827;")

        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(30, 25, 30, 25)
        main_layout.setSpacing(20)

        header_widget = QWidget()
        header_widget.setStyleSheet("""
            background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                stop:0 #1e293b, stop:1 #334155);
            border-radius: 12px;
            padding: 20px;
        """)
        header_layout = QHBoxLayout(header_widget)

        logo_label = QLabel()
        logo_pixmap = QPixmap(logo_path)
        if not logo_pixmap.isNull():
            scaled_pixmap = logo_pixmap.scaled(80, 80, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            logo_label.setPixmap(scaled_pixmap)
        header_layout.addWidget(logo_label)

        title_container = QWidget()
        title_layout = QVBoxLayout(title_container)
        title_layout.setSpacing(5)
        title_layout.setContentsMargins(15, 0, 0, 0)

        title_label = QLabel("DOMAIN INTELLIGENT")
        title_font = QFont("Segoe UI", 28, QFont.Bold)
        title_label.setFont(title_font)
        title_label.setStyleSheet("""
            color: #f1f5f9;
            background: transparent;
            letter-spacing: 2px;
        """)
        title_layout.addWidget(title_label)

        subtitle_label = QLabel("Advanced Security Reconnaissance & Threat Intelligence Platform")
        subtitle_font = QFont("Segoe UI", 11)
        subtitle_label.setFont(subtitle_font)
        subtitle_label.setStyleSheet("""
            color: #94a3b8;
            background: transparent;
        """)
        title_layout.addWidget(subtitle_label)

        header_layout.addWidget(title_container)
        header_layout.addStretch()

        main_layout.addWidget(header_widget)

        scan_group = QGroupBox("Domain Scanning")
        scan_group.setStyleSheet("""
            QGroupBox {
                font-weight: 600;
                font-size: 14px;
                border: 2px solid #2563eb;
                border-radius: 10px;
                margin-top: 15px;
                padding: 20px;
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #1e293b, stop:1 #0f172a);
            }
            QGroupBox::title {
                color: #60a5fa;
                subcontrol-origin: margin;
                left: 15px;
                padding: 0 8px;
            }
        """)
        scan_layout = QVBoxLayout()

        input_layout = QHBoxLayout()
        domain_label = QLabel("Domain:")
        domain_label.setStyleSheet("color: #e2e8f0; font-weight: bold;")
        input_layout.addWidget(domain_label)

        self.domain_input = QLineEdit()
        self.domain_input.setPlaceholderText("Enter domain (e.g., example.com)")
        self.domain_input.setStyleSheet("""
            QLineEdit {
                padding: 12px 16px;
                border: 2px solid #374151;
                border-radius: 8px;
                background-color: #1f2937;
                color: #f3f4f6;
                font-size: 14px;
                font-family: 'Segoe UI', Arial;
            }
            QLineEdit:focus {
                border: 2px solid #3b82f6;
                background-color: #111827;
            }
            QLineEdit::placeholder {
                color: #6b7280;
            }
        """)
        input_layout.addWidget(self.domain_input)

        self.scan_button = QPushButton("Start Scan")
        self.scan_button.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #3b82f6, stop:1 #2563eb);
                color: white;
                padding: 12px 35px;
                border: none;
                border-radius: 8px;
                font-weight: 600;
                font-size: 14px;
                font-family: 'Segoe UI', Arial;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #2563eb, stop:1 #1d4ed8);
            }
            QPushButton:pressed {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #1e40af, stop:1 #1e3a8a);
            }
            QPushButton:disabled {
                background-color: #374151;
                color: #6b7280;
            }
        """)
        self.scan_button.clicked.connect(self.start_scan)
        input_layout.addWidget(self.scan_button)

        scan_layout.addLayout(input_layout)

        self.progress_bar = QProgressBar()
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 2px solid #374151;
                border-radius: 8px;
                text-align: center;
                height: 32px;
                background-color: #1f2937;
                color: #f3f4f6;
                font-weight: 600;
                font-size: 13px;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #3b82f6, stop:0.5 #2563eb, stop:1 #3b82f6);
                border-radius: 6px;
            }
        """)
        scan_layout.addWidget(self.progress_bar)

        self.status_label = QLabel("Ready to scan")
        self.status_label.setAlignment(Qt.AlignCenter)
        self.status_label.setStyleSheet("color: #94a3b8; padding: 5px;")
        scan_layout.addWidget(self.status_label)

        scan_group.setLayout(scan_layout)
        main_layout.addWidget(scan_group)

        self.tabs = QTabWidget()
        self.tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 2px solid #374151;
                border-radius: 10px;
                background-color: #0f172a;
                padding: 5px;
            }
            QTabBar::tab {
                background-color: #1f2937;
                color: #9ca3af;
                padding: 12px 24px;
                border: none;
                border-top-left-radius: 8px;
                border-top-right-radius: 8px;
                margin-right: 4px;
                font-weight: 500;
                font-size: 13px;
            }
            QTabBar::tab:selected {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #3b82f6, stop:1 #2563eb);
                color: white;
                font-weight: 600;
            }
            QTabBar::tab:hover:!selected {
                background-color: #374151;
                color: #d1d5db;
            }
        """)

        self.overview_tab = QTextEdit()
        self.setup_text_edit(self.overview_tab)
        self.tabs.addTab(self.overview_tab, "Overview")

        self.security_tab = QTextEdit()
        self.setup_text_edit(self.security_tab)
        self.tabs.addTab(self.security_tab, "Security Analysis")

        self.threats_tab = QTextEdit()
        self.setup_text_edit(self.threats_tab)
        self.tabs.addTab(self.threats_tab, "Threats & Vulnerabilities")

        self.compliance_tab = QTextEdit()
        self.setup_text_edit(self.compliance_tab)
        self.tabs.addTab(self.compliance_tab, "Compliance")

        self.recommendations_tab = QTextEdit()
        self.setup_text_edit(self.recommendations_tab)
        self.tabs.addTab(self.recommendations_tab, "Recommendations")

        self.raw_tab = QTextEdit()
        self.setup_text_edit(self.raw_tab)
        self.tabs.addTab(self.raw_tab, "Raw Data")

        main_layout.addWidget(self.tabs)

        button_layout = QHBoxLayout()
        button_layout.setSpacing(12)

        self.export_pdf_button = QPushButton("Export PDF")
        self.export_pdf_button.setEnabled(False)
        self.export_pdf_button.clicked.connect(self.export_pdf)
        self.style_action_button(self.export_pdf_button, "#10b981", "#059669")
        button_layout.addWidget(self.export_pdf_button)

        self.export_json_button = QPushButton("Export JSON")
        self.export_json_button.setEnabled(False)
        self.export_json_button.clicked.connect(self.export_json)
        self.style_action_button(self.export_json_button, "#8b5cf6", "#7c3aed")
        button_layout.addWidget(self.export_json_button)

        self.clear_button = QPushButton("Clear Results")
        self.clear_button.setEnabled(False)
        self.clear_button.clicked.connect(self.clear_results)
        self.style_action_button(self.clear_button, "#ef4444", "#dc2626")
        button_layout.addWidget(self.clear_button)

        main_layout.addLayout(button_layout)

        self.statusBar().setStyleSheet("""
            background-color: #0f172a;
            color: #9ca3af;
            border-top: 2px solid #1f2937;
            font-size: 12px;
            padding: 5px;
        """)
        self.statusBar().showMessage("Ready")

    def setup_text_edit(self, text_edit):
        text_edit.setReadOnly(True)
        text_edit.setStyleSheet("""
            QTextEdit {
                background-color: #111827;
                color: #e5e7eb;
                border: 2px solid #1f2937;
                border-radius: 8px;
                padding: 15px;
                font-family: 'Segoe UI', 'Consolas', 'Monaco', monospace;
                font-size: 13px;
                line-height: 1.6;
            }
        """)

    def style_action_button(self, button, color, hover_color):
        button.setStyleSheet(f"""
            QPushButton {{
                background-color: {color};
                color: white;
                padding: 12px 28px;
                border: none;
                border-radius: 8px;
                font-weight: 600;
                font-size: 13px;
                font-family: 'Segoe UI', Arial;
            }}
            QPushButton:hover {{
                background-color: {hover_color};
            }}
            QPushButton:pressed {{
                padding: 13px 27px;
            }}
            QPushButton:disabled {{
                background-color: #374151;
                color: #6b7280;
            }}
        """)

    def start_scan(self):
        domain = self.domain_input.text().strip()

        if not domain:
            QMessageBox.warning(self, "Input Error", "Please enter a domain name")
            return

        self.scan_button.setEnabled(False)
        self.domain_input.setEnabled(False)
        self.export_pdf_button.setEnabled(False)
        self.export_json_button.setEnabled(False)
        self.clear_button.setEnabled(False)
        self.progress_bar.setValue(0)

        self.clear_all_tabs()

        self.scan_worker = ScanWorker(domain)
        self.scan_worker.progress_update.connect(self.update_progress)
        self.scan_worker.scan_complete.connect(self.scan_finished)
        self.scan_worker.scan_error.connect(self.scan_failed)
        self.scan_worker.start()

    def update_progress(self, value, message):
        self.progress_bar.setValue(value)
        self.status_label.setText(message)
        self.statusBar().showMessage(message)

    def scan_finished(self, results):
        self.current_results = results
        self.display_results(results)

        self.scan_button.setEnabled(True)
        self.domain_input.setEnabled(True)
        self.export_pdf_button.setEnabled(True)
        self.export_json_button.setEnabled(True)
        self.clear_button.setEnabled(True)

        self.statusBar().showMessage("Scan completed successfully")
        QMessageBox.information(self, "Success", "Domain scan completed successfully!")

    def scan_failed(self, error):
        self.scan_button.setEnabled(True)
        self.domain_input.setEnabled(True)
        self.statusBar().showMessage("Scan failed")
        QMessageBox.critical(self, "Error", f"Scan failed: {error}")

    def display_results(self, results):
        self.display_overview(results)
        self.display_security(results)
        self.display_threats(results)
        self.display_compliance(results)
        self.display_recommendations(results)
        self.display_raw_data(results)

    def display_overview(self, results):
        confidence = results['authenticity'].get('confidence', results['authenticity'].get('confidence_score', 0))
        html = f"""
        <style>
            body {{ font-family: 'Segoe UI', Arial, sans-serif; line-height: 1.8; }}
            h2 {{ color: #60a5fa; border-bottom: 2px solid #1f2937; padding-bottom: 10px; }}
            h3 {{ color: #a78bfa; margin-top: 25px; margin-bottom: 12px; }}
            strong {{ color: #d1d5db; }}
            ul {{ line-height: 2.0; }}
            li {{ margin-bottom: 8px; }}
            .stat-badge {{
                display: inline-block;
                padding: 4px 12px;
                border-radius: 6px;
                font-weight: 600;
                margin-left: 8px;
            }}
        </style>
        <h2>Domain Analysis Overview</h2>
        <p><strong>Domain:</strong> <span style='color: #60a5fa; font-size: 15px;'>{results['domain']}</span></p>
        <p><strong>Timestamp:</strong> {results['timestamp']}</p>
        <p><strong>Authenticity:</strong>
            <span class='stat-badge' style='background-color: {"#065f46" if results['authenticity']['is_genuine'] else "#7f1d1d"}; color: white;'>
                {'Genuine' if results['authenticity']['is_genuine'] else 'Suspicious'}
            </span>
        </p>
        <p><strong>Confidence:</strong> <span style='color: #60a5fa; font-size: 16px; font-weight: 600;'>{confidence}%</span></p>

        <h3>Quick Stats</h3>
        <ul>
            <li><strong>Risk Score:</strong>
                <span class='stat-badge' style='background-color: {"#7f1d1d" if results['threat_analysis'].get('risk_score', 0) > 70 else "#854d0e" if results['threat_analysis'].get('risk_score', 0) > 40 else "#065f46"}; color: white;'>
                    {results['threat_analysis'].get('risk_score', 'N/A')}/100
                </span>
            </li>
            <li><strong>Compliance Score:</strong>
                <span style='color: #34d399; font-weight: 600;'>{results['compliance_audit'].get('overall_score', 'N/A')}/100</span>
            </li>
            <li><strong>Total Vulnerabilities:</strong>
                <span style='color: #fbbf24; font-weight: 600;'>{results['vulnerability_analysis'].get('vulnerability_summary', {}).get('total_vulnerabilities', 0)}</span>
            </li>
        </ul>
        """

        if results.get('geolocation'):
            geo = results['geolocation']
            html += f"""
            <h3>Location Information</h3>
            <ul>
                <li><strong>Country:</strong> {geo.get('country', 'N/A')}</li>
                <li><strong>City:</strong> {geo.get('city', 'N/A')}</li>
                <li><strong>ISP:</strong> {geo.get('isp', 'N/A')}</li>
            </ul>
            """

        self.overview_tab.setHtml(html)

    def display_security(self, results):
        recon = results.get('reconnaissance', {})
        html = """
        <style>
            body { font-family: 'Segoe UI', Arial, sans-serif; line-height: 1.8; }
            h2 { color: #60a5fa; border-bottom: 2px solid #1f2937; padding-bottom: 10px; }
            h3 { color: #a78bfa; margin-top: 25px; margin-bottom: 12px; }
            strong { color: #d1d5db; }
            ul { line-height: 2.0; }
            li { margin-bottom: 8px; }
        </style>
        <h2>Security Analysis</h2>
        """

        ssl = recon.get('ssl', {})
        html += f"""
        <h3>SSL Certificate</h3>
        <ul>
            <li><strong>Valid:</strong> <span style='color: {"#34d399" if ssl.get("valid") else "#f87171"}; font-weight: 600;'>
                {'Yes' if ssl.get('valid') else 'No'}
            </span></li>
            <li><strong>Issuer:</strong> {ssl.get('issuer', 'N/A')}</li>
            <li><strong>Expires:</strong> {ssl.get('expires', 'N/A')}</li>
        </ul>
        """

        headers = recon.get('security_headers', {})
        html += "<h3>Security Headers</h3><ul>"
        for header, value in headers.items():
            color = "#34d399" if value != "Not set" else "#f87171"
            html += f"<li><strong>{header}:</strong> <span style='color: {color}; font-weight: 600;'>{value}</span></li>"
        html += "</ul>"

        owasp = results.get('owasp_analysis', {})
        if owasp:
            html += f"<h3>OWASP Analysis</h3>"
            html += f"<p style='color: #d1d5db;'>{owasp.get('summary', 'No OWASP analysis available')}</p>"

        self.security_tab.setHtml(html)

    def display_threats(self, results):
        threat = results.get('threat_analysis', {})
        risk_score = threat.get('risk_score', 0)
        html = f"""
        <style>
            body {{ font-family: 'Segoe UI', Arial, sans-serif; line-height: 1.8; }}
            h2 {{ color: #f87171; border-bottom: 2px solid #1f2937; padding-bottom: 10px; }}
            h3 {{ color: #fbbf24; margin-top: 25px; margin-bottom: 12px; }}
            strong {{ color: #d1d5db; }}
            ul {{ line-height: 2.0; }}
            li {{ margin-bottom: 8px; }}
        </style>
        <h2>Threat Analysis</h2>

        <h3>Risk Assessment</h3>
        <p><strong>Risk Score:</strong> <span style='color: {"#f87171" if risk_score > 70 else "#fbbf24" if risk_score > 40 else "#34d399"}; font-size: 18px; font-weight: 600;'>
            {risk_score}/100
        </span></p>
        """

        flags = threat.get('rule_based_flags', [])
        if flags:
            html += "<h3>Threat Indicators</h3><ul>"
            for flag in flags:
                html += f"<li style='color: #fca5a5;'>{flag}</li>"
            html += "</ul>"

        vuln = results.get('vulnerability_analysis', {})
        vuln_summary = vuln.get('vulnerability_summary', {})
        html += f"""
        <h3>Vulnerabilities</h3>
        <ul>
            <li><strong>Critical:</strong> <span style='color: #f87171; font-weight: 600;'>{vuln_summary.get('critical', 0)}</span></li>
            <li><strong>High:</strong> <span style='color: #fb923c; font-weight: 600;'>{vuln_summary.get('high', 0)}</span></li>
            <li><strong>Medium:</strong> <span style='color: #fbbf24; font-weight: 600;'>{vuln_summary.get('medium', 0)}</span></li>
            <li><strong>Low:</strong> <span style='color: #34d399; font-weight: 600;'>{vuln_summary.get('low', 0)}</span></li>
        </ul>
        """

        self.threats_tab.setHtml(html)

    def display_compliance(self, results):
        compliance = results.get('compliance_audit', {})
        score = compliance.get('overall_score', 0)
        html = f"""
        <style>
            body {{ font-family: 'Segoe UI', Arial, sans-serif; line-height: 1.8; }}
            h2 {{ color: #34d399; border-bottom: 2px solid #1f2937; padding-bottom: 10px; }}
            h3 {{ color: #5eead4; margin-top: 25px; margin-bottom: 12px; }}
            strong {{ color: #d1d5db; }}
            ul {{ line-height: 2.0; }}
            li {{ margin-bottom: 8px; color: #e5e7eb; }}
        </style>
        <h2>Compliance Audit</h2>

        <h3>Overall Score</h3>
        <p><strong>Score:</strong> <span style='color: {"#34d399" if score > 70 else "#fbbf24" if score > 40 else "#f87171"}; font-size: 18px; font-weight: 600;'>
            {score}/100
        </span></p>
        """

        gdpr = compliance.get('gdpr_compliance', {})
        if gdpr:
            html += "<h3>GDPR Compliance</h3><ul>"
            for key, value in gdpr.items():
                html += f"<li><strong>{key}:</strong> {value}</li>"
            html += "</ul>"

        recommendations = compliance.get('recommendations', [])
        if recommendations:
            html += "<h3>Compliance Recommendations</h3><ul>"
            for rec in recommendations:
                html += f"<li>{rec}</li>"
            html += "</ul>"

        self.compliance_tab.setHtml(html)

    def display_recommendations(self, results):
        remediation = results.get('remediation_playbook', {})
        html = """
        <style>
            body { font-family: 'Segoe UI', Arial, sans-serif; line-height: 1.8; }
            h2 { color: #a78bfa; border-bottom: 2px solid #1f2937; padding-bottom: 10px; }
            h3 { color: #c4b5fd; margin-top: 25px; margin-bottom: 12px; }
            strong { color: #d1d5db; }
            ul, ol { line-height: 2.0; }
            li { margin-bottom: 12px; color: #e5e7eb; }
        </style>
        <h2>Security Recommendations</h2>
        """

        summary = remediation.get('executive_summary', {})
        recommendations = summary.get('key_recommendations', [])

        if recommendations:
            html += "<h3>Priority Actions</h3><ol>"
            for rec in recommendations:
                html += f"<li>{rec}</li>"
            html += "</ol>"

        threat_recs = results.get('threat_analysis', {}).get('recommendations', [])
        if threat_recs:
            html += "<h3>Threat Mitigation</h3><ul>"
            for rec in threat_recs:
                html += f"<li>{rec}</li>"
            html += "</ul>"

        self.recommendations_tab.setHtml(html)

    def display_raw_data(self, results):
        json_str = json.dumps(results, indent=2, default=str)
        self.raw_tab.setText(json_str)

    def clear_all_tabs(self):
        self.overview_tab.clear()
        self.security_tab.clear()
        self.threats_tab.clear()
        self.compliance_tab.clear()
        self.recommendations_tab.clear()
        self.raw_tab.clear()

    def export_pdf(self):
        if not self.current_results:
            return

        filename, _ = QFileDialog.getSaveFileName(
            self, "Save PDF Report",
            f"{self.current_results['domain']}_report.pdf",
            "PDF Files (*.pdf)"
        )

        if filename:
            try:
                pdf_path = generate_pdf_report(self.current_results)

                import shutil
                shutil.copy(pdf_path, filename)

                QMessageBox.information(self, "Success", f"Report exported to {filename}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to export PDF: {str(e)}")

    def export_json(self):
        if not self.current_results:
            return

        filename, _ = QFileDialog.getSaveFileName(
            self, "Save JSON Report",
            f"{self.current_results['domain']}_report.json",
            "JSON Files (*.json)"
        )

        if filename:
            try:
                with open(filename, 'w') as f:
                    json.dump(self.current_results, f, indent=2, default=str)

                QMessageBox.information(self, "Success", f"Report exported to {filename}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to export JSON: {str(e)}")

    def clear_results(self):
        reply = QMessageBox.question(
            self, "Confirm Clear",
            "Are you sure you want to clear the results?",
            QMessageBox.Yes | QMessageBox.No
        )

        if reply == QMessageBox.Yes:
            self.current_results = None
            self.clear_all_tabs()
            self.progress_bar.setValue(0)
            self.status_label.setText("Ready to scan")
            self.export_pdf_button.setEnabled(False)
            self.export_json_button.setEnabled(False)
            self.clear_button.setEnabled(False)
            self.domain_input.clear()


def main():
    app = QApplication(sys.argv)
    app.setStyle('Fusion')

    window = DomainReconApp()
    window.show()

    sys.exit(app.exec_())


if __name__ == '__main__':
    main()
