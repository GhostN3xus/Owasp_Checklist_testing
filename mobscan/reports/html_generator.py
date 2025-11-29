#!/usr/bin/env python3
"""
MOBSCAN HTML Report Generator
Gera relatórios HTML com template profissional e estilização
"""

from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List
import html


class HTMLReportGenerator:
    """Gerador de relatórios HTML"""

    def __init__(self, scan_results: Dict[str, Any], output_dir: str = "./reports"):
        self.results = scan_results
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(self) -> str:
        """
        Gera relatório HTML completo

        Returns:
            Caminho do arquivo HTML gerado
        """
        # Gera nome do arquivo
        target = self.results.get('target', 'unknown')
        target_name = Path(target).stem or 'unknown'
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"mobscan_report_{target_name}_{timestamp}.html"
        filepath = self.output_dir / filename

        # Gera conteúdo HTML
        html_content = self._generate_html()

        # Salva arquivo
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)

        return str(filepath)

    def _generate_html(self) -> str:
        """Gera HTML completo"""
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MOBSCAN Security Report - {html.escape(self.results.get('target', 'Unknown'))}</title>
    {self._generate_styles()}
</head>
<body>
    <div class="container">
        {self._generate_header()}
        {self._generate_summary()}
        {self._generate_findings_table()}
        {self._generate_detailed_findings()}
        {self._generate_module_results()}
        {self._generate_footer()}
    </div>
    {self._generate_scripts()}
</body>
</html>"""

    def _generate_styles(self) -> str:
        """Gera CSS do relatório"""
        return """<style>
        :root {
            --critical: #dc3545;
            --high: #fd7e14;
            --medium: #ffc107;
            --low: #0dcaf0;
            --info: #6c757d;
            --success: #198754;
            --bg-dark: #1a1d23;
            --bg-card: #2d3139;
            --text-primary: #e9ecef;
            --text-secondary: #adb5bd;
            --border: #495057;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1a1d23 0%, #2d3139 100%);
            color: var(--text-primary);
            line-height: 1.6;
            padding: 20px;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: var(--bg-card);
            border-radius: 12px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
            overflow: hidden;
        }

        .header {
            background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%);
            padding: 40px;
            text-align: center;
            border-bottom: 4px solid #4f46e5;
        }

        .header h1 {
            font-size: 2.5rem;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0, 0, 0, 0.3);
        }

        .header .subtitle {
            font-size: 1.2rem;
            opacity: 0.9;
        }

        .header .meta {
            margin-top: 20px;
            display: flex;
            justify-content: center;
            gap: 30px;
            flex-wrap: wrap;
        }

        .meta-item {
            background: rgba(255, 255, 255, 0.1);
            padding: 10px 20px;
            border-radius: 8px;
            backdrop-filter: blur(10px);
        }

        .meta-item strong {
            display: block;
            font-size: 0.9rem;
            opacity: 0.8;
        }

        .section {
            padding: 40px;
        }

        .section-title {
            font-size: 1.8rem;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid var(--border);
            color: #8b5cf6;
        }

        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }

        .stat-card {
            background: var(--bg-dark);
            padding: 25px;
            border-radius: 10px;
            border-left: 4px solid var(--info);
            transition: transform 0.2s, box-shadow 0.2s;
        }

        .stat-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 8px 16px rgba(0, 0, 0, 0.3);
        }

        .stat-card.critical { border-left-color: var(--critical); }
        .stat-card.high { border-left-color: var(--high); }
        .stat-card.medium { border-left-color: var(--medium); }
        .stat-card.low { border-left-color: var(--low); }

        .stat-value {
            font-size: 2.5rem;
            font-weight: bold;
            margin-bottom: 5px;
        }

        .stat-label {
            color: var(--text-secondary);
            text-transform: uppercase;
            font-size: 0.85rem;
            letter-spacing: 1px;
        }

        .findings-table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            background: var(--bg-dark);
            border-radius: 8px;
            overflow: hidden;
        }

        .findings-table th {
            background: linear-gradient(135deg, #4f46e5 0%, #7c3aed 100%);
            padding: 15px;
            text-align: left;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.85rem;
            letter-spacing: 1px;
        }

        .findings-table td {
            padding: 15px;
            border-bottom: 1px solid var(--border);
        }

        .findings-table tr:hover {
            background: rgba(139, 92, 246, 0.1);
        }

        .severity-badge {
            display: inline-block;
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: bold;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .severity-critical { background: var(--critical); color: white; }
        .severity-high { background: var(--high); color: white; }
        .severity-medium { background: var(--medium); color: #000; }
        .severity-low { background: var(--low); color: #000; }
        .severity-info { background: var(--info); color: white; }

        .finding-card {
            background: var(--bg-dark);
            border-radius: 10px;
            padding: 30px;
            margin-bottom: 25px;
            border-left: 5px solid var(--info);
            transition: all 0.3s;
        }

        .finding-card:hover {
            box-shadow: 0 8px 20px rgba(0, 0, 0, 0.3);
            transform: translateX(5px);
        }

        .finding-card.critical { border-left-color: var(--critical); }
        .finding-card.high { border-left-color: var(--high); }
        .finding-card.medium { border-left-color: var(--medium); }
        .finding-card.low { border-left-color: var(--low); }

        .finding-header {
            display: flex;
            justify-content: space-between;
            align-items: start;
            margin-bottom: 20px;
        }

        .finding-title {
            font-size: 1.4rem;
            margin-bottom: 10px;
            color: #a78bfa;
        }

        .finding-meta {
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
            margin-bottom: 15px;
            font-size: 0.9rem;
            color: var(--text-secondary);
        }

        .finding-description {
            margin: 15px 0;
            line-height: 1.8;
        }

        .finding-recommendation {
            background: rgba(25, 135, 84, 0.1);
            border-left: 3px solid var(--success);
            padding: 15px;
            margin-top: 15px;
            border-radius: 5px;
        }

        .code-block {
            background: #1a1d23;
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 15px;
            margin: 15px 0;
            overflow-x: auto;
            font-family: 'Courier New', monospace;
            font-size: 0.9rem;
        }

        .footer {
            background: var(--bg-dark);
            padding: 30px 40px;
            text-align: center;
            color: var(--text-secondary);
            border-top: 1px solid var(--border);
        }

        .footer-links {
            margin-top: 15px;
        }

        .footer-links a {
            color: #8b5cf6;
            text-decoration: none;
            margin: 0 10px;
        }

        .footer-links a:hover {
            text-decoration: underline;
        }

        .chart-container {
            background: var(--bg-dark);
            padding: 20px;
            border-radius: 10px;
            margin: 20px 0;
        }

        @media print {
            body {
                background: white;
                color: black;
            }
            .container {
                box-shadow: none;
            }
            .finding-card {
                page-break-inside: avoid;
            }
        }

        @media (max-width: 768px) {
            .header h1 {
                font-size: 1.8rem;
            }
            .summary-grid {
                grid-template-columns: 1fr;
            }
            .meta {
                flex-direction: column;
                gap: 10px !important;
            }
        }
    </style>"""

    def _generate_header(self) -> str:
        """Gera cabeçalho do relatório"""
        target = html.escape(self.results.get('target', 'Unknown'))
        generated_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        modules = ', '.join(self.results.get('modules_used', []))

        return f"""<div class="header">
        <h1>🔒 MOBSCAN Security Assessment Report</h1>
        <div class="subtitle">Mobile Application Security Analysis</div>
        <div class="meta">
            <div class="meta-item">
                <strong>Target</strong>
                <div>{target}</div>
            </div>
            <div class="meta-item">
                <strong>Generated</strong>
                <div>{generated_at}</div>
            </div>
            <div class="meta-item">
                <strong>Version</strong>
                <div>MOBSCAN v1.1.0</div>
            </div>
            <div class="meta-item">
                <strong>Modules</strong>
                <div>{modules or 'N/A'}</div>
            </div>
        </div>
    </div>"""

    def _generate_summary(self) -> str:
        """Gera seção de resumo"""
        findings = self.results.get('findings', [])
        severity_counts = self._count_by_severity(findings)

        return f"""<div class="section">
        <h2 class="section-title">📊 Executive Summary</h2>
        <div class="summary-grid">
            <div class="stat-card">
                <div class="stat-value">{len(findings)}</div>
                <div class="stat-label">Total Findings</div>
            </div>
            <div class="stat-card critical">
                <div class="stat-value">{severity_counts['critical']}</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat-card high">
                <div class="stat-value">{severity_counts['high']}</div>
                <div class="stat-label">High</div>
            </div>
            <div class="stat-card medium">
                <div class="stat-value">{severity_counts['medium']}</div>
                <div class="stat-label">Medium</div>
            </div>
            <div class="stat-card low">
                <div class="stat-value">{severity_counts['low']}</div>
                <div class="stat-label">Low</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{severity_counts['info']}</div>
                <div class="stat-label">Info</div>
            </div>
        </div>
    </div>"""

    def _generate_findings_table(self) -> str:
        """Gera tabela resumida de findings"""
        findings = self.results.get('findings', [])

        if not findings:
            return '<div class="section"><p>No security findings identified.</p></div>'

        # Agrupa por categoria
        by_category = {}
        for finding in findings:
            category = finding.get('category', 'Uncategorized')
            if category not in by_category:
                by_category[category] = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}

            severity = finding.get('severity', 'info').lower()
            if severity in by_category[category]:
                by_category[category][severity] += 1

        rows = ""
        for category, counts in sorted(by_category.items()):
            total = sum(counts.values())
            rows += f"""<tr>
                <td>{html.escape(category)}</td>
                <td>{counts['critical']}</td>
                <td>{counts['high']}</td>
                <td>{counts['medium']}</td>
                <td>{counts['low']}</td>
                <td>{counts['info']}</td>
                <td><strong>{total}</strong></td>
            </tr>"""

        return f"""<div class="section">
        <h2 class="section-title">🎯 Findings by Category</h2>
        <table class="findings-table">
            <thead>
                <tr>
                    <th>Category</th>
                    <th>Critical</th>
                    <th>High</th>
                    <th>Medium</th>
                    <th>Low</th>
                    <th>Info</th>
                    <th>Total</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </div>"""

    def _generate_detailed_findings(self) -> str:
        """Gera seção de findings detalhados"""
        findings = self.results.get('findings', [])

        if not findings:
            return ""

        # Ordena por severidade
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        sorted_findings = sorted(
            findings,
            key=lambda x: severity_order.get(x.get('severity', 'info').lower(), 5)
        )

        cards = ""
        for idx, finding in enumerate(sorted_findings, 1):
            cards += self._generate_finding_card(idx, finding)

        return f"""<div class="section">
        <h2 class="section-title">🔍 Detailed Findings</h2>
        {cards}
    </div>"""

    def _generate_finding_card(self, number: int, finding: Dict[str, Any]) -> str:
        """Gera card de finding individual"""
        title = html.escape(finding.get('title', 'Unknown Issue'))
        severity = finding.get('severity', 'info').lower()
        category = html.escape(finding.get('category', 'Uncategorized'))
        description = html.escape(finding.get('description', 'No description'))
        location = html.escape(finding.get('location', 'N/A'))
        recommendation = html.escape(finding.get('recommendation', 'Review and remediate'))
        cwe = finding.get('cwe', '')
        owasp = finding.get('owasp', '')

        meta_items = f"<span>📂 {category}</span>"
        if location != 'N/A':
            meta_items += f"<span>📍 {location}</span>"
        if cwe:
            meta_items += f"<span>🔗 CWE: {html.escape(str(cwe))}</span>"
        if owasp:
            meta_items += f"<span>🛡️ OWASP: {html.escape(str(owasp))}</span>"

        evidence_html = ""
        evidence = finding.get('evidence', {})
        if evidence:
            evidence_text = self._format_evidence(evidence)
            evidence_html = f"""<div class="code-block">{html.escape(evidence_text)}</div>"""

        return f"""<div class="finding-card {severity}">
        <div class="finding-header">
            <div>
                <div class="finding-title">{number}. {title}</div>
                <div class="finding-meta">{meta_items}</div>
            </div>
            <span class="severity-badge severity-{severity}">{severity.upper()}</span>
        </div>
        <div class="finding-description">
            <strong>Description:</strong><br>
            {description}
        </div>
        {evidence_html}
        <div class="finding-recommendation">
            <strong>💡 Recommendation:</strong><br>
            {recommendation}
        </div>
    </div>"""

    def _generate_module_results(self) -> str:
        """Gera resultados dos módulos"""
        modules_results = self.results.get('modules_results', {})

        if not modules_results:
            return ""

        module_cards = ""
        for module_name, module_data in modules_results.items():
            status = module_data.get('status', 'Unknown')
            duration = module_data.get('duration', 0)
            findings_count = len(module_data.get('findings', []))

            module_cards += f"""<div class="stat-card">
                <h3 style="margin-bottom: 15px;">{module_name.upper()}</h3>
                <div style="color: var(--text-secondary);">
                    <div>Status: <strong>{status}</strong></div>
                    <div>Duration: <strong>{duration:.2f}s</strong></div>
                    <div>Findings: <strong>{findings_count}</strong></div>
                </div>
            </div>"""

        return f"""<div class="section">
        <h2 class="section-title">🔧 Module Results</h2>
        <div class="summary-grid">
            {module_cards}
        </div>
    </div>"""

    def _generate_footer(self) -> str:
        """Gera rodapé"""
        return """<div class="footer">
        <div>
            <strong>MOBSCAN v1.1.0</strong> - Mobile Security Testing Framework
        </div>
        <div class="footer-links">
            <a href="https://mas.owasp.org/MASTG/" target="_blank">OWASP MASTG</a>
            <a href="https://mas.owasp.org/MASVS/" target="_blank">OWASP MASVS</a>
            <a href="https://github.com/GhostN3xus/Owasp_Checklist_testing" target="_blank">GitHub</a>
        </div>
        <div style="margin-top: 15px; font-size: 0.9rem;">
            Generated on """ + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + """
        </div>
    </div>"""

    def _generate_scripts(self) -> str:
        """Gera scripts JavaScript"""
        return """<script>
        // Print functionality
        document.addEventListener('DOMContentLoaded', function() {
            console.log('MOBSCAN Report loaded successfully');
        });

        // Add print button functionality
        function printReport() {
            window.print();
        }
    </script>"""

    # Helper methods

    def _count_by_severity(self, findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """Conta findings por severidade"""
        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for finding in findings:
            severity = finding.get('severity', 'info').lower()
            if severity in counts:
                counts[severity] += 1
        return counts

    def _format_evidence(self, evidence: Dict[str, Any]) -> str:
        """Formata evidências"""
        lines = []
        for key, value in evidence.items():
            if isinstance(value, (list, dict)):
                import json
                lines.append(f"{key}:")
                lines.append(json.dumps(value, indent=2))
            else:
                lines.append(f"{key}: {value}")
        return '\n'.join(lines)
