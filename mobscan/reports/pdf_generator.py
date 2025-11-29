#!/usr/bin/env python3
"""
MOBSCAN PDF Report Generator
Gera relatórios PDF usando WeasyPrint
"""

from datetime import datetime
from pathlib import Path
from typing import Dict, Any
import logging

logger = logging.getLogger(__name__)


class PDFReportGenerator:
    """Gerador de relatórios PDF"""

    def __init__(self, scan_results: Dict[str, Any], output_dir: str = "./reports"):
        self.results = scan_results
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(self) -> str:
        """
        Gera relatório PDF usando WeasyPrint

        Returns:
            Caminho do arquivo PDF gerado
        """
        try:
            from weasyprint import HTML, CSS
        except ImportError:
            logger.warning(
                "WeasyPrint not available. Install with: pip install weasyprint\n"
                "Falling back to HTML generation with print instructions."
            )
            return self._generate_html_fallback()

        # Gera nome do arquivo
        target = self.results.get('target', 'unknown')
        target_name = Path(target).stem or 'unknown'
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"mobscan_report_{target_name}_{timestamp}.pdf"
        filepath = self.output_dir / filename

        # Gera HTML otimizado para PDF
        html_content = self._generate_pdf_html()

        # Gera PDF
        try:
            HTML(string=html_content).write_pdf(
                str(filepath),
                stylesheets=[CSS(string=self._get_pdf_css())]
            )
            logger.info(f"PDF report generated: {filepath}")
            return str(filepath)
        except Exception as e:
            logger.error(f"Error generating PDF: {e}")
            return self._generate_html_fallback()

    def _generate_html_fallback(self) -> str:
        """Gera HTML com instruções para impressão"""
        from .html_generator import HTMLReportGenerator

        logger.info("Generating HTML report instead of PDF")
        generator = HTMLReportGenerator(self.results, str(self.output_dir))
        html_path = generator.generate()

        print("\n" + "="*60)
        print("PDF generation not available.")
        print(f"HTML report generated: {html_path}")
        print("\nTo create PDF:")
        print("1. Open the HTML file in a browser")
        print("2. Use browser's Print function (Ctrl+P / Cmd+P)")
        print("3. Select 'Save as PDF'")
        print("="*60 + "\n")

        return html_path

    def _generate_pdf_html(self) -> str:
        """Gera HTML otimizado para PDF"""
        from .html_generator import HTMLReportGenerator

        # Reutiliza o gerador HTML mas com template otimizado para PDF
        generator = HTMLReportGenerator(self.results, str(self.output_dir))

        # Gera HTML básico
        html_parts = [
            '<!DOCTYPE html>',
            '<html>',
            '<head>',
            '<meta charset="UTF-8">',
            '<title>MOBSCAN Security Report</title>',
            '</head>',
            '<body>',
            generator._generate_header(),
            generator._generate_summary(),
            generator._generate_findings_table(),
            generator._generate_detailed_findings(),
            generator._generate_module_results(),
            generator._generate_footer(),
            '</body>',
            '</html>'
        ]

        return '\n'.join(html_parts)

    def _get_pdf_css(self) -> str:
        """CSS otimizado para geração de PDF"""
        return """
        @page {
            size: A4;
            margin: 2cm;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Helvetica', 'Arial', sans-serif;
            font-size: 11pt;
            line-height: 1.6;
            color: #333;
        }

        .header {
            background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%);
            color: white;
            padding: 30px;
            text-align: center;
            margin-bottom: 20px;
        }

        .header h1 {
            font-size: 24pt;
            margin-bottom: 10px;
        }

        .header .subtitle {
            font-size: 14pt;
        }

        .header .meta {
            margin-top: 15px;
            display: flex;
            justify-content: center;
            gap: 20px;
            flex-wrap: wrap;
        }

        .meta-item {
            background: rgba(255, 255, 255, 0.2);
            padding: 8px 15px;
            border-radius: 5px;
        }

        .section {
            margin: 25px 0;
            page-break-inside: avoid;
        }

        .section-title {
            font-size: 18pt;
            margin-bottom: 15px;
            padding-bottom: 8px;
            border-bottom: 2px solid #6366f1;
            color: #6366f1;
            page-break-after: avoid;
        }

        .summary-grid {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 15px;
            margin-bottom: 20px;
        }

        .stat-card {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            border-left: 4px solid #6c757d;
            text-align: center;
        }

        .stat-card.critical { border-left-color: #dc3545; }
        .stat-card.high { border-left-color: #fd7e14; }
        .stat-card.medium { border-left-color: #ffc107; }
        .stat-card.low { border-left-color: #0dcaf0; }

        .stat-value {
            font-size: 24pt;
            font-weight: bold;
            color: #333;
        }

        .stat-label {
            color: #6c757d;
            font-size: 9pt;
            text-transform: uppercase;
            margin-top: 5px;
        }

        .findings-table {
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }

        .findings-table th {
            background: #6366f1;
            color: white;
            padding: 10px;
            text-align: left;
            font-size: 9pt;
            text-transform: uppercase;
        }

        .findings-table td {
            padding: 10px;
            border-bottom: 1px solid #dee2e6;
            font-size: 10pt;
        }

        .findings-table tr:nth-child(even) {
            background: #f8f9fa;
        }

        .finding-card {
            background: #f8f9fa;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
            border-left: 5px solid #6c757d;
            page-break-inside: avoid;
        }

        .finding-card.critical { border-left-color: #dc3545; }
        .finding-card.high { border-left-color: #fd7e14; }
        .finding-card.medium { border-left-color: #ffc107; }
        .finding-card.low { border-left-color: #0dcaf0; }

        .finding-header {
            margin-bottom: 15px;
        }

        .finding-title {
            font-size: 14pt;
            font-weight: bold;
            color: #333;
            margin-bottom: 8px;
        }

        .finding-meta {
            font-size: 9pt;
            color: #6c757d;
            margin-bottom: 10px;
        }

        .finding-meta span {
            margin-right: 15px;
        }

        .severity-badge {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 8pt;
            font-weight: bold;
            text-transform: uppercase;
            float: right;
        }

        .severity-critical {
            background: #dc3545;
            color: white;
        }

        .severity-high {
            background: #fd7e14;
            color: white;
        }

        .severity-medium {
            background: #ffc107;
            color: #000;
        }

        .severity-low {
            background: #0dcaf0;
            color: #000;
        }

        .severity-info {
            background: #6c757d;
            color: white;
        }

        .finding-description {
            margin: 10px 0;
            font-size: 10pt;
            line-height: 1.6;
        }

        .finding-recommendation {
            background: #d1e7dd;
            border-left: 3px solid #198754;
            padding: 12px;
            margin-top: 12px;
            border-radius: 5px;
            font-size: 10pt;
        }

        .code-block {
            background: #f1f3f5;
            border: 1px solid #dee2e6;
            border-radius: 5px;
            padding: 12px;
            margin: 10px 0;
            font-family: 'Courier New', monospace;
            font-size: 9pt;
            overflow-x: auto;
            page-break-inside: avoid;
        }

        .footer {
            background: #f8f9fa;
            padding: 20px;
            text-align: center;
            margin-top: 30px;
            border-top: 2px solid #dee2e6;
            font-size: 9pt;
            color: #6c757d;
        }

        .footer-links {
            margin-top: 10px;
        }

        .footer-links a {
            color: #6366f1;
            text-decoration: none;
            margin: 0 10px;
        }

        /* Page breaks */
        h1, h2, h3 {
            page-break-after: avoid;
        }

        .finding-card {
            page-break-inside: avoid;
        }
        """


def generate_pdf_report(scan_results: Dict[str, Any], output_dir: str = "./reports") -> str:
    """
    Helper function para gerar relatório PDF

    Args:
        scan_results: Resultados do scan
        output_dir: Diretório de saída

    Returns:
        Caminho do arquivo PDF gerado
    """
    generator = PDFReportGenerator(scan_results, output_dir)
    return generator.generate()
