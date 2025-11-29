"""
MOBSCAN Report Generators
Módulo para geração de relatórios em múltiplos formatos
"""

from .report_generator import (
    ReportGenerator,
    ReportMetadata,
    generate_reports,
    load_scan_results
)
from .html_generator import HTMLReportGenerator
from .markdown_generator import MarkdownReportGenerator
from .pdf_generator import PDFReportGenerator, generate_pdf_report

__all__ = [
    'ReportGenerator',
    'ReportMetadata',
    'HTMLReportGenerator',
    'MarkdownReportGenerator',
    'PDFReportGenerator',
    'generate_reports',
    'load_scan_results',
    'generate_pdf_report'
]

__version__ = '1.1.0'
