#!/usr/bin/env python3
"""
MOBSCAN Report Generator
Gera relatórios em múltiplos formatos: JSON, HTML, Markdown, PDF
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict


@dataclass
class ReportMetadata:
    """Metadados do relatório"""
    tool_name: str = "MOBSCAN"
    tool_version: str = "1.1.0"
    generated_at: str = ""
    target: str = ""
    modules_used: List[str] = None
    scan_duration: float = 0.0

    def __post_init__(self):
        if not self.generated_at:
            self.generated_at = datetime.now().isoformat()
        if self.modules_used is None:
            self.modules_used = []


class ReportGenerator:
    """Classe base para geração de relatórios"""

    def __init__(self, scan_results: Dict[str, Any], output_dir: str = "./reports"):
        """
        Inicializa o gerador de relatórios

        Args:
            scan_results: Resultados do scan contendo findings, metadata, etc
            output_dir: Diretório de saída para os relatórios
        """
        self.results = scan_results
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Extrai metadata
        self.metadata = ReportMetadata(
            target=scan_results.get('target', 'unknown'),
            modules_used=scan_results.get('modules_used', []),
            scan_duration=scan_results.get('scan_duration', 0.0)
        )

    def _count_findings_by_severity(self) -> Dict[str, int]:
        """Conta findings por severidade"""
        counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }

        findings = self.results.get('findings', [])
        for finding in findings:
            severity = finding.get('severity', 'info').lower()
            if severity in counts:
                counts[severity] += 1

        return counts

    def _get_summary_stats(self) -> Dict[str, Any]:
        """Gera estatísticas resumidas"""
        findings = self.results.get('findings', [])
        severity_counts = self._count_findings_by_severity()

        return {
            'total_findings': len(findings),
            'severity_breakdown': severity_counts,
            'critical_count': severity_counts['critical'],
            'high_count': severity_counts['high'],
            'medium_count': severity_counts['medium'],
            'low_count': severity_counts['low'],
            'info_count': severity_counts['info'],
            'modules_executed': len(self.metadata.modules_used),
            'scan_duration_seconds': self.metadata.scan_duration
        }

    def generate_all(self, formats: List[str] = None) -> Dict[str, str]:
        """
        Gera relatórios em múltiplos formatos

        Args:
            formats: Lista de formatos desejados ['json', 'html', 'markdown', 'pdf']
                    Se None, gera todos os formatos

        Returns:
            Dicionário com formato -> caminho do arquivo gerado
        """
        if formats is None:
            formats = ['json', 'html', 'markdown']

        generated_files = {}

        if 'json' in formats:
            generated_files['json'] = self.generate_json()

        if 'html' in formats:
            generated_files['html'] = self.generate_html()

        if 'markdown' in formats:
            generated_files['markdown'] = self.generate_markdown()

        if 'pdf' in formats:
            generated_files['pdf'] = self.generate_pdf()

        return generated_files

    def generate_json(self) -> str:
        """
        Gera relatório JSON completo

        Returns:
            Caminho do arquivo JSON gerado
        """
        # Prepara dados do relatório
        report_data = {
            'metadata': asdict(self.metadata),
            'summary': self._get_summary_stats(),
            'findings': self.results.get('findings', []),
            'scan_details': {
                'target_info': self.results.get('target_info', {}),
                'configuration': self.results.get('configuration', {}),
                'modules_results': self.results.get('modules_results', {})
            }
        }

        # Gera nome do arquivo
        target_name = Path(self.metadata.target).stem or 'unknown'
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"mobscan_report_{target_name}_{timestamp}.json"
        filepath = self.output_dir / filename

        # Salva JSON com formatação
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False, default=str)

        return str(filepath)

    def generate_html(self) -> str:
        """
        Gera relatório HTML com template profissional

        Returns:
            Caminho do arquivo HTML gerado
        """
        from .html_generator import HTMLReportGenerator

        generator = HTMLReportGenerator(self.results, str(self.output_dir))
        return generator.generate()

    def generate_markdown(self) -> str:
        """
        Gera relatório Markdown

        Returns:
            Caminho do arquivo Markdown gerado
        """
        from .markdown_generator import MarkdownReportGenerator

        generator = MarkdownReportGenerator(self.results, str(self.output_dir))
        return generator.generate()

    def generate_pdf(self) -> str:
        """
        Gera relatório PDF usando WeasyPrint

        Returns:
            Caminho do arquivo PDF gerado
        """
        from .pdf_generator import PDFReportGenerator

        generator = PDFReportGenerator(self.results, str(self.output_dir))
        return generator.generate()


def load_scan_results(input_file: str) -> Dict[str, Any]:
    """
    Carrega resultados de scan de um arquivo JSON

    Args:
        input_file: Caminho para o arquivo JSON com resultados

    Returns:
        Dicionário com os resultados do scan
    """
    with open(input_file, 'r', encoding='utf-8') as f:
        return json.load(f)


def generate_reports(
    input_file: str,
    output_dir: str = "./reports",
    formats: List[str] = None
) -> Dict[str, str]:
    """
    Função helper para gerar relatórios a partir de arquivo de resultados

    Args:
        input_file: Caminho para o arquivo JSON com resultados do scan
        output_dir: Diretório de saída
        formats: Lista de formatos desejados

    Returns:
        Dicionário com formato -> caminho do arquivo gerado
    """
    results = load_scan_results(input_file)
    generator = ReportGenerator(results, output_dir)
    return generator.generate_all(formats)


# Para compatibilidade com imports antigos
__all__ = [
    'ReportGenerator',
    'ReportMetadata',
    'generate_reports',
    'load_scan_results'
]
