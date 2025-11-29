#!/usr/bin/env python3
"""
MOBSCAN Markdown Report Generator
Gera relatórios em formato Markdown
"""

from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List


class MarkdownReportGenerator:
    """Gerador de relatórios Markdown"""

    def __init__(self, scan_results: Dict[str, Any], output_dir: str = "./reports"):
        self.results = scan_results
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(self) -> str:
        """
        Gera relatório Markdown completo

        Returns:
            Caminho do arquivo Markdown gerado
        """
        # Gera nome do arquivo
        target = self.results.get('target', 'unknown')
        target_name = Path(target).stem or 'unknown'
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"mobscan_report_{target_name}_{timestamp}.md"
        filepath = self.output_dir / filename

        # Gera conteúdo
        content = self._generate_content()

        # Salva arquivo
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)

        return str(filepath)

    def _generate_content(self) -> str:
        """Gera conteúdo completo do relatório"""
        sections = [
            self._header(),
            self._executive_summary(),
            self._findings_summary(),
            self._detailed_findings(),
            self._module_details(),
            self._recommendations(),
            self._appendix()
        ]

        return '\n\n'.join(sections)

    def _header(self) -> str:
        """Gera cabeçalho do relatório"""
        target = self.results.get('target', 'Unknown')
        generated_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        return f"""# 🔒 MOBSCAN Security Assessment Report

**Target Application:** `{target}`
**Scan Date:** {generated_at}
**MOBSCAN Version:** 1.1.0
**Report Type:** Comprehensive Security Analysis

---"""

    def _executive_summary(self) -> str:
        """Gera resumo executivo"""
        findings = self.results.get('findings', [])
        modules_used = self.results.get('modules_used', [])
        duration = self.results.get('scan_duration', 0)

        # Conta por severidade
        severity_counts = self._count_by_severity(findings)

        risk_level = self._calculate_risk_level(severity_counts)

        return f"""## 📊 Executive Summary

This report presents the results of a comprehensive mobile security assessment conducted using MOBSCAN v1.1.0.

### Key Metrics

| Metric | Value |
|--------|-------|
| **Total Findings** | {len(findings)} |
| **Critical Issues** | {severity_counts['critical']} |
| **High Severity** | {severity_counts['high']} |
| **Medium Severity** | {severity_counts['medium']} |
| **Low Severity** | {severity_counts['low']} |
| **Informational** | {severity_counts['info']} |
| **Modules Executed** | {len(modules_used)} |
| **Scan Duration** | {duration:.2f}s |
| **Overall Risk Level** | **{risk_level}** |

### Modules Executed

{self._format_modules_list(modules_used)}

---"""

    def _findings_summary(self) -> str:
        """Gera resumo de findings"""
        findings = self.results.get('findings', [])

        if not findings:
            return """## 🎯 Findings Summary

No security findings were identified during this assessment."""

        # Agrupa por categoria
        by_category = self._group_by_category(findings)

        # Gera tabela
        table = "## 🎯 Findings Summary\n\n"
        table += "| Category | Critical | High | Medium | Low | Info | Total |\n"
        table += "|----------|----------|------|--------|-----|------|-------|\n"

        for category, items in sorted(by_category.items()):
            counts = self._count_by_severity(items)
            total = len(items)
            table += f"| {category} | {counts['critical']} | {counts['high']} | {counts['medium']} | {counts['low']} | {counts['info']} | {total} |\n"

        return table + "\n---"

    def _detailed_findings(self) -> str:
        """Gera seção de findings detalhados"""
        findings = self.results.get('findings', [])

        if not findings:
            return ""

        content = "## 🔍 Detailed Findings\n\n"

        # Ordena por severidade (critical > high > medium > low > info)
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        sorted_findings = sorted(
            findings,
            key=lambda x: severity_order.get(x.get('severity', 'info').lower(), 5)
        )

        for idx, finding in enumerate(sorted_findings, 1):
            content += self._format_finding(idx, finding) + "\n\n"

        return content + "---"

    def _format_finding(self, number: int, finding: Dict[str, Any]) -> str:
        """Formata um finding individual"""
        title = finding.get('title', 'Unknown Issue')
        severity = finding.get('severity', 'info').upper()
        category = finding.get('category', 'Uncategorized')
        description = finding.get('description', 'No description available')
        location = finding.get('location', 'N/A')
        recommendation = finding.get('recommendation', 'Review and remediate as appropriate')
        cwe = finding.get('cwe', '')
        owasp = finding.get('owasp', '')

        # Emoji por severidade
        emoji = self._severity_emoji(severity)

        result = f"### {number}. {emoji} {title}\n\n"
        result += f"**Severity:** {severity}  \n"
        result += f"**Category:** {category}  \n"

        if location:
            result += f"**Location:** `{location}`  \n"

        if cwe:
            result += f"**CWE:** {cwe}  \n"

        if owasp:
            result += f"**OWASP MASTG:** {owasp}  \n"

        result += f"\n**Description:**\n\n{description}\n\n"
        result += f"**Recommendation:**\n\n{recommendation}"

        # Evidências
        evidence = finding.get('evidence', {})
        if evidence:
            result += "\n\n**Evidence:**\n\n"
            result += f"```\n{self._format_evidence(evidence)}\n```"

        return result

    def _module_details(self) -> str:
        """Gera detalhes dos módulos executados"""
        modules_results = self.results.get('modules_results', {})

        if not modules_results:
            return ""

        content = "## 🔧 Module Execution Details\n\n"

        for module_name, module_data in modules_results.items():
            content += f"### {module_name.upper()} Module\n\n"

            status = module_data.get('status', 'Unknown')
            duration = module_data.get('duration', 0)
            findings_count = len(module_data.get('findings', []))

            content += f"- **Status:** {status}\n"
            content += f"- **Duration:** {duration:.2f}s\n"
            content += f"- **Findings:** {findings_count}\n\n"

            # Detalhes específicos do módulo
            details = module_data.get('details', {})
            if details:
                content += "**Details:**\n\n"
                for key, value in details.items():
                    content += f"- **{key}:** {value}\n"
                content += "\n"

        return content + "---"

    def _recommendations(self) -> str:
        """Gera seção de recomendações"""
        findings = self.results.get('findings', [])

        if not findings:
            return ""

        # Agrupa recomendações por prioridade
        critical_high = [f for f in findings if f.get('severity', '').lower() in ['critical', 'high']]

        content = "## 💡 Recommendations\n\n"
        content += "### Priority Actions\n\n"

        if critical_high:
            content += "The following critical and high severity issues require immediate attention:\n\n"
            for idx, finding in enumerate(critical_high, 1):
                title = finding.get('title', 'Unknown')
                recommendation = finding.get('recommendation', 'Review and remediate')
                content += f"{idx}. **{title}**\n   - {recommendation}\n\n"
        else:
            content += "No critical or high severity issues identified.\n\n"

        content += "### General Security Improvements\n\n"
        content += "- Implement regular security testing in CI/CD pipeline\n"
        content += "- Enable runtime application self-protection (RASP)\n"
        content += "- Conduct periodic security code reviews\n"
        content += "- Keep dependencies updated and monitor for vulnerabilities\n"
        content += "- Implement certificate pinning for network communications\n"
        content += "- Use secure storage mechanisms for sensitive data\n\n"

        return content + "---"

    def _appendix(self) -> str:
        """Gera apêndice com informações técnicas"""
        target_info = self.results.get('target_info', {})

        content = "## 📎 Appendix\n\n"
        content += "### Target Information\n\n"

        if target_info:
            content += "| Property | Value |\n"
            content += "|----------|-------|\n"
            for key, value in target_info.items():
                content += f"| {key} | {value} |\n"
        else:
            content += "No additional target information available.\n"

        content += "\n### Scan Configuration\n\n"
        config = self.results.get('configuration', {})
        if config:
            content += "```yaml\n"
            import yaml
            content += yaml.dump(config, default_flow_style=False)
            content += "```\n"

        content += "\n### References\n\n"
        content += "- [OWASP MASTG](https://mas.owasp.org/MASTG/)\n"
        content += "- [OWASP MASVS](https://mas.owasp.org/MASVS/)\n"
        content += "- [CWE Database](https://cwe.mitre.org/)\n"
        content += "- [MOBSCAN Documentation](https://github.com/GhostN3xus/Owasp_Checklist_testing)\n"

        return content

    # Helper methods

    def _count_by_severity(self, findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """Conta findings por severidade"""
        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for finding in findings:
            severity = finding.get('severity', 'info').lower()
            if severity in counts:
                counts[severity] += 1
        return counts

    def _group_by_category(self, findings: List[Dict[str, Any]]) -> Dict[str, List[Dict]]:
        """Agrupa findings por categoria"""
        by_category = {}
        for finding in findings:
            category = finding.get('category', 'Uncategorized')
            if category not in by_category:
                by_category[category] = []
            by_category[category].append(finding)
        return by_category

    def _calculate_risk_level(self, severity_counts: Dict[str, int]) -> str:
        """Calcula nível de risco geral"""
        if severity_counts['critical'] > 0:
            return "🔴 CRITICAL"
        elif severity_counts['high'] >= 3:
            return "🟠 HIGH"
        elif severity_counts['high'] > 0 or severity_counts['medium'] >= 5:
            return "🟡 MEDIUM"
        elif severity_counts['medium'] > 0 or severity_counts['low'] > 0:
            return "🟢 LOW"
        else:
            return "✅ MINIMAL"

    def _severity_emoji(self, severity: str) -> str:
        """Retorna emoji para severidade"""
        emojis = {
            'CRITICAL': '🔴',
            'HIGH': '🟠',
            'MEDIUM': '🟡',
            'LOW': '🔵',
            'INFO': 'ℹ️'
        }
        return emojis.get(severity.upper(), '❓')

    def _format_modules_list(self, modules: List[str]) -> str:
        """Formata lista de módulos"""
        if not modules:
            return "- No modules executed"

        module_descriptions = {
            'sast': 'Static Application Security Testing',
            'dast': 'Dynamic Application Security Testing',
            'sca': 'Software Composition Analysis',
            'frida': 'Runtime Instrumentation Analysis'
        }

        result = []
        for module in modules:
            desc = module_descriptions.get(module.lower(), 'Unknown module')
            result.append(f"- **{module.upper()}:** {desc}")

        return '\n'.join(result)

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
