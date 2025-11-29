"""
Plugin de Análise de URLs - Detecta URLs suspeitas e inseguras em aplicações mobile.

Este plugin analisa o código fonte do aplicativo em busca de:
- URLs HTTP (não HTTPS)
- URLs suspeitas ou maliciosas
- Endpoints de API expostos
- URLs hardcoded
"""

import re
import zipfile
from pathlib import Path
from typing import Any, Dict, List

from mobscan.core.plugin_system import (
    AnalyzerPlugin,
    PluginMetadata,
    PluginType
)


class URLAnalyzerPlugin(AnalyzerPlugin):
    """Plugin que analisa URLs em aplicações mobile."""

    def __init__(self):
        self.patterns = {
            'http_url': re.compile(r'http://[^\s\'"<>]+'),
            'https_url': re.compile(r'https://[^\s\'"<>]+'),
            'ip_address': re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'),
            'api_endpoint': re.compile(r'(/api/|/v\d+/|/rest/)'),
        }
        self.suspicious_domains = [
            'localhost',
            '127.0.0.1',
            '0.0.0.0',
            'example.com',
            'test.com',
        ]

    def get_metadata(self) -> PluginMetadata:
        """Retorna metadados do plugin."""
        return PluginMetadata(
            name="url_analyzer",
            version="1.0.0",
            author="MOBSCAN Team",
            description="Analisa URLs suspeitas e inseguras em aplicações mobile",
            plugin_type=PluginType.ANALYZER,
            dependencies=[],
            config_schema={
                "check_http": {"type": "bool", "default": True},
                "check_suspicious": {"type": "bool", "default": True},
                "custom_domains": {"type": "list", "default": []},
            }
        )

    async def initialize(self, config: Dict[str, Any]) -> bool:
        """Inicializa o plugin."""
        self.config = config

        # Adiciona domínios customizados se fornecidos
        custom_domains = config.get('custom_domains', [])
        if custom_domains:
            self.suspicious_domains.extend(custom_domains)

        return True

    async def analyze(self, target: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Executa análise de URLs no alvo.

        Args:
            target: Caminho do APK ou IPA
            context: Contexto da análise

        Returns:
            Resultados da análise
        """
        findings = []

        try:
            # Extrai arquivos do APK/IPA
            files_content = self._extract_files(target)

            # Analisa cada arquivo
            for file_path, content in files_content.items():
                file_findings = self._analyze_content(file_path, content)
                findings.extend(file_findings)

            return {
                "plugin": "url_analyzer",
                "findings": findings,
                "stats": {
                    "total_urls": len(findings),
                    "http_urls": sum(1 for f in findings if f['type'] == 'http_url'),
                    "suspicious_urls": sum(1 for f in findings if f['type'] == 'suspicious_url'),
                    "files_analyzed": len(files_content),
                }
            }

        except Exception as e:
            return {
                "plugin": "url_analyzer",
                "error": str(e),
                "findings": []
            }

    def _extract_files(self, target: str) -> Dict[str, str]:
        """Extrai conteúdo de arquivos do APK/IPA."""
        files_content = {}

        try:
            with zipfile.ZipFile(target, 'r') as zip_ref:
                for file_info in zip_ref.filelist:
                    # Analisa apenas arquivos de código
                    if file_info.filename.endswith(('.java', '.kt', '.swift', '.m', '.xml', '.json')):
                        try:
                            content = zip_ref.read(file_info.filename).decode('utf-8', errors='ignore')
                            files_content[file_info.filename] = content
                        except Exception:
                            continue
        except Exception as e:
            print(f"Error extracting files: {e}")

        return files_content

    def _analyze_content(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        """Analisa conteúdo em busca de URLs."""
        findings = []

        # Detecta URLs HTTP (inseguras)
        if self.config.get('check_http', True):
            for match in self.patterns['http_url'].finditer(content):
                url = match.group(0)
                line_num = content[:match.start()].count('\n') + 1

                findings.append({
                    'type': 'http_url',
                    'severity': 'medium',
                    'title': 'Insecure HTTP URL Detected',
                    'description': f'HTTP URL found (not HTTPS): {url}',
                    'file': file_path,
                    'line': line_num,
                    'url': url,
                    'recommendation': 'Use HTTPS instead of HTTP for secure communication'
                })

        # Detecta URLs suspeitas
        if self.config.get('check_suspicious', True):
            for match in self.patterns['https_url'].finditer(content):
                url = match.group(0)

                # Verifica se contém domínio suspeito
                for suspicious_domain in self.suspicious_domains:
                    if suspicious_domain in url:
                        line_num = content[:match.start()].count('\n') + 1

                        findings.append({
                            'type': 'suspicious_url',
                            'severity': 'low',
                            'title': 'Suspicious URL Detected',
                            'description': f'URL with suspicious domain: {url}',
                            'file': file_path,
                            'line': line_num,
                            'url': url,
                            'domain': suspicious_domain,
                            'recommendation': 'Verify if this is a test/development URL that should be removed'
                        })
                        break

        # Detecta IPs hardcoded
        for match in self.patterns['ip_address'].finditer(content):
            ip = match.group(0)
            # Ignora IPs privados/especiais
            if not ip.startswith(('192.168.', '10.', '172.')):
                line_num = content[:match.start()].count('\n') + 1

                findings.append({
                    'type': 'hardcoded_ip',
                    'severity': 'medium',
                    'title': 'Hardcoded IP Address',
                    'description': f'Hardcoded IP address found: {ip}',
                    'file': file_path,
                    'line': line_num,
                    'ip': ip,
                    'recommendation': 'Use domain names instead of hardcoded IP addresses'
                })

        return findings

    async def cleanup(self) -> None:
        """Cleanup do plugin."""
        pass

    def validate_config(self, config: Dict[str, Any]) -> bool:
        """Valida configuração do plugin."""
        # Validação básica
        if 'check_http' in config and not isinstance(config['check_http'], bool):
            return False
        if 'check_suspicious' in config and not isinstance(config['check_suspicious'], bool):
            return False
        if 'custom_domains' in config and not isinstance(config['custom_domains'], list):
            return False

        return True

    def get_supported_targets(self) -> List[str]:
        """Retorna tipos de alvos suportados."""
        return ["apk", "ipa"]
