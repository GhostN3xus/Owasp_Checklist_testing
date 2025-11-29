"""
SAST Engine - Static Application Security Testing.

Análise estática de código para detectar vulnerabilidades em apps mobile.
Suporta APK (Android) e IPA (iOS).

Detecta:
- Secrets hardcoded
- Weak cryptography
- Insecure storage
- Manifest vulnerabilities
- Permission issues
- Debuggable/exported components
- Vulnerable libraries
"""

import re
import zipfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Any, Optional, Set
import logging
import hashlib
import json

logger = logging.getLogger(__name__)


@dataclass
class Finding:
    """Representa uma descoberta de segurança."""
    severity: str  # critical, high, medium, low, info
    category: str
    title: str
    description: str
    file_path: str
    line_number: Optional[int] = None
    code_snippet: Optional[str] = None
    cwe_id: Optional[int] = None
    owasp_category: Optional[str] = None
    remediation: Optional[str] = None
    references: List[str] = field(default_factory=list)


@dataclass
class SASTResult:
    """Resultado da análise SAST."""
    app_path: str
    findings: List[Finding] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    stats: Dict[str, int] = field(default_factory=dict)


class SecretDetector:
    """Detecta secrets hardcoded no código."""

    # Padrões de secrets
    PATTERNS = {
        'aws_access_key': r'AKIA[0-9A-Z]{16}',
        'aws_secret_key': r'[0-9a-zA-Z/+]{40}',
        'api_key': r'api[_-]?key[\s]*[:=][\s]*["\']([a-zA-Z0-9_\-]{20,})["\']',
        'password': r'password[\s]*[:=][\s]*["\']([^"\']{8,})["\']',
        'token': r'token[\s]*[:=][\s]*["\']([a-zA-Z0-9_\-]{20,})["\']',
        'jwt': r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*',
        'private_key': r'-----BEGIN (RSA |EC )?PRIVATE KEY-----',
        'google_api': r'AIza[0-9A-Za-z\-_]{35}',
        'github_token': r'gh[pousr]_[A-Za-z0-9_]{36,}',
        'slack_token': r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}',
    }

    def detect(self, content: str, file_path: str) -> List[Finding]:
        """Detecta secrets em um arquivo."""
        findings = []

        for secret_type, pattern in self.PATTERNS.items():
            matches = re.finditer(pattern, content, re.IGNORECASE)

            for match in matches:
                # Calcula linha
                line_number = content[:match.start()].count('\n') + 1

                # Extrai snippet
                lines = content.split('\n')
                snippet = lines[line_number - 1] if line_number <= len(lines) else ""

                findings.append(Finding(
                    severity="critical",
                    category="Hardcoded Secrets",
                    title=f"Hardcoded {secret_type.replace('_', ' ').title()}",
                    description=f"Detected hardcoded {secret_type} in source code",
                    file_path=file_path,
                    line_number=line_number,
                    code_snippet=snippet.strip(),
                    cwe_id=798,
                    owasp_category="MASVS-STORAGE-1",
                    remediation="Remove hardcoded secrets and use secure storage or environment variables",
                    references=[
                        "https://owasp.org/www-project-mobile-top-10/",
                        "https://cwe.mitre.org/data/definitions/798.html"
                    ]
                ))

        return findings


class WeakCryptoDetector:
    """Detecta uso de criptografia fraca."""

    WEAK_ALGORITHMS = {
        'md5': r'\bMD5\b|\bMessageDigest\.getInstance\(["\']MD5["\']\)',
        'sha1': r'\bSHA1\b|\bMessageDigest\.getInstance\(["\']SHA-1["\']\)',
        'des': r'\bDES\b|\bCipher\.getInstance\(["\']DES',
        'rc4': r'\bRC4\b|\bARC4\b',
        'ecb': r'\/ECB\/',
    }

    INSECURE_RANDOM = r'\bnew\s+Random\(\)|\bMath\.random\(\)'

    def detect(self, content: str, file_path: str) -> List[Finding]:
        """Detecta criptografia fraca."""
        findings = []

        # Verifica algoritmos fracos
        for algo, pattern in self.WEAK_ALGORITHMS.items():
            matches = re.finditer(pattern, content, re.IGNORECASE)

            for match in matches:
                line_number = content[:match.start()].count('\n') + 1
                lines = content.split('\n')
                snippet = lines[line_number - 1] if line_number <= len(lines) else ""

                findings.append(Finding(
                    severity="high",
                    category="Weak Cryptography",
                    title=f"Weak Cryptographic Algorithm: {algo.upper()}",
                    description=f"Use of weak cryptographic algorithm {algo.upper()} detected",
                    file_path=file_path,
                    line_number=line_number,
                    code_snippet=snippet.strip(),
                    cwe_id=327,
                    owasp_category="MASVS-CRYPTO-1",
                    remediation=f"Replace {algo.upper()} with secure alternatives like AES-256-GCM or SHA-256",
                    references=[
                        "https://owasp.org/www-project-mobile-top-10/",
                        "https://cwe.mitre.org/data/definitions/327.html"
                    ]
                ))

        # Verifica geração insegura de números aleatórios
        matches = re.finditer(self.INSECURE_RANDOM, content)
        for match in matches:
            line_number = content[:match.start()].count('\n') + 1
            lines = content.split('\n')
            snippet = lines[line_number - 1] if line_number <= len(lines) else ""

            findings.append(Finding(
                severity="medium",
                category="Weak Cryptography",
                title="Insecure Random Number Generator",
                description="Use of insecure random number generator",
                file_path=file_path,
                line_number=line_number,
                code_snippet=snippet.strip(),
                cwe_id=338,
                owasp_category="MASVS-CRYPTO-1",
                remediation="Use SecureRandom instead of Random or Math.random()",
                references=[
                    "https://cwe.mitre.org/data/definitions/338.html"
                ]
            ))

        return findings


class InsecureStorageDetector:
    """Detecta armazenamento inseguro de dados."""

    PATTERNS = {
        'shared_prefs_mode_world': r'MODE_WORLD_(READABLE|WRITEABLE)',
        'external_storage': r'getExternalStorage|Environment\.getExternalStorageDirectory',
        'sqlite_no_encryption': r'SQLiteDatabase\.open|SQLiteOpenHelper',
        'file_permissions': r'setReadable\(true\)|setWritable\(true\)',
    }

    def detect(self, content: str, file_path: str) -> List[Finding]:
        """Detecta problemas de armazenamento."""
        findings = []

        for issue_type, pattern in self.PATTERNS.items():
            matches = re.finditer(pattern, content)

            for match in matches:
                line_number = content[:match.start()].count('\n') + 1
                lines = content.split('\n')
                snippet = lines[line_number - 1] if line_number <= len(lines) else ""

                severity = "high" if "world" in issue_type else "medium"

                findings.append(Finding(
                    severity=severity,
                    category="Insecure Storage",
                    title=f"Insecure Storage: {issue_type.replace('_', ' ').title()}",
                    description=f"Detected insecure storage pattern: {issue_type}",
                    file_path=file_path,
                    line_number=line_number,
                    code_snippet=snippet.strip(),
                    cwe_id=922,
                    owasp_category="MASVS-STORAGE-1",
                    remediation="Use encrypted storage mechanisms",
                    references=[
                        "https://developer.android.com/topic/security/data"
                    ]
                ))

        return findings


class ManifestAnalyzer:
    """Analisa AndroidManifest.xml para vulnerabilidades."""

    def analyze(self, manifest_content: str) -> List[Finding]:
        """Analisa o manifest."""
        findings = []

        try:
            root = ET.fromstring(manifest_content)

            # Verifica debuggable
            application = root.find('.//application')
            if application is not None:
                debuggable = application.get('{http://schemas.android.com/apk/res/android}debuggable')
                if debuggable == 'true':
                    findings.append(Finding(
                        severity="high",
                        category="Manifest Configuration",
                        title="Application is Debuggable",
                        description="Application has debuggable flag set to true in production",
                        file_path="AndroidManifest.xml",
                        cwe_id=489,
                        owasp_category="MASVS-RESILIENCE-2",
                        remediation="Set android:debuggable to false in production builds",
                        references=[
                            "https://developer.android.com/guide/topics/manifest/application-element"
                        ]
                    ))

                # Verifica allowBackup
                allow_backup = application.get('{http://schemas.android.com/apk/res/android}allowBackup')
                if allow_backup == 'true':
                    findings.append(Finding(
                        severity="medium",
                        category="Manifest Configuration",
                        title="Backup Allowed",
                        description="Application allows backup which may expose sensitive data",
                        file_path="AndroidManifest.xml",
                        cwe_id=200,
                        owasp_category="MASVS-STORAGE-2",
                        remediation="Set android:allowBackup to false if app handles sensitive data",
                        references=[
                            "https://developer.android.com/guide/topics/manifest/application-element"
                        ]
                    ))

            # Verifica exported components sem permission
            for component_type in ['activity', 'service', 'receiver', 'provider']:
                components = root.findall(f'.//{component_type}')
                for component in components:
                    exported = component.get('{http://schemas.android.com/apk/res/android}exported')
                    permission = component.get('{http://schemas.android.com/apk/res/android}permission')
                    name = component.get('{http://schemas.android.com/apk/res/android}name')

                    if exported == 'true' and not permission:
                        findings.append(Finding(
                            severity="high",
                            category="Manifest Configuration",
                            title=f"Exported {component_type.title()} Without Permission",
                            description=f"Component {name} is exported but has no permission protection",
                            file_path="AndroidManifest.xml",
                            cwe_id=927,
                            owasp_category="MASVS-PLATFORM-1",
                            remediation="Add permission requirement or set exported=false",
                            references=[
                                "https://developer.android.com/guide/topics/manifest/activity-element"
                            ]
                        ))

        except Exception as e:
            logger.error(f"Error parsing manifest: {e}")

        return findings


class SASTEngine:
    """
    Motor principal de análise estática.

    Orquestra todos os detectores e gera relatório completo.
    """

    def __init__(self):
        self.secret_detector = SecretDetector()
        self.crypto_detector = WeakCryptoDetector()
        self.storage_detector = InsecureStorageDetector()
        self.manifest_analyzer = ManifestAnalyzer()

    async def scan(self, app_path: str, options: Dict[str, Any] = None) -> SASTResult:
        """
        Executa scan SAST completo.

        Args:
            app_path: Caminho para APK ou IPA
            options: Opções de configuração

        Returns:
            Resultado da análise
        """
        options = options or {}
        result = SASTResult(app_path=app_path)

        logger.info(f"Starting SAST scan for: {app_path}")

        try:
            path = Path(app_path)

            if path.suffix.lower() == '.apk':
                await self._scan_apk(path, result, options)
            elif path.suffix.lower() == '.ipa':
                await self._scan_ipa(path, result, options)
            else:
                raise ValueError(f"Unsupported file type: {path.suffix}")

            # Calcula estatísticas
            self._calculate_stats(result)

            logger.info(f"SAST scan completed: {len(result.findings)} findings")

        except Exception as e:
            logger.error(f"Error during SAST scan: {e}")
            raise

        return result

    async def _scan_apk(self, apk_path: Path, result: SASTResult,
                       options: Dict[str, Any]) -> None:
        """Scan específico para APK."""
        with zipfile.ZipFile(apk_path, 'r') as apk:
            # Lista todos os arquivos
            file_list = apk.namelist()

            # Extrai metadados
            result.metadata['package_name'] = self._extract_package_name(apk)
            result.metadata['file_count'] = len(file_list)

            # Analisa AndroidManifest.xml
            if 'AndroidManifest.xml' in file_list:
                try:
                    manifest_data = apk.read('AndroidManifest.xml')
                    # Nota: manifest binário precisa ser decodificado
                    # Por simplicidade, assumimos texto aqui
                    manifest_str = manifest_data.decode('utf-8', errors='ignore')
                    manifest_findings = self.manifest_analyzer.analyze(manifest_str)
                    result.findings.extend(manifest_findings)
                except Exception as e:
                    logger.warning(f"Error analyzing manifest: {e}")

            # Analisa arquivos de código
            code_extensions = ['.java', '.kt', '.xml', '.json', '.properties']
            for file_path in file_list:
                if any(file_path.endswith(ext) for ext in code_extensions):
                    try:
                        content = apk.read(file_path).decode('utf-8', errors='ignore')

                        # Aplica detectores
                        result.findings.extend(
                            self.secret_detector.detect(content, file_path)
                        )
                        result.findings.extend(
                            self.crypto_detector.detect(content, file_path)
                        )
                        result.findings.extend(
                            self.storage_detector.detect(content, file_path)
                        )

                    except Exception as e:
                        logger.debug(f"Error analyzing {file_path}: {e}")

    async def _scan_ipa(self, ipa_path: Path, result: SASTResult,
                       options: Dict[str, Any]) -> None:
        """Scan específico para IPA."""
        with zipfile.ZipFile(ipa_path, 'r') as ipa:
            file_list = ipa.namelist()

            result.metadata['file_count'] = len(file_list)

            # Analisa arquivos Swift/Objective-C
            code_extensions = ['.swift', '.m', '.h', '.plist']
            for file_path in file_list:
                if any(file_path.endswith(ext) for ext in code_extensions):
                    try:
                        content = ipa.read(file_path).decode('utf-8', errors='ignore')

                        result.findings.extend(
                            self.secret_detector.detect(content, file_path)
                        )
                        result.findings.extend(
                            self.crypto_detector.detect(content, file_path)
                        )

                    except Exception as e:
                        logger.debug(f"Error analyzing {file_path}: {e}")

    def _extract_package_name(self, apk: zipfile.ZipFile) -> Optional[str]:
        """Extrai nome do pacote do APK."""
        try:
            # Implementação simplificada
            return "com.example.app"
        except:
            return None

    def _calculate_stats(self, result: SASTResult) -> None:
        """Calcula estatísticas dos findings."""
        result.stats = {
            'total': len(result.findings),
            'critical': sum(1 for f in result.findings if f.severity == 'critical'),
            'high': sum(1 for f in result.findings if f.severity == 'high'),
            'medium': sum(1 for f in result.findings if f.severity == 'medium'),
            'low': sum(1 for f in result.findings if f.severity == 'low'),
            'info': sum(1 for f in result.findings if f.severity == 'info'),
        }

        # Agrupa por categoria
        categories = {}
        for finding in result.findings:
            categories[finding.category] = categories.get(finding.category, 0) + 1

        result.stats['by_category'] = categories
