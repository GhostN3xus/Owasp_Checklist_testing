"""
SCA Engine - Software Composition Analysis.

Análise de dependências e bibliotecas de terceiros para:
- Extração de dependências (Gradle, Maven, CocoaPods, SPM)
- Verificação de vulnerabilidades conhecidas
- Detecção de versões desatualizadas
- Compliance de licenças
- Análise de supply chain
- Geração de SBOM (Software Bill of Materials)
"""

import re
import json
import zipfile
import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Any, Optional, Set
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


@dataclass
class Dependency:
    """Representa uma dependência."""
    name: str
    version: str
    ecosystem: str  # maven, npm, cocoapods, etc
    direct: bool = True
    license: Optional[str] = None
    hash: Optional[str] = None


@dataclass
class Vulnerability:
    """Representa uma vulnerabilidade conhecida."""
    cve_id: str
    severity: str
    description: str
    affected_versions: List[str]
    fixed_version: Optional[str] = None
    references: List[str] = field(default_factory=list)
    cvss_score: Optional[float] = None


@dataclass
class DependencyIssue:
    """Problema encontrado em uma dependência."""
    dependency: Dependency
    issue_type: str  # vulnerability, outdated, license, deprecated
    severity: str
    title: str
    description: str
    remediation: Optional[str] = None
    vulnerabilities: List[Vulnerability] = field(default_factory=list)


@dataclass
class SCAResult:
    """Resultado da análise SCA."""
    app_path: str
    dependencies: List[Dependency] = field(default_factory=list)
    issues: List[DependencyIssue] = field(default_factory=list)
    sbom: Dict[str, Any] = field(default_factory=dict)
    stats: Dict[str, int] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


class DependencyExtractor:
    """Extrai dependências de diferentes formatos."""

    def extract_gradle(self, content: str) -> List[Dependency]:
        """Extrai dependências de build.gradle."""
        dependencies = []

        # Padrão: implementation 'group:artifact:version'
        patterns = [
            r"implementation\s+['\"]([^:]+):([^:]+):([^'\"]+)['\"]",
            r"api\s+['\"]([^:]+):([^:]+):([^'\"]+)['\"]",
            r"compile\s+['\"]([^:]+):([^:]+):([^'\"]+)['\"]",
        ]

        for pattern in patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                group, artifact, version = match.groups()
                dependencies.append(Dependency(
                    name=f"{group}:{artifact}",
                    version=version,
                    ecosystem="maven",
                    direct=True
                ))

        return dependencies

    def extract_maven(self, content: str) -> List[Dependency]:
        """Extrai dependências de pom.xml."""
        dependencies = []

        # Padrão XML simplificado
        pattern = r"<dependency>.*?<groupId>([^<]+)</groupId>.*?<artifactId>([^<]+)</artifactId>.*?<version>([^<]+)</version>.*?</dependency>"
        matches = re.finditer(pattern, content, re.DOTALL)

        for match in matches:
            group, artifact, version = match.groups()
            dependencies.append(Dependency(
                name=f"{group}:{artifact}",
                version=version,
                ecosystem="maven",
                direct=True
            ))

        return dependencies

    def extract_cocoapods(self, content: str) -> List[Dependency]:
        """Extrai dependências de Podfile."""
        dependencies = []

        # Padrão: pod 'PodName', 'version'
        pattern = r"pod\s+['\"]([^'\"]+)['\"],\s*['\"]([^'\"]+)['\"]"
        matches = re.finditer(pattern, content)

        for match in matches:
            name, version = match.groups()
            dependencies.append(Dependency(
                name=name,
                version=version,
                ecosystem="cocoapods",
                direct=True
            ))

        return dependencies

    def extract_swift_package(self, content: str) -> List[Dependency]:
        """Extrai dependências de Package.swift."""
        dependencies = []

        # Padrão: .package(url: "...", from: "version")
        pattern = r'\.package\(url:\s*"([^"]+)",\s*(?:from|exact):\s*"([^"]+)"\)'
        matches = re.finditer(pattern, content)

        for match in matches:
            url, version = match.groups()
            # Extrai nome do repositório
            name = url.split('/')[-1].replace('.git', '')

            dependencies.append(Dependency(
                name=name,
                version=version,
                ecosystem="swift",
                direct=True
            ))

        return dependencies


class VulnerabilityChecker:
    """Verifica vulnerabilidades conhecidas em dependências."""

    def __init__(self):
        # Banco de dados simulado de vulnerabilidades
        self.vuln_db = self._load_vulnerability_database()

    def _load_vulnerability_database(self) -> Dict[str, List[Vulnerability]]:
        """Carrega banco de dados de vulnerabilidades."""
        # Simulado - em produção, integraria com NVD, OSV, etc.
        return {
            "com.squareup.okhttp3:okhttp": [
                Vulnerability(
                    cve_id="CVE-2021-0341",
                    severity="high",
                    description="Certificate pinning bypass vulnerability",
                    affected_versions=["< 4.9.3"],
                    fixed_version="4.9.3",
                    cvss_score=7.5,
                    references=[
                        "https://nvd.nist.gov/vuln/detail/CVE-2021-0341"
                    ]
                )
            ],
            "com.google.code.gson:gson": [
                Vulnerability(
                    cve_id="CVE-2022-25647",
                    severity="high",
                    description="Deserialization vulnerability",
                    affected_versions=["< 2.8.9"],
                    fixed_version="2.8.9",
                    cvss_score=7.5,
                    references=[
                        "https://nvd.nist.gov/vuln/detail/CVE-2022-25647"
                    ]
                )
            ],
        }

    def check_vulnerabilities(self, dependency: Dependency) -> List[Vulnerability]:
        """Verifica vulnerabilidades para uma dependência."""
        vulnerabilities = []

        if dependency.name in self.vuln_db:
            for vuln in self.vuln_db[dependency.name]:
                if self._is_version_affected(dependency.version, vuln.affected_versions):
                    vulnerabilities.append(vuln)

        return vulnerabilities

    def _is_version_affected(self, version: str, affected_patterns: List[str]) -> bool:
        """Verifica se versão está afetada."""
        # Implementação simplificada - em produção, usaria semver
        for pattern in affected_patterns:
            if pattern.startswith('<'):
                max_version = pattern.replace('<', '').strip()
                if self._compare_versions(version, max_version) < 0:
                    return True
            elif pattern.startswith('>'):
                min_version = pattern.replace('>', '').strip()
                if self._compare_versions(version, min_version) > 0:
                    return True

        return False

    def _compare_versions(self, v1: str, v2: str) -> int:
        """Compara versões (-1: v1 < v2, 0: igual, 1: v1 > v2)."""
        # Implementação simplificada
        try:
            parts1 = [int(x) for x in v1.split('.')]
            parts2 = [int(x) for x in v2.split('.')]

            for p1, p2 in zip(parts1, parts2):
                if p1 < p2:
                    return -1
                elif p1 > p2:
                    return 1

            return 0
        except:
            return 0


class LicenseAnalyzer:
    """Analisa licenças de dependências."""

    KNOWN_LICENSES = {
        'apache-2.0': {'type': 'permissive', 'risk': 'low'},
        'mit': {'type': 'permissive', 'risk': 'low'},
        'bsd': {'type': 'permissive', 'risk': 'low'},
        'gpl': {'type': 'copyleft', 'risk': 'high'},
        'agpl': {'type': 'copyleft', 'risk': 'high'},
        'lgpl': {'type': 'weak-copyleft', 'risk': 'medium'},
    }

    def analyze_license(self, dependency: Dependency) -> Optional[DependencyIssue]:
        """Analisa licença de uma dependência."""
        if not dependency.license:
            return DependencyIssue(
                dependency=dependency,
                issue_type="license",
                severity="low",
                title="Unknown License",
                description=f"License not identified for {dependency.name}",
                remediation="Verify the license manually"
            )

        license_lower = dependency.license.lower()

        # Verifica licenças problemáticas
        for lic_name, info in self.KNOWN_LICENSES.items():
            if lic_name in license_lower:
                if info['risk'] == 'high':
                    return DependencyIssue(
                        dependency=dependency,
                        issue_type="license",
                        severity="medium",
                        title=f"Copyleft License Detected: {dependency.license}",
                        description=f"{dependency.name} uses a copyleft license which may have implications",
                        remediation="Review license compatibility with your project"
                    )

        return None


class SBOMGenerator:
    """Gera Software Bill of Materials."""

    def generate_sbom(self, dependencies: List[Dependency],
                     app_name: str = "mobile-app",
                     app_version: str = "1.0.0") -> Dict[str, Any]:
        """
        Gera SBOM no formato CycloneDX.

        Args:
            dependencies: Lista de dependências
            app_name: Nome do aplicativo
            app_version: Versão do aplicativo

        Returns:
            SBOM em formato dict
        """
        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "serialNumber": f"urn:uuid:{self._generate_uuid()}",
            "version": 1,
            "metadata": {
                "timestamp": datetime.now().isoformat(),
                "tools": [
                    {
                        "vendor": "MOBSCAN",
                        "name": "MOBSCAN SCA Engine",
                        "version": "1.1.0"
                    }
                ],
                "component": {
                    "type": "application",
                    "name": app_name,
                    "version": app_version
                }
            },
            "components": []
        }

        for dep in dependencies:
            component = {
                "type": "library",
                "name": dep.name,
                "version": dep.version,
                "purl": self._generate_purl(dep)
            }

            if dep.license:
                component["licenses"] = [{"license": {"name": dep.license}}]

            if dep.hash:
                component["hashes"] = [{"alg": "SHA-256", "content": dep.hash}]

            sbom["components"].append(component)

        return sbom

    def _generate_uuid(self) -> str:
        """Gera UUID para o SBOM."""
        import uuid
        return str(uuid.uuid4())

    def _generate_purl(self, dep: Dependency) -> str:
        """Gera Package URL (purl) para dependência."""
        if dep.ecosystem == "maven":
            parts = dep.name.split(':')
            if len(parts) == 2:
                return f"pkg:maven/{parts[0]}/{parts[1]}@{dep.version}"

        return f"pkg:{dep.ecosystem}/{dep.name}@{dep.version}"


class SCAEngine:
    """
    Motor principal de análise de composição de software.

    Orquestra extração, análise e relatório de dependências.
    """

    def __init__(self):
        self.extractor = DependencyExtractor()
        self.vuln_checker = VulnerabilityChecker()
        self.license_analyzer = LicenseAnalyzer()
        self.sbom_generator = SBOMGenerator()

    async def scan(self, app_path: str, options: Dict[str, Any] = None) -> SCAResult:
        """
        Executa scan SCA completo.

        Args:
            app_path: Caminho para APK ou IPA
            options: Opções de configuração

        Returns:
            Resultado da análise
        """
        options = options or {}
        result = SCAResult(app_path=app_path)

        logger.info(f"Starting SCA scan for: {app_path}")

        try:
            path = Path(app_path)

            if path.suffix.lower() == '.apk':
                await self._scan_apk(path, result, options)
            elif path.suffix.lower() == '.ipa':
                await self._scan_ipa(path, result, options)
            else:
                raise ValueError(f"Unsupported file type: {path.suffix}")

            # Analisa dependências
            await self._analyze_dependencies(result)

            # Gera SBOM
            result.sbom = self.sbom_generator.generate_sbom(
                result.dependencies,
                app_name=path.stem
            )

            # Calcula estatísticas
            self._calculate_stats(result)

            logger.info(f"SCA scan completed: {len(result.dependencies)} dependencies, {len(result.issues)} issues")

        except Exception as e:
            logger.error(f"Error during SCA scan: {e}")
            raise

        return result

    async def _scan_apk(self, apk_path: Path, result: SCAResult,
                       options: Dict[str, Any]) -> None:
        """Scan específico para APK."""
        with zipfile.ZipFile(apk_path, 'r') as apk:
            file_list = apk.namelist()

            # Procura build.gradle
            for file_path in file_list:
                if 'build.gradle' in file_path:
                    try:
                        content = apk.read(file_path).decode('utf-8', errors='ignore')
                        deps = self.extractor.extract_gradle(content)
                        result.dependencies.extend(deps)
                    except Exception as e:
                        logger.debug(f"Error extracting from {file_path}: {e}")

                # Procura pom.xml
                elif 'pom.xml' in file_path:
                    try:
                        content = apk.read(file_path).decode('utf-8', errors='ignore')
                        deps = self.extractor.extract_maven(content)
                        result.dependencies.extend(deps)
                    except Exception as e:
                        logger.debug(f"Error extracting from {file_path}: {e}")

    async def _scan_ipa(self, ipa_path: Path, result: SCAResult,
                       options: Dict[str, Any]) -> None:
        """Scan específico para IPA."""
        with zipfile.ZipFile(ipa_path, 'r') as ipa:
            file_list = ipa.namelist()

            # Procura Podfile
            for file_path in file_list:
                if 'Podfile' in file_path:
                    try:
                        content = ipa.read(file_path).decode('utf-8', errors='ignore')
                        deps = self.extractor.extract_cocoapods(content)
                        result.dependencies.extend(deps)
                    except Exception as e:
                        logger.debug(f"Error extracting from {file_path}: {e}")

                # Procura Package.swift
                elif 'Package.swift' in file_path:
                    try:
                        content = ipa.read(file_path).decode('utf-8', errors='ignore')
                        deps = self.extractor.extract_swift_package(content)
                        result.dependencies.extend(deps)
                    except Exception as e:
                        logger.debug(f"Error extracting from {file_path}: {e}")

    async def _analyze_dependencies(self, result: SCAResult) -> None:
        """Analisa dependências encontradas."""
        for dep in result.dependencies:
            # Verifica vulnerabilidades
            vulnerabilities = self.vuln_checker.check_vulnerabilities(dep)

            if vulnerabilities:
                issue = DependencyIssue(
                    dependency=dep,
                    issue_type="vulnerability",
                    severity="critical" if any(v.severity == "critical" for v in vulnerabilities) else "high",
                    title=f"Vulnerable Dependency: {dep.name}",
                    description=f"{dep.name}@{dep.version} has {len(vulnerabilities)} known vulnerabilities",
                    remediation=f"Update to latest secure version",
                    vulnerabilities=vulnerabilities
                )
                result.issues.append(issue)

            # Analisa licença
            license_issue = self.license_analyzer.analyze_license(dep)
            if license_issue:
                result.issues.append(license_issue)

    def _calculate_stats(self, result: SCAResult) -> None:
        """Calcula estatísticas."""
        result.stats = {
            'total_dependencies': len(result.dependencies),
            'direct_dependencies': sum(1 for d in result.dependencies if d.direct),
            'transitive_dependencies': sum(1 for d in result.dependencies if not d.direct),
            'total_issues': len(result.issues),
            'vulnerabilities': sum(1 for i in result.issues if i.issue_type == 'vulnerability'),
            'license_issues': sum(1 for i in result.issues if i.issue_type == 'license'),
        }

        # Agrupa por ecosystem
        ecosystems = {}
        for dep in result.dependencies:
            ecosystems[dep.ecosystem] = ecosystems.get(dep.ecosystem, 0) + 1

        result.stats['by_ecosystem'] = ecosystems
