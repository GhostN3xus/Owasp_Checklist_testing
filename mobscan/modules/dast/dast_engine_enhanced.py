"""
DAST Engine Enhanced - Dynamic Application Security Testing.

Análise dinâmica de aplicativos mobile em runtime, incluindo:
- Network traffic interception
- Security headers validation
- Sensitive data detection
- Unencrypted HTTP detection
- Certificate validation
- HAR export
"""

import asyncio
import json
import ssl
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Any, Optional, Set
from urllib.parse import urlparse
import logging
import re
import base64

logger = logging.getLogger(__name__)


@dataclass
class NetworkRequest:
    """Representa uma requisição de rede capturada."""
    method: str
    url: str
    headers: Dict[str, str]
    body: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class NetworkResponse:
    """Representa uma resposta de rede capturada."""
    status_code: int
    headers: Dict[str, str]
    body: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class NetworkTransaction:
    """Transação completa (request + response)."""
    request: NetworkRequest
    response: Optional[NetworkResponse] = None
    duration_ms: int = 0
    size_bytes: int = 0


@dataclass
class DASTFinding:
    """Descoberta de segurança durante análise dinâmica."""
    severity: str
    category: str
    title: str
    description: str
    url: Optional[str] = None
    evidence: Optional[str] = None
    remediation: Optional[str] = None
    cwe_id: Optional[int] = None
    owasp_category: Optional[str] = None


@dataclass
class DASTResult:
    """Resultado da análise DAST."""
    transactions: List[NetworkTransaction] = field(default_factory=list)
    findings: List[DASTFinding] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    stats: Dict[str, int] = field(default_factory=dict)


class SensitiveDataDetector:
    """Detecta dados sensíveis em tráfego de rede."""

    PATTERNS = {
        'credit_card': r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',
        'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
        'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        'phone': r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
        'ip_address': r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
        'password': r'"password"\s*:\s*"[^"]+"|password=[^&\s]+',
        'api_key': r'api[_-]?key[\s]*[:=][\s]*["\']([a-zA-Z0-9_\-]{20,})["\']',
        'token': r'token[\s]*[:=][\s]*["\']([a-zA-Z0-9_\-]{20,})["\']',
        'jwt': r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*',
    }

    def detect(self, data: str, context: str = "") -> List[DASTFinding]:
        """Detecta dados sensíveis em string."""
        findings = []

        for data_type, pattern in self.PATTERNS.items():
            matches = re.finditer(pattern, data, re.IGNORECASE)

            for match in matches:
                findings.append(DASTFinding(
                    severity="high" if data_type in ['credit_card', 'ssn', 'password'] else "medium",
                    category="Sensitive Data Exposure",
                    title=f"Sensitive Data in {context}: {data_type.replace('_', ' ').title()}",
                    description=f"Detected {data_type} transmitted over network",
                    evidence=match.group()[:50] + "..." if len(match.group()) > 50 else match.group(),
                    cwe_id=200,
                    owasp_category="MASVS-NETWORK-1",
                    remediation="Encrypt sensitive data before transmission and use HTTPS"
                ))

        return findings


class SecurityHeadersValidator:
    """Valida headers de segurança HTTP."""

    REQUIRED_HEADERS = {
        'Strict-Transport-Security': {
            'severity': 'high',
            'description': 'Missing HSTS header - connection may be downgraded to HTTP'
        },
        'X-Content-Type-Options': {
            'severity': 'medium',
            'description': 'Missing X-Content-Type-Options header - vulnerable to MIME sniffing'
        },
        'X-Frame-Options': {
            'severity': 'medium',
            'description': 'Missing X-Frame-Options header - vulnerable to clickjacking'
        },
        'Content-Security-Policy': {
            'severity': 'medium',
            'description': 'Missing CSP header - vulnerable to XSS and injection attacks'
        },
    }

    def validate(self, headers: Dict[str, str], url: str) -> List[DASTFinding]:
        """Valida headers de segurança."""
        findings = []

        # Converte headers para case-insensitive dict
        headers_lower = {k.lower(): v for k, v in headers.items()}

        for header, config in self.REQUIRED_HEADERS.items():
            if header.lower() not in headers_lower:
                findings.append(DASTFinding(
                    severity=config['severity'],
                    category="Security Headers",
                    title=f"Missing Security Header: {header}",
                    description=config['description'],
                    url=url,
                    cwe_id=693,
                    owasp_category="MASVS-NETWORK-1",
                    remediation=f"Add {header} header to response"
                ))

        # Valida valores específicos
        if 'strict-transport-security' in headers_lower:
            hsts_value = headers_lower['strict-transport-security']
            if 'max-age' not in hsts_value.lower():
                findings.append(DASTFinding(
                    severity="medium",
                    category="Security Headers",
                    title="Invalid HSTS Configuration",
                    description="HSTS header present but missing max-age directive",
                    url=url,
                    evidence=hsts_value,
                    remediation="Add max-age directive to HSTS header"
                ))

        return findings


class CertificateValidator:
    """Valida certificados SSL/TLS."""

    def validate_certificate(self, hostname: str, cert_info: Dict[str, Any]) -> List[DASTFinding]:
        """Valida certificado SSL."""
        findings = []

        # Verifica expiração
        if 'notAfter' in cert_info:
            expiry = datetime.strptime(cert_info['notAfter'], '%b %d %H:%M:%S %Y %Z')
            if expiry < datetime.now():
                findings.append(DASTFinding(
                    severity="critical",
                    category="TLS/SSL",
                    title="Expired SSL Certificate",
                    description=f"SSL certificate for {hostname} has expired",
                    url=f"https://{hostname}",
                    evidence=f"Expired on: {cert_info['notAfter']}",
                    cwe_id=295,
                    owasp_category="MASVS-NETWORK-1",
                    remediation="Renew SSL certificate"
                ))

        # Verifica algoritmo de assinatura
        if 'signatureAlgorithm' in cert_info:
            weak_algos = ['md5', 'sha1']
            sig_algo = cert_info['signatureAlgorithm'].lower()

            for weak in weak_algos:
                if weak in sig_algo:
                    findings.append(DASTFinding(
                        severity="high",
                        category="TLS/SSL",
                        title="Weak Certificate Signature Algorithm",
                        description=f"Certificate uses weak signature algorithm: {sig_algo}",
                        url=f"https://{hostname}",
                        evidence=cert_info['signatureAlgorithm'],
                        cwe_id=327,
                        remediation="Use certificate with SHA-256 or stronger signature"
                    ))
                    break

        return findings


class ProxyHandler:
    """Handler para captura e análise de tráfego via proxy."""

    def __init__(self):
        self.transactions: List[NetworkTransaction] = []
        self.sensitive_detector = SensitiveDataDetector()
        self.headers_validator = SecurityHeadersValidator()

    async def handle_request(self, request: NetworkRequest) -> None:
        """Processa requisição capturada."""
        transaction = NetworkTransaction(request=request)
        self.transactions.append(transaction)

        logger.debug(f"Captured request: {request.method} {request.url}")

    async def handle_response(self, response: NetworkResponse,
                             request: NetworkRequest) -> None:
        """Processa resposta capturada."""
        # Encontra transação correspondente
        for transaction in reversed(self.transactions):
            if (transaction.request.url == request.url and
                transaction.response is None):
                transaction.response = response
                break

        logger.debug(f"Captured response: {response.status_code} for {request.url}")

    def export_har(self, output_path: str) -> None:
        """Exporta transações para formato HAR."""
        har = {
            "log": {
                "version": "1.2",
                "creator": {
                    "name": "MOBSCAN",
                    "version": "1.1.0"
                },
                "entries": []
            }
        }

        for transaction in self.transactions:
            entry = {
                "startedDateTime": transaction.request.timestamp.isoformat(),
                "time": transaction.duration_ms,
                "request": {
                    "method": transaction.request.method,
                    "url": transaction.request.url,
                    "headers": [
                        {"name": k, "value": v}
                        for k, v in transaction.request.headers.items()
                    ],
                    "bodySize": len(transaction.request.body or "")
                },
                "response": {
                    "status": transaction.response.status_code if transaction.response else 0,
                    "headers": [
                        {"name": k, "value": v}
                        for k, v in (transaction.response.headers if transaction.response else {}).items()
                    ],
                    "bodySize": len(transaction.response.body or "") if transaction.response else 0
                } if transaction.response else {}
            }

            har["log"]["entries"].append(entry)

        with open(output_path, 'w') as f:
            json.dump(har, f, indent=2)

        logger.info(f"HAR exported to: {output_path}")


class DASTEngine:
    """
    Motor principal de análise dinâmica.

    Captura e analisa tráfego de rede em runtime.
    """

    def __init__(self):
        self.proxy_handler = ProxyHandler()
        self.sensitive_detector = SensitiveDataDetector()
        self.headers_validator = SecurityHeadersValidator()
        self.cert_validator = CertificateValidator()

    async def start_analysis(self, options: Dict[str, Any] = None) -> DASTResult:
        """
        Inicia análise dinâmica.

        Args:
            options: Opções de configuração
                - proxy_port: Porta do proxy (padrão: 8080)
                - duration: Duração da análise em segundos
                - target_host: Host alvo (opcional)

        Returns:
            Resultado da análise
        """
        options = options or {}
        result = DASTResult()

        proxy_port = options.get('proxy_port', 8080)
        duration = options.get('duration', 60)

        logger.info(f"Starting DAST analysis on port {proxy_port} for {duration}s")

        try:
            # Simula captura de tráfego
            # Em implementação real, iniciaria servidor proxy
            await asyncio.sleep(duration)

            # Analisa transações capturadas
            result.transactions = self.proxy_handler.transactions

            # Executa análises
            await self._analyze_transactions(result)

            # Calcula estatísticas
            self._calculate_stats(result)

            logger.info(f"DAST analysis completed: {len(result.findings)} findings")

        except Exception as e:
            logger.error(f"Error during DAST analysis: {e}")
            raise

        return result

    async def _analyze_transactions(self, result: DASTResult) -> None:
        """Analisa todas as transações capturadas."""
        http_requests = set()
        domains = set()

        for transaction in result.transactions:
            url = transaction.request.url
            parsed_url = urlparse(url)

            domains.add(parsed_url.netloc)

            # Verifica HTTP não criptografado
            if parsed_url.scheme == 'http':
                http_requests.add(url)
                result.findings.append(DASTFinding(
                    severity="high",
                    category="Unencrypted Communication",
                    title="Unencrypted HTTP Request",
                    description="Application is sending requests over unencrypted HTTP",
                    url=url,
                    cwe_id=319,
                    owasp_category="MASVS-NETWORK-1",
                    remediation="Use HTTPS for all network communications"
                ))

            # Verifica dados sensíveis no request
            if transaction.request.body:
                sensitive_findings = self.sensitive_detector.detect(
                    transaction.request.body,
                    context="Request Body"
                )
                for finding in sensitive_findings:
                    finding.url = url
                    result.findings.append(finding)

            # Verifica headers de segurança na response
            if transaction.response:
                header_findings = self.headers_validator.validate(
                    transaction.response.headers,
                    url
                )
                result.findings.extend(header_findings)

                # Verifica dados sensíveis no response
                if transaction.response.body:
                    sensitive_findings = self.sensitive_detector.detect(
                        transaction.response.body,
                        context="Response Body"
                    )
                    for finding in sensitive_findings:
                        finding.url = url
                        result.findings.append(finding)

        # Metadados
        result.metadata['unique_domains'] = list(domains)
        result.metadata['http_requests_count'] = len(http_requests)
        result.metadata['total_transactions'] = len(result.transactions)

    def _calculate_stats(self, result: DASTResult) -> None:
        """Calcula estatísticas."""
        result.stats = {
            'total_findings': len(result.findings),
            'critical': sum(1 for f in result.findings if f.severity == 'critical'),
            'high': sum(1 for f in result.findings if f.severity == 'high'),
            'medium': sum(1 for f in result.findings if f.severity == 'medium'),
            'low': sum(1 for f in result.findings if f.severity == 'low'),
            'transactions': len(result.transactions),
        }

        # Agrupa por categoria
        categories = {}
        for finding in result.findings:
            categories[finding.category] = categories.get(finding.category, 0) + 1

        result.stats['by_category'] = categories

    def export_har(self, output_path: str) -> None:
        """Exporta captura para formato HAR."""
        self.proxy_handler.export_har(output_path)
