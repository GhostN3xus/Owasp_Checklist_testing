#!/usr/bin/env python3
"""
MOBSCAN Configuration Manager
Gerencia arquivos de configuração (criar, carregar, validar)
"""

import yaml
from pathlib import Path
from typing import Dict, Any, Tuple, List
import logging

logger = logging.getLogger(__name__)


class ConfigManager:
    """Gerenciador de configuração do MOBSCAN"""

    DEFAULT_CONFIG = {
        'scan': {
            'modules': ['sast', 'dast', 'sca', 'frida'],
            'intensity': 'normal',
            'output_dir': './mobscan_results',
            'parallel': True,
            'timeout': 3600,
            'continue_on_error': False
        },
        'sast': {
            'enabled': True,
            'rules': [
                'hardcoded_secrets',
                'weak_crypto',
                'insecure_storage',
                'manifest_issues',
                'permission_issues',
                'exported_components'
            ],
            'min_severity': 'medium',
            'exclude_paths': [
                'test/**',
                'tests/**',
                'build/**',
                'dist/**'
            ],
            'manifest': {
                'check_debuggable': True,
                'check_backup': True,
                'check_exported': True,
                'check_permissions': True
            },
            'include_code_snippets': True,
            'max_snippet_lines': 5
        },
        'dast': {
            'enabled': True,
            'proxy': {
                'host': 'localhost',
                'port': 8080,
                'ssl_insecure': False
            },
            'duration': 300,
            'export_har': True,
            'sensitive_data': {
                'enabled': True,
                'patterns': [
                    'credit_card',
                    'ssn',
                    'api_key',
                    'password'
                ]
            }
        },
        'sca': {
            'enabled': True,
            'check_vulnerabilities': True,
            'check_licenses': True,
            'check_outdated': True,
            'generate_sbom': True,
            'sbom_format': 'cyclonedx',
            'min_severity': 'medium',
            'exclude_packages': []
        },
        'frida': {
            'enabled': True,
            'device': 'usb',
            'scripts': [
                'ssl_pinning_bypass',
                'root_detection_bypass',
                'crypto_monitor',
                'storage_monitor'
            ],
            'auto_reload': True,
            'timeout': 300
        },
        'reports': {
            'formats': ['html', 'json', 'markdown'],
            'output_dir': './reports',
            'include_evidence': True,
            'include_remediation': True
        },
        'logging': {
            'level': 'INFO',
            'file': None,
            'format': 'standard'
        }
    }

    def __init__(self):
        """Inicializa o gerenciador de configuração"""
        pass

    def create_default_config(self, output_file: str = 'mobscan_config.yaml') -> str:
        """
        Cria arquivo de configuração padrão

        Args:
            output_file: Caminho do arquivo de saída

        Returns:
            Caminho absoluto do arquivo criado
        """
        filepath = Path(output_file).resolve()

        # Cria configuração com comentários
        config_content = self._generate_config_with_comments()

        # Salva arquivo
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(config_content)

        logger.info(f"Default configuration created: {filepath}")
        return str(filepath)

    def load_config(self, config_file: str) -> Dict[str, Any]:
        """
        Carrega arquivo de configuração

        Args:
            config_file: Caminho do arquivo de configuração

        Returns:
            Dicionário com a configuração

        Raises:
            FileNotFoundError: Se o arquivo não existir
            yaml.YAMLError: Se o arquivo não for YAML válido
        """
        filepath = Path(config_file)

        if not filepath.exists():
            raise FileNotFoundError(f"Configuration file not found: {config_file}")

        with open(filepath, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)

        logger.info(f"Configuration loaded from: {filepath}")
        return config

    def validate_config(self, config_file: str) -> Tuple[bool, List[str]]:
        """
        Valida arquivo de configuração

        Args:
            config_file: Caminho do arquivo de configuração

        Returns:
            Tupla (is_valid, errors) onde:
            - is_valid: True se a configuração é válida
            - errors: Lista de erros encontrados
        """
        errors = []

        try:
            config = self.load_config(config_file)
        except FileNotFoundError as e:
            return False, [str(e)]
        except yaml.YAMLError as e:
            return False, [f"Invalid YAML syntax: {e}"]

        # Valida seções obrigatórias
        required_sections = ['scan']
        for section in required_sections:
            if section not in config:
                errors.append(f"Missing required section: '{section}'")

        # Valida scan section
        if 'scan' in config:
            scan_config = config['scan']

            # Valida modules
            if 'modules' in scan_config:
                valid_modules = {'sast', 'dast', 'sca', 'frida'}
                modules = scan_config['modules']

                if not isinstance(modules, list):
                    errors.append("'scan.modules' must be a list")
                else:
                    invalid_modules = set(modules) - valid_modules
                    if invalid_modules:
                        errors.append(
                            f"Invalid modules: {invalid_modules}. "
                            f"Valid modules: {valid_modules}"
                        )

            # Valida intensity
            if 'intensity' in scan_config:
                valid_intensities = {'quick', 'normal', 'comprehensive'}
                intensity = scan_config['intensity']

                if intensity not in valid_intensities:
                    errors.append(
                        f"Invalid intensity: '{intensity}'. "
                        f"Valid options: {valid_intensities}"
                    )

            # Valida timeout
            if 'timeout' in scan_config:
                timeout = scan_config['timeout']
                if not isinstance(timeout, int) or timeout <= 0:
                    errors.append("'scan.timeout' must be a positive integer")

        # Valida severities
        valid_severities = {'info', 'low', 'medium', 'high', 'critical'}

        for section in ['sast', 'sca']:
            if section in config and 'min_severity' in config[section]:
                severity = config[section]['min_severity']
                if severity not in valid_severities:
                    errors.append(
                        f"Invalid {section}.min_severity: '{severity}'. "
                        f"Valid options: {valid_severities}"
                    )

        # Valida reports formats
        if 'reports' in config and 'formats' in config['reports']:
            valid_formats = {'json', 'html', 'markdown', 'pdf'}
            formats = config['reports']['formats']

            if not isinstance(formats, list):
                errors.append("'reports.formats' must be a list")
            else:
                invalid_formats = set(formats) - valid_formats
                if invalid_formats:
                    errors.append(
                        f"Invalid report formats: {invalid_formats}. "
                        f"Valid formats: {valid_formats}"
                    )

        is_valid = len(errors) == 0
        return is_valid, errors

    def merge_with_defaults(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Mescla configuração fornecida com valores padrão

        Args:
            config: Configuração parcial fornecida

        Returns:
            Configuração completa com defaults
        """
        merged = self.DEFAULT_CONFIG.copy()

        def deep_merge(base: dict, override: dict) -> dict:
            """Faz merge profundo de dicionários"""
            result = base.copy()
            for key, value in override.items():
                if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                    result[key] = deep_merge(result[key], value)
                else:
                    result[key] = value
            return result

        return deep_merge(merged, config)

    def _generate_config_with_comments(self) -> str:
        """Gera arquivo de configuração com comentários"""
        return """# MOBSCAN v1.1.0 - Configuration File
# Edit this file to customize your security scans

# ============================================================================
# SCAN CONFIGURATION
# ============================================================================
scan:
  # Modules to run (sast, dast, sca, frida)
  modules:
    - sast    # Static Application Security Testing
    - dast    # Dynamic Application Security Testing
    - sca     # Software Composition Analysis
    - frida   # Runtime Instrumentation

  # Scan intensity: quick, normal, comprehensive
  intensity: normal

  # Output directory for results
  output_dir: ./mobscan_results

  # Run modules in parallel
  parallel: true

  # Global timeout in seconds
  timeout: 3600

  # Continue if a module fails
  continue_on_error: false

# ============================================================================
# SAST - Static Application Security Testing
# ============================================================================
sast:
  enabled: true

  # Rules to apply
  rules:
    - hardcoded_secrets
    - weak_crypto
    - insecure_storage
    - manifest_issues
    - permission_issues
    - exported_components

  # Minimum severity to report (info, low, medium, high, critical)
  min_severity: medium

  # Paths to exclude from scanning
  exclude_paths:
    - test/**
    - tests/**
    - build/**
    - dist/**

  # AndroidManifest.xml checks
  manifest:
    check_debuggable: true
    check_backup: true
    check_exported: true
    check_permissions: true

  # Include code snippets in reports
  include_code_snippets: true
  max_snippet_lines: 5

# ============================================================================
# DAST - Dynamic Application Security Testing
# ============================================================================
dast:
  enabled: true

  # Proxy configuration
  proxy:
    host: localhost
    port: 8080
    ssl_insecure: false

  # Analysis duration in seconds
  duration: 300

  # Export network traffic as HAR file
  export_har: true

  # Sensitive data detection
  sensitive_data:
    enabled: true
    patterns:
      - credit_card
      - ssn
      - api_key
      - password

# ============================================================================
# SCA - Software Composition Analysis
# ============================================================================
sca:
  enabled: true

  # Check for known vulnerabilities
  check_vulnerabilities: true

  # Check licenses
  check_licenses: true

  # Check for outdated dependencies
  check_outdated: true

  # Generate SBOM (Software Bill of Materials)
  generate_sbom: true
  sbom_format: cyclonedx  # cyclonedx or spdx

  # Minimum severity to report
  min_severity: medium

  # Packages to exclude
  exclude_packages: []

# ============================================================================
# FRIDA - Runtime Instrumentation
# ============================================================================
frida:
  enabled: true

  # Device type: usb, network, or device_id
  device: usb

  # Frida scripts to load
  scripts:
    - ssl_pinning_bypass
    - root_detection_bypass
    - crypto_monitor
    - storage_monitor

  # Auto-reload scripts on changes
  auto_reload: true

  # Script execution timeout
  timeout: 300

# ============================================================================
# REPORTS
# ============================================================================
reports:
  # Output formats: json, html, markdown, pdf
  formats:
    - html
    - json
    - markdown

  # Output directory
  output_dir: ./reports

  # Include evidence in reports
  include_evidence: true

  # Include remediation steps
  include_remediation: true

# ============================================================================
# LOGGING
# ============================================================================
logging:
  # Log level: DEBUG, INFO, WARNING, ERROR, CRITICAL
  level: INFO

  # Log file (null for stdout only)
  file: null

  # Log format: standard, json, detailed
  format: standard
"""


def load_config_from_file(config_file: str) -> Dict[str, Any]:
    """
    Helper function to load configuration from file

    Args:
        config_file: Path to configuration file

    Returns:
        Configuration dictionary
    """
    manager = ConfigManager()
    config = manager.load_config(config_file)
    return manager.merge_with_defaults(config)
