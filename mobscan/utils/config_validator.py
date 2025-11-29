"""
Configuration Validator - Valida arquivos de configuração MOBSCAN.

Valida estrutura, tipos e valores de configurações.
"""

from typing import Dict, Any, List, Optional
from dataclasses import dataclass
import yaml
import json
from pathlib import Path


@dataclass
class ValidationError:
    """Erro de validação."""
    path: str
    message: str
    severity: str  # error, warning


class ConfigValidator:
    """Validador de configuração."""

    SCHEMA = {
        'scan': {
            'type': dict,
            'required': False,
            'children': {
                'modules': {
                    'type': list,
                    'required': False,
                    'allowed_values': ['sast', 'dast', 'sca', 'frida']
                },
                'intensity': {
                    'type': str,
                    'required': False,
                    'allowed_values': ['quick', 'normal', 'comprehensive']
                },
                'output_dir': {
                    'type': str,
                    'required': False
                },
                'parallel': {
                    'type': bool,
                    'required': False
                }
            }
        },
        'sast': {
            'type': dict,
            'required': False,
            'children': {
                'enabled': {
                    'type': bool,
                    'required': False
                },
                'rules': {
                    'type': list,
                    'required': False
                },
                'exclude_paths': {
                    'type': list,
                    'required': False
                },
                'min_severity': {
                    'type': str,
                    'required': False,
                    'allowed_values': ['info', 'low', 'medium', 'high', 'critical']
                }
            }
        },
        'dast': {
            'type': dict,
            'required': False,
            'children': {
                'enabled': {
                    'type': bool,
                    'required': False
                },
                'proxy': {
                    'type': dict,
                    'required': False,
                    'children': {
                        'host': {'type': str, 'required': False},
                        'port': {'type': int, 'required': False}
                    }
                },
                'duration': {
                    'type': int,
                    'required': False
                },
                'export_har': {
                    'type': bool,
                    'required': False
                }
            }
        },
        'sca': {
            'type': dict,
            'required': False,
            'children': {
                'enabled': {
                    'type': bool,
                    'required': False
                },
                'check_vulnerabilities': {
                    'type': bool,
                    'required': False
                },
                'check_licenses': {
                    'type': bool,
                    'required': False
                },
                'generate_sbom': {
                    'type': bool,
                    'required': False
                }
            }
        },
        'frida': {
            'type': dict,
            'required': False,
            'children': {
                'enabled': {
                    'type': bool,
                    'required': False
                },
                'device_id': {
                    'type': str,
                    'required': False
                },
                'hooks': {
                    'type': list,
                    'required': False
                },
                'custom_scripts': {
                    'type': list,
                    'required': False
                }
            }
        },
        'report': {
            'type': dict,
            'required': False,
            'children': {
                'formats': {
                    'type': list,
                    'required': False,
                    'allowed_values': ['html', 'pdf', 'json', 'markdown', 'docx']
                },
                'output_dir': {
                    'type': str,
                    'required': False
                },
                'template': {
                    'type': str,
                    'required': False
                }
            }
        },
        'plugins': {
            'type': dict,
            'required': False,
            'children': {
                'enabled': {
                    'type': bool,
                    'required': False
                },
                'directories': {
                    'type': list,
                    'required': False
                }
            }
        }
    }

    def __init__(self):
        self.errors: List[ValidationError] = []

    def validate_file(self, config_path: str) -> bool:
        """
        Valida arquivo de configuração.

        Args:
            config_path: Caminho do arquivo

        Returns:
            True se válido
        """
        self.errors = []

        try:
            path = Path(config_path)

            if not path.exists():
                self.errors.append(ValidationError(
                    path="file",
                    message=f"Configuration file not found: {config_path}",
                    severity="error"
                ))
                return False

            # Carrega arquivo
            with open(path, 'r') as f:
                if path.suffix in ['.yaml', '.yml']:
                    config = yaml.safe_load(f)
                elif path.suffix == '.json':
                    config = json.load(f)
                else:
                    self.errors.append(ValidationError(
                        path="file",
                        message=f"Unsupported file format: {path.suffix}",
                        severity="error"
                    ))
                    return False

            # Valida configuração
            self._validate_dict(config, self.SCHEMA, "")

            return len([e for e in self.errors if e.severity == 'error']) == 0

        except Exception as e:
            self.errors.append(ValidationError(
                path="file",
                message=f"Error loading configuration: {e}",
                severity="error"
            ))
            return False

    def _validate_dict(self, config: Dict[str, Any],
                      schema: Dict[str, Any],
                      path: str) -> None:
        """Valida dicionário recursivamente."""
        for key, rules in schema.items():
            current_path = f"{path}.{key}" if path else key

            # Verifica se campo obrigatório existe
            if rules.get('required', False) and key not in config:
                self.errors.append(ValidationError(
                    path=current_path,
                    message=f"Required field missing: {key}",
                    severity="error"
                ))
                continue

            if key not in config:
                continue

            value = config[key]

            # Valida tipo
            expected_type = rules['type']
            if not isinstance(value, expected_type):
                self.errors.append(ValidationError(
                    path=current_path,
                    message=f"Invalid type for {key}: expected {expected_type.__name__}, got {type(value).__name__}",
                    severity="error"
                ))
                continue

            # Valida valores permitidos
            if 'allowed_values' in rules:
                if isinstance(value, list):
                    for item in value:
                        if item not in rules['allowed_values']:
                            self.errors.append(ValidationError(
                                path=current_path,
                                message=f"Invalid value '{item}' for {key}. Allowed: {rules['allowed_values']}",
                                severity="error"
                            ))
                else:
                    if value not in rules['allowed_values']:
                        self.errors.append(ValidationError(
                            path=current_path,
                            message=f"Invalid value '{value}' for {key}. Allowed: {rules['allowed_values']}",
                            severity="error"
                        ))

            # Valida filhos (nested dict)
            if 'children' in rules and isinstance(value, dict):
                self._validate_dict(value, rules['children'], current_path)

        # Verifica campos desconhecidos
        for key in config.keys():
            if key not in schema:
                current_path = f"{path}.{key}" if path else key
                self.errors.append(ValidationError(
                    path=current_path,
                    message=f"Unknown configuration field: {key}",
                    severity="warning"
                ))

    def get_errors(self, severity: Optional[str] = None) -> List[ValidationError]:
        """Retorna erros de validação."""
        if severity:
            return [e for e in self.errors if e.severity == severity]
        return self.errors

    def print_errors(self) -> None:
        """Imprime erros formatados."""
        if not self.errors:
            print("✓ Configuration is valid")
            return

        print(f"Found {len(self.errors)} validation issues:\n")

        for error in self.errors:
            symbol = "✗" if error.severity == "error" else "⚠"
            print(f"{symbol} [{error.severity.upper()}] {error.path}")
            print(f"  {error.message}\n")


def create_default_config(output_path: str) -> None:
    """
    Cria arquivo de configuração padrão.

    Args:
        output_path: Caminho de saída
    """
    default_config = {
        'scan': {
            'modules': ['sast', 'sca', 'dast'],
            'intensity': 'normal',
            'output_dir': './mobscan_results',
            'parallel': True
        },
        'sast': {
            'enabled': True,
            'rules': ['all'],
            'exclude_paths': [
                'test/**',
                'build/**'
            ],
            'min_severity': 'medium'
        },
        'dast': {
            'enabled': True,
            'proxy': {
                'host': 'localhost',
                'port': 8080
            },
            'duration': 60,
            'export_har': True
        },
        'sca': {
            'enabled': True,
            'check_vulnerabilities': True,
            'check_licenses': True,
            'generate_sbom': True
        },
        'frida': {
            'enabled': False,
            'device_id': 'usb',
            'hooks': [
                'root_bypass',
                'ssl_bypass',
                'crypto_monitor'
            ],
            'custom_scripts': []
        },
        'report': {
            'formats': ['html', 'json', 'pdf'],
            'output_dir': './reports',
            'template': None
        },
        'plugins': {
            'enabled': True,
            'directories': [
                './plugins'
            ]
        }
    }

    with open(output_path, 'w') as f:
        yaml.dump(default_config, f, default_flow_style=False, sort_keys=False)

    print(f"✓ Default configuration created: {output_path}")
