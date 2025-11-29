# MOBSCAN Plugins

Este diretório contém plugins customizados para o MOBSCAN.

## Plugins Disponíveis

### URL Analyzer Plugin

**Arquivo:** `plugin_url_analyzer.py`

**Descrição:** Detecta URLs suspeitas e inseguras em aplicações mobile.

**Funcionalidades:**
- Detecta URLs HTTP (não HTTPS)
- Identifica domínios suspeitos (localhost, example.com, etc)
- Encontra IPs hardcoded
- Detecta endpoints de API expostos

**Configuração:**

```yaml
plugins:
  url_analyzer:
    check_http: true          # Verifica URLs HTTP
    check_suspicious: true    # Verifica domínios suspeitos
    custom_domains:           # Domínios customizados para verificar
      - "internal.company.com"
      - "staging.app.com"
```

**Uso:**

O plugin é carregado automaticamente quando presente no diretório `plugins/`. Para usar:

```bash
# O plugin será carregado automaticamente durante o scan
python -m mobscan scan app.apk --modules sast
```

**Severidades:**
- **Medium:** URLs HTTP, IPs hardcoded
- **Low:** URLs com domínios suspeitos

## Como Criar um Plugin Customizado

### 1. Estrutura Básica

Crie um arquivo `plugin_<nome>.py` neste diretório:

```python
from mobscan.core.plugin_system import (
    AnalyzerPlugin,
    PluginMetadata,
    PluginType
)

class MyCustomPlugin(AnalyzerPlugin):
    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="my_plugin",
            version="1.0.0",
            author="Your Name",
            description="Plugin description",
            plugin_type=PluginType.ANALYZER
        )

    async def initialize(self, config):
        return True

    async def analyze(self, target, context):
        # Sua lógica de análise
        return {
            "plugin": "my_plugin",
            "findings": []
        }

    async def cleanup(self):
        pass
```

### 2. Tipos de Plugins

#### Analyzer Plugin

Realiza análise customizada em aplicações:

```python
class MyAnalyzer(AnalyzerPlugin):
    async def analyze(self, target: str, context: Dict[str, Any]) -> Dict[str, Any]:
        # Retorna findings
        return {
            "findings": [
                {
                    "severity": "high",
                    "title": "Issue Title",
                    "description": "Issue description",
                    "file": "path/to/file",
                    "line": 42
                }
            ]
        }
```

#### Reporter Plugin

Gera relatórios em formatos customizados:

```python
class MyReporter(ReporterPlugin):
    async def generate_report(self, data: Dict[str, Any], output_path: str) -> bool:
        # Gera relatório customizado
        return True

    def get_format(self) -> str:
        return "custom_format"
```

#### Hook Plugin

Intercepta o fluxo de execução:

```python
class MyHook(HookPlugin):
    async def on_before_scan(self, context: Dict[str, Any]) -> Dict[str, Any]:
        # Executado antes do scan
        return context

    async def on_after_scan(self, results: Dict[str, Any]) -> Dict[str, Any]:
        # Executado após o scan
        return results
```

### 3. Boas Práticas

- **Nomenclatura:** Use `plugin_` como prefixo no nome do arquivo
- **Documentação:** Documente bem as funcionalidades e configurações
- **Validação:** Implemente `validate_config()` para validar configurações
- **Tratamento de Erros:** Use try/except para capturar exceções
- **Logging:** Use o módulo logging para debug
- **Performance:** Otimize para não impactar o tempo de scan

### 4. Teste Seu Plugin

```bash
# Teste o plugin com um APK
python -m mobscan scan test.apk --verbose

# Verifique se o plugin foi carregado
# Os logs devem mostrar: "Plugin loaded: <nome> v<versão>"
```

## Exemplos de Uso

### Exemplo 1: Plugin de Análise de Permissões

```python
class PermissionAnalyzer(AnalyzerPlugin):
    async def analyze(self, target, context):
        dangerous_permissions = [
            "READ_CONTACTS",
            "ACCESS_FINE_LOCATION",
            "CAMERA"
        ]

        findings = []
        # Analisa AndroidManifest.xml
        # Adiciona findings para permissões perigosas

        return {"findings": findings}
```

### Exemplo 2: Plugin de Relatório CSV

```python
class CSVReporter(ReporterPlugin):
    async def generate_report(self, data, output_path):
        import csv

        with open(output_path, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Severity', 'Title', 'File', 'Line'])

            for finding in data.get('findings', []):
                writer.writerow([
                    finding.get('severity'),
                    finding.get('title'),
                    finding.get('file'),
                    finding.get('line')
                ])

        return True

    def get_format(self):
        return "csv"
```

## Contribuindo

Para contribuir com novos plugins:

1. Crie seu plugin seguindo as diretrizes acima
2. Teste extensivamente
3. Documente no README
4. Abra um Pull Request

## Suporte

Para dúvidas sobre desenvolvimento de plugins:
- Consulte a documentação: `docs/PLUGIN_DEVELOPMENT.md`
- Veja exemplos: `examples/`
- Issues: https://github.com/your-org/mobscan/issues
