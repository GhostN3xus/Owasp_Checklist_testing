"""
Comprehensive Test Suite for MOBSCAN.

Testes abrangentes para todos os componentes principais.
"""

import pytest
import asyncio
from pathlib import Path
import tempfile
import json


# ============================================================================
# EVENT DISPATCHER TESTS
# ============================================================================

class TestEventDispatcher:
    """Testes para Event Dispatcher."""

    @pytest.mark.asyncio
    async def test_subscribe_and_emit(self):
        """Testa inscrição e emissão de eventos."""
        from mobscan.core.dispatcher import EventDispatcher, Event

        dispatcher = EventDispatcher()
        received_events = []

        async def handler(event: Event):
            received_events.append(event)

        await dispatcher.subscribe("test.event", handler)
        await dispatcher.emit("test.event", {"message": "Hello"})

        # Aguarda processamento assíncrono
        await asyncio.sleep(0.1)

        assert len(received_events) == 1
        assert received_events[0].name == "test.event"
        assert received_events[0].data["message"] == "Hello"

    @pytest.mark.asyncio
    async def test_unsubscribe(self):
        """Testa desinscrição de eventos."""
        from mobscan.core.dispatcher import EventDispatcher

        dispatcher = EventDispatcher()
        call_count = 0

        async def handler(event):
            nonlocal call_count
            call_count += 1

        await dispatcher.subscribe("test.event", handler)
        await dispatcher.emit("test.event", {})
        await asyncio.sleep(0.1)

        assert call_count == 1

        await dispatcher.unsubscribe("test.event", handler)
        await dispatcher.emit("test.event", {})
        await asyncio.sleep(0.1)

        assert call_count == 1  # Não incrementou

    @pytest.mark.asyncio
    async def test_event_history(self):
        """Testa histórico de eventos."""
        from mobscan.core.dispatcher import EventDispatcher

        dispatcher = EventDispatcher()

        await dispatcher.emit("event.1", {"id": 1})
        await dispatcher.emit("event.2", {"id": 2})

        history = dispatcher.get_history()

        assert len(history) == 2
        assert history[0].name == "event.1"
        assert history[1].name == "event.2"


# ============================================================================
# PLUGIN SYSTEM TESTS
# ============================================================================

class TestPluginSystem:
    """Testes para Plugin System."""

    @pytest.mark.asyncio
    async def test_plugin_metadata(self):
        """Testa criação de plugin metadata."""
        from mobscan.core.plugin_system import PluginMetadata, PluginType

        metadata = PluginMetadata(
            name="test_plugin",
            version="1.0.0",
            author="Test Author",
            description="Test plugin",
            plugin_type=PluginType.ANALYZER
        )

        assert metadata.name == "test_plugin"
        assert metadata.version == "1.0.0"
        assert metadata.plugin_type == PluginType.ANALYZER

    def test_plugin_manager_stats(self):
        """Testa estatísticas do plugin manager."""
        from mobscan.core.plugin_system import PluginManager

        manager = PluginManager()
        stats = manager.get_stats()

        assert 'total_plugins' in stats
        assert 'active_plugins' in stats
        assert 'plugin_types' in stats


# ============================================================================
# SAST ENGINE TESTS
# ============================================================================

class TestSASTEngine:
    """Testes para SAST Engine."""

    def test_secret_detector(self):
        """Testa detecção de secrets."""
        from mobscan.modules.sast.sast_engine import SecretDetector

        detector = SecretDetector()

        test_code = '''
        String apiKey = "api_key: AIzaSyDxxxxxxxxxxxxxxxxxxxxxxxxxxx";
        String password = "password: MySecretPassword123";
        '''

        findings = detector.detect(test_code, "test.java")

        assert len(findings) > 0
        assert any(f.category == "Hardcoded Secrets" for f in findings)

    def test_weak_crypto_detector(self):
        """Testa detecção de criptografia fraca."""
        from mobscan.modules.sast.sast_engine import WeakCryptoDetector

        detector = WeakCryptoDetector()

        test_code = '''
        MessageDigest md = MessageDigest.getInstance("MD5");
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        '''

        findings = detector.detect(test_code, "test.java")

        assert len(findings) >= 2
        assert any("MD5" in f.title for f in findings)
        assert any("ECB" in f.title for f in findings)

    def test_insecure_storage_detector(self):
        """Testa detecção de armazenamento inseguro."""
        from mobscan.modules.sast.sast_engine import InsecureStorageDetector

        detector = InsecureStorageDetector()

        test_code = '''
        SharedPreferences prefs = getSharedPreferences("data", MODE_WORLD_READABLE);
        File external = Environment.getExternalStorageDirectory();
        '''

        findings = detector.detect(test_code, "test.java")

        assert len(findings) > 0

    @pytest.mark.asyncio
    async def test_sast_engine_scan(self):
        """Testa scan completo do SAST Engine."""
        from mobscan.modules.sast.sast_engine import SASTEngine

        # Cria APK de teste
        with tempfile.NamedTemporaryFile(suffix='.apk', delete=False) as f:
            apk_path = f.name

        engine = SASTEngine()

        try:
            result = await engine.scan(apk_path)

            assert result.app_path == apk_path
            assert 'total' in result.stats

        finally:
            Path(apk_path).unlink(missing_ok=True)


# ============================================================================
# DAST ENGINE TESTS
# ============================================================================

class TestDASTEngine:
    """Testes para DAST Engine."""

    def test_sensitive_data_detector(self):
        """Testa detecção de dados sensíveis."""
        from mobscan.modules.dast.dast_engine_enhanced import SensitiveDataDetector

        detector = SensitiveDataDetector()

        test_data = '''
        {
            "email": "user@example.com",
            "password": "secret123",
            "credit_card": "4111-1111-1111-1111"
        }
        '''

        findings = detector.detect(test_data, "Response")

        assert len(findings) >= 2
        assert any("email" in f.title.lower() for f in findings)

    def test_security_headers_validator(self):
        """Testa validação de headers de segurança."""
        from mobscan.modules.dast.dast_engine_enhanced import SecurityHeadersValidator

        validator = SecurityHeadersValidator()

        headers = {
            "Content-Type": "application/json"
        }

        findings = validator.validate(headers, "https://example.com")

        assert len(findings) > 0
        assert any("HSTS" in f.title for f in findings)

    @pytest.mark.asyncio
    async def test_dast_engine_analysis(self):
        """Testa análise DAST."""
        from mobscan.modules.dast.dast_engine_enhanced import DASTEngine

        engine = DASTEngine()

        result = await engine.start_analysis({
            'duration': 1  # 1 segundo para teste rápido
        })

        assert 'total_findings' in result.stats


# ============================================================================
# FRIDA ENGINE TESTS
# ============================================================================

class TestFridaEngine:
    """Testes para Frida Engine."""

    def test_list_hooks(self):
        """Testa listagem de hooks."""
        from mobscan.modules.frida.frida_engine import FridaEngine

        engine = FridaEngine()
        hooks = engine.list_hooks()

        assert len(hooks) > 0
        assert any(h.name == "Root Detection Bypass" for h in hooks)

    def test_get_hook(self):
        """Testa obtenção de hook específico."""
        from mobscan.modules.frida.frida_engine import FridaEngine

        engine = FridaEngine()
        hook = engine.get_hook('root_bypass')

        assert hook is not None
        assert hook.category == "bypass"

    @pytest.mark.asyncio
    async def test_frida_attach(self):
        """Testa anexação ao processo."""
        from mobscan.modules.frida.frida_engine import FridaEngine

        engine = FridaEngine()

        result = await engine.attach("com.test.app", hooks=['root_bypass'])

        assert result.app_identifier == "com.test.app"
        assert len(result.hooks_loaded) > 0


# ============================================================================
# SCA ENGINE TESTS
# ============================================================================

class TestSCAEngine:
    """Testes para SCA Engine."""

    def test_gradle_dependency_extraction(self):
        """Testa extração de dependências Gradle."""
        from mobscan.modules.sca.sca_engine import DependencyExtractor

        extractor = DependencyExtractor()

        gradle_content = '''
        dependencies {
            implementation 'com.squareup.okhttp3:okhttp:4.9.0'
            api 'com.google.code.gson:gson:2.8.6'
        }
        '''

        dependencies = extractor.extract_gradle(gradle_content)

        assert len(dependencies) == 2
        assert dependencies[0].name == "com.squareup.okhttp3:okhttp"
        assert dependencies[0].version == "4.9.0"

    def test_vulnerability_checker(self):
        """Testa verificação de vulnerabilidades."""
        from mobscan.modules.sca.sca_engine import VulnerabilityChecker, Dependency

        checker = VulnerabilityChecker()

        dep = Dependency(
            name="com.squareup.okhttp3:okhttp",
            version="4.9.0",
            ecosystem="maven"
        )

        vulnerabilities = checker.check_vulnerabilities(dep)

        # Verifica se encontra vulnerabilidades simuladas
        assert isinstance(vulnerabilities, list)

    def test_sbom_generation(self):
        """Testa geração de SBOM."""
        from mobscan.modules.sca.sca_engine import SBOMGenerator, Dependency

        generator = SBOMGenerator()

        dependencies = [
            Dependency(
                name="test-lib",
                version="1.0.0",
                ecosystem="maven"
            )
        ]

        sbom = generator.generate_sbom(dependencies)

        assert sbom['bomFormat'] == "CycloneDX"
        assert len(sbom['components']) == 1


# ============================================================================
# CONFIG VALIDATOR TESTS
# ============================================================================

class TestConfigValidator:
    """Testes para Config Validator."""

    def test_valid_config(self):
        """Testa validação de config válida."""
        from mobscan.utils.config_validator import ConfigValidator

        validator = ConfigValidator()

        # Cria config temporária
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("""
scan:
  modules: [sast, sca]
  intensity: normal

sast:
  enabled: true
  min_severity: medium
""")
            config_path = f.name

        try:
            is_valid = validator.validate_file(config_path)

            assert is_valid
            assert len(validator.get_errors('error')) == 0

        finally:
            Path(config_path).unlink(missing_ok=True)

    def test_invalid_config(self):
        """Testa validação de config inválida."""
        from mobscan.utils.config_validator import ConfigValidator

        validator = ConfigValidator()

        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("""
scan:
  modules: [invalid_module]
  intensity: wrong_value
""")
            config_path = f.name

        try:
            is_valid = validator.validate_file(config_path)

            assert not is_valid
            assert len(validator.get_errors('error')) > 0

        finally:
            Path(config_path).unlink(missing_ok=True)


# ============================================================================
# INTEGRATION TESTS
# ============================================================================

class TestIntegration:
    """Testes de integração."""

    @pytest.mark.asyncio
    async def test_full_scan_workflow(self):
        """Testa workflow completo de scan."""
        from mobscan.modules.sast.sast_engine import SASTEngine
        from mobscan.modules.sca.sca_engine import SCAEngine

        # Cria arquivo de teste
        with tempfile.NamedTemporaryFile(suffix='.apk', delete=False) as f:
            apk_path = f.name

        try:
            # SAST
            sast_engine = SASTEngine()
            sast_result = await sast_engine.scan(apk_path)

            assert sast_result is not None

            # SCA
            sca_engine = SCAEngine()
            sca_result = await sca_engine.scan(apk_path)

            assert sca_result is not None

        finally:
            Path(apk_path).unlink(missing_ok=True)


# ============================================================================
# PYTEST CONFIGURATION
# ============================================================================

def pytest_configure(config):
    """Configuração do pytest."""
    config.addinivalue_line(
        "markers", "asyncio: mark test as async"
    )
