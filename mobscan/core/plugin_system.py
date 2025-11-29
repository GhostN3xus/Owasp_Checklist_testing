"""
Plugin System - Sistema extensível de plugins para MOBSCAN.

Permite adicionar funcionalidades através de plugins sem modificar
o código core. Suporta três tipos de plugins:
- Analyzer: Análise customizada
- Reporter: Formatos de relatório customizados
- Hook: Interceptar e modificar o fluxo de execução
"""

import importlib.util
import inspect
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Type, Callable
from enum import Enum

logger = logging.getLogger(__name__)


class PluginType(Enum):
    """Tipos de plugins suportados."""
    ANALYZER = "analyzer"
    REPORTER = "reporter"
    HOOK = "hook"
    CUSTOM = "custom"


class PluginStatus(Enum):
    """Status de um plugin."""
    LOADED = "loaded"
    ACTIVE = "active"
    INACTIVE = "inactive"
    ERROR = "error"


@dataclass
class PluginMetadata:
    """Metadados de um plugin."""
    name: str
    version: str
    author: str
    description: str
    plugin_type: PluginType
    dependencies: List[str] = field(default_factory=list)
    config_schema: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PluginInfo:
    """Informações sobre um plugin carregado."""
    metadata: PluginMetadata
    instance: Any
    status: PluginStatus
    loaded_at: datetime = field(default_factory=datetime.now)
    error: Optional[str] = None


class Plugin(ABC):
    """
    Classe base para todos os plugins.

    Todos os plugins devem herdar desta classe e implementar
    os métodos abstratos.
    """

    @abstractmethod
    def get_metadata(self) -> PluginMetadata:
        """Retorna metadados do plugin."""
        pass

    @abstractmethod
    async def initialize(self, config: Dict[str, Any]) -> bool:
        """
        Inicializa o plugin.

        Args:
            config: Configuração do plugin

        Returns:
            True se inicializado com sucesso
        """
        pass

    @abstractmethod
    async def cleanup(self) -> None:
        """Cleanup ao descarregar o plugin."""
        pass

    def validate_config(self, config: Dict[str, Any]) -> bool:
        """
        Valida configuração do plugin.

        Args:
            config: Configuração a validar

        Returns:
            True se válida
        """
        return True


class AnalyzerPlugin(Plugin):
    """
    Plugin de análise customizada.

    Permite adicionar novos tipos de análise ao MOBSCAN.
    """

    @abstractmethod
    async def analyze(self, target: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Executa análise customizada.

        Args:
            target: Alvo da análise (APK, IPA, etc)
            context: Contexto da análise

        Returns:
            Resultados da análise
        """
        pass

    def get_supported_targets(self) -> List[str]:
        """Retorna tipos de alvos suportados (apk, ipa, etc)."""
        return ["apk", "ipa"]


class ReporterPlugin(Plugin):
    """
    Plugin de relatório customizado.

    Permite adicionar novos formatos de saída.
    """

    @abstractmethod
    async def generate_report(self, data: Dict[str, Any],
                             output_path: str) -> bool:
        """
        Gera relatório customizado.

        Args:
            data: Dados para o relatório
            output_path: Caminho de saída

        Returns:
            True se gerado com sucesso
        """
        pass

    def get_format(self) -> str:
        """Retorna o formato do relatório (pdf, html, etc)."""
        return "custom"


class HookPlugin(Plugin):
    """
    Plugin de hook.

    Permite interceptar e modificar o fluxo de execução.
    """

    @abstractmethod
    async def on_before_scan(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Executado antes do scan."""
        return context

    @abstractmethod
    async def on_after_scan(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Executado após o scan."""
        return results

    async def on_error(self, error: Exception, context: Dict[str, Any]) -> None:
        """Executado quando ocorre erro."""
        pass


class PluginManager:
    """
    Gerenciador de plugins.

    Responsável por carregar, descarregar e gerenciar plugins.
    """

    def __init__(self):
        self._plugins: Dict[str, PluginInfo] = {}
        self._plugin_dirs: List[Path] = []
        self._hooks: Dict[str, List[Callable]] = {}

    def add_plugin_directory(self, path: str) -> None:
        """
        Adiciona diretório para buscar plugins.

        Args:
            path: Caminho do diretório
        """
        plugin_dir = Path(path)
        if plugin_dir.exists() and plugin_dir.is_dir():
            self._plugin_dirs.append(plugin_dir)
            logger.info(f"Plugin directory added: {path}")
        else:
            logger.warning(f"Plugin directory not found: {path}")

    async def load_plugin(self, plugin_path: str,
                         config: Dict[str, Any] = None) -> bool:
        """
        Carrega um plugin de um arquivo.

        Args:
            plugin_path: Caminho do arquivo do plugin
            config: Configuração do plugin

        Returns:
            True se carregado com sucesso
        """
        try:
            # Carrega módulo
            spec = importlib.util.spec_from_file_location(
                "plugin_module",
                plugin_path
            )
            if spec is None or spec.loader is None:
                raise ValueError(f"Invalid plugin file: {plugin_path}")

            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            # Encontra classe do plugin
            plugin_class = None
            for name, obj in inspect.getmembers(module, inspect.isclass):
                if (issubclass(obj, Plugin) and
                    obj not in [Plugin, AnalyzerPlugin, ReporterPlugin, HookPlugin]):
                    plugin_class = obj
                    break

            if plugin_class is None:
                raise ValueError("No plugin class found in module")

            # Instancia plugin
            plugin_instance = plugin_class()
            metadata = plugin_instance.get_metadata()

            # Valida configuração
            if config and not plugin_instance.validate_config(config):
                raise ValueError("Invalid plugin configuration")

            # Inicializa plugin
            if not await plugin_instance.initialize(config or {}):
                raise RuntimeError("Plugin initialization failed")

            # Registra plugin
            plugin_info = PluginInfo(
                metadata=metadata,
                instance=plugin_instance,
                status=PluginStatus.ACTIVE
            )

            self._plugins[metadata.name] = plugin_info
            logger.info(f"Plugin loaded: {metadata.name} v{metadata.version}")

            return True

        except Exception as e:
            logger.error(f"Error loading plugin from {plugin_path}: {e}")
            return False

    async def unload_plugin(self, plugin_name: str) -> bool:
        """
        Descarrega um plugin.

        Args:
            plugin_name: Nome do plugin

        Returns:
            True se descarregado com sucesso
        """
        if plugin_name not in self._plugins:
            logger.warning(f"Plugin not found: {plugin_name}")
            return False

        try:
            plugin_info = self._plugins[plugin_name]
            await plugin_info.instance.cleanup()
            del self._plugins[plugin_name]
            logger.info(f"Plugin unloaded: {plugin_name}")
            return True

        except Exception as e:
            logger.error(f"Error unloading plugin {plugin_name}: {e}")
            return False

    def get_plugin(self, plugin_name: str) -> Optional[Plugin]:
        """
        Retorna instância de um plugin.

        Args:
            plugin_name: Nome do plugin

        Returns:
            Instância do plugin ou None
        """
        plugin_info = self._plugins.get(plugin_name)
        return plugin_info.instance if plugin_info else None

    def get_plugins_by_type(self, plugin_type: PluginType) -> List[Plugin]:
        """
        Retorna todos os plugins de um tipo específico.

        Args:
            plugin_type: Tipo de plugin

        Returns:
            Lista de plugins
        """
        return [
            info.instance
            for info in self._plugins.values()
            if info.metadata.plugin_type == plugin_type
            and info.status == PluginStatus.ACTIVE
        ]

    def list_plugins(self) -> List[PluginInfo]:
        """Retorna lista de todos os plugins carregados."""
        return list(self._plugins.values())

    async def discover_plugins(self) -> List[str]:
        """
        Descobre plugins nos diretórios configurados.

        Returns:
            Lista de caminhos de plugins encontrados
        """
        discovered = []

        for plugin_dir in self._plugin_dirs:
            for plugin_file in plugin_dir.glob("*.py"):
                if plugin_file.stem.startswith("plugin_"):
                    discovered.append(str(plugin_file))

        logger.info(f"Discovered {len(discovered)} plugins")
        return discovered

    async def load_all_plugins(self, config: Dict[str, Dict[str, Any]] = None) -> int:
        """
        Carrega todos os plugins descobertos.

        Args:
            config: Configurações por plugin

        Returns:
            Número de plugins carregados
        """
        plugins = await self.discover_plugins()
        loaded = 0

        for plugin_path in plugins:
            plugin_name = Path(plugin_path).stem
            plugin_config = config.get(plugin_name, {}) if config else {}

            if await self.load_plugin(plugin_path, plugin_config):
                loaded += 1

        logger.info(f"Loaded {loaded}/{len(plugins)} plugins")
        return loaded

    def register_hook(self, hook_name: str, callback: Callable) -> None:
        """
        Registra um hook.

        Args:
            hook_name: Nome do hook
            callback: Função callback
        """
        if hook_name not in self._hooks:
            self._hooks[hook_name] = []

        self._hooks[hook_name].append(callback)
        logger.debug(f"Hook registered: {hook_name}")

    async def execute_hooks(self, hook_name: str, *args, **kwargs) -> List[Any]:
        """
        Executa todos os hooks de um tipo.

        Args:
            hook_name: Nome do hook
            *args: Argumentos posicionais
            **kwargs: Argumentos nomeados

        Returns:
            Lista de resultados
        """
        results = []

        if hook_name in self._hooks:
            for hook in self._hooks[hook_name]:
                try:
                    if inspect.iscoroutinefunction(hook):
                        result = await hook(*args, **kwargs)
                    else:
                        result = hook(*args, **kwargs)
                    results.append(result)
                except Exception as e:
                    logger.error(f"Error executing hook {hook_name}: {e}")

        return results

    def get_stats(self) -> Dict[str, Any]:
        """Retorna estatísticas do gerenciador de plugins."""
        return {
            "total_plugins": len(self._plugins),
            "active_plugins": sum(
                1 for p in self._plugins.values()
                if p.status == PluginStatus.ACTIVE
            ),
            "plugin_types": {
                ptype.value: len(self.get_plugins_by_type(ptype))
                for ptype in PluginType
            },
            "hooks": {name: len(hooks) for name, hooks in self._hooks.items()}
        }


# Singleton global
_global_plugin_manager: Optional[PluginManager] = None


def get_plugin_manager() -> PluginManager:
    """Retorna a instância global do gerenciador de plugins."""
    global _global_plugin_manager
    if _global_plugin_manager is None:
        _global_plugin_manager = PluginManager()
    return _global_plugin_manager
