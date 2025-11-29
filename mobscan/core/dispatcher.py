"""
Event Dispatcher - Sistema de pub/sub para comunicação entre componentes.

Este módulo implementa um sistema de eventos assíncrono que permite
comunicação desacoplada entre os diferentes módulos do MOBSCAN.
"""

import asyncio
from typing import Dict, List, Callable, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class EventPriority(Enum):
    """Prioridade de eventos."""
    LOW = 0
    NORMAL = 1
    HIGH = 2
    CRITICAL = 3


@dataclass
class Event:
    """Representa um evento no sistema."""
    name: str
    data: Dict[str, Any]
    timestamp: datetime = field(default_factory=datetime.now)
    priority: EventPriority = EventPriority.NORMAL
    source: Optional[str] = None
    correlation_id: Optional[str] = None


class EventDispatcher:
    """
    Sistema de despacho de eventos assíncrono.

    Permite que componentes se inscrevam em eventos e sejam notificados
    quando esses eventos ocorrem, facilitando a comunicação desacoplada.

    Exemplo:
        >>> dispatcher = EventDispatcher()
        >>> await dispatcher.subscribe("scan.started", handler_function)
        >>> await dispatcher.emit("scan.started", {"app": "example.apk"})
    """

    def __init__(self):
        self._subscribers: Dict[str, List[Callable]] = {}
        self._middleware: List[Callable] = []
        self._event_history: List[Event] = []
        self._max_history = 1000
        self._stats = {
            "events_emitted": 0,
            "events_processed": 0,
            "errors": 0
        }

    async def subscribe(self, event_name: str, handler: Callable,
                       priority: int = 0) -> None:
        """
        Inscreve um handler para um evento específico.

        Args:
            event_name: Nome do evento
            handler: Função callback a ser chamada
            priority: Prioridade do handler (maior = executado primeiro)
        """
        if event_name not in self._subscribers:
            self._subscribers[event_name] = []

        self._subscribers[event_name].append({
            'handler': handler,
            'priority': priority
        })

        # Ordena por prioridade (maior primeiro)
        self._subscribers[event_name].sort(
            key=lambda x: x['priority'],
            reverse=True
        )

        logger.debug(f"Handler subscribed to '{event_name}' with priority {priority}")

    async def unsubscribe(self, event_name: str, handler: Callable) -> bool:
        """
        Remove um handler de um evento.

        Args:
            event_name: Nome do evento
            handler: Handler a ser removido

        Returns:
            True se o handler foi removido, False caso contrário
        """
        if event_name in self._subscribers:
            original_length = len(self._subscribers[event_name])
            self._subscribers[event_name] = [
                sub for sub in self._subscribers[event_name]
                if sub['handler'] != handler
            ]
            removed = original_length > len(self._subscribers[event_name])
            if removed:
                logger.debug(f"Handler unsubscribed from '{event_name}'")
            return removed
        return False

    def add_middleware(self, middleware: Callable) -> None:
        """
        Adiciona middleware para processar eventos antes da emissão.

        Args:
            middleware: Função que recebe e retorna um Event
        """
        self._middleware.append(middleware)
        logger.debug("Middleware added to event dispatcher")

    async def emit(self, event_name: str, data: Dict[str, Any] = None,
                   priority: EventPriority = EventPriority.NORMAL,
                   source: Optional[str] = None,
                   correlation_id: Optional[str] = None) -> None:
        """
        Emite um evento para todos os subscribers.

        Args:
            event_name: Nome do evento
            data: Dados do evento
            priority: Prioridade do evento
            source: Origem do evento
            correlation_id: ID para rastreamento
        """
        event = Event(
            name=event_name,
            data=data or {},
            priority=priority,
            source=source,
            correlation_id=correlation_id
        )

        # Aplica middleware
        for middleware in self._middleware:
            try:
                event = await middleware(event) if asyncio.iscoroutinefunction(middleware) else middleware(event)
            except Exception as e:
                logger.error(f"Middleware error: {e}")
                self._stats["errors"] += 1

        # Adiciona ao histórico
        self._event_history.append(event)
        if len(self._event_history) > self._max_history:
            self._event_history.pop(0)

        self._stats["events_emitted"] += 1

        # Notifica subscribers
        if event_name in self._subscribers:
            tasks = []
            for subscriber in self._subscribers[event_name]:
                handler = subscriber['handler']

                if asyncio.iscoroutinefunction(handler):
                    tasks.append(self._safe_call_async(handler, event))
                else:
                    tasks.append(self._safe_call_sync(handler, event))

            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)

        logger.debug(f"Event '{event_name}' emitted with {len(self._subscribers.get(event_name, []))} subscribers")

    async def _safe_call_async(self, handler: Callable, event: Event) -> None:
        """Executa handler assíncrono com tratamento de erros."""
        try:
            await handler(event)
            self._stats["events_processed"] += 1
        except Exception as e:
            logger.error(f"Error in async handler for '{event.name}': {e}")
            self._stats["errors"] += 1

    async def _safe_call_sync(self, handler: Callable, event: Event) -> None:
        """Executa handler síncrono com tratamento de erros."""
        try:
            handler(event)
            self._stats["events_processed"] += 1
        except Exception as e:
            logger.error(f"Error in sync handler for '{event.name}': {e}")
            self._stats["errors"] += 1

    def get_history(self, event_name: Optional[str] = None,
                   limit: int = 100) -> List[Event]:
        """
        Retorna histórico de eventos.

        Args:
            event_name: Filtrar por nome de evento (opcional)
            limit: Número máximo de eventos

        Returns:
            Lista de eventos
        """
        history = self._event_history

        if event_name:
            history = [e for e in history if e.name == event_name]

        return history[-limit:]

    def get_stats(self) -> Dict[str, Any]:
        """Retorna estatísticas do dispatcher."""
        return {
            **self._stats,
            "subscribers": {
                event: len(handlers)
                for event, handlers in self._subscribers.items()
            },
            "middleware_count": len(self._middleware),
            "history_size": len(self._event_history)
        }

    def clear_history(self) -> None:
        """Limpa o histórico de eventos."""
        self._event_history.clear()
        logger.debug("Event history cleared")

    async def emit_and_wait(self, event_name: str, data: Dict[str, Any] = None,
                           timeout: float = 30.0) -> List[Any]:
        """
        Emite evento e aguarda todas as respostas.

        Args:
            event_name: Nome do evento
            data: Dados do evento
            timeout: Timeout em segundos

        Returns:
            Lista com resultados dos handlers
        """
        results = []

        if event_name in self._subscribers:
            tasks = []
            for subscriber in self._subscribers[event_name]:
                handler = subscriber['handler']
                event = Event(name=event_name, data=data or {})

                if asyncio.iscoroutinefunction(handler):
                    tasks.append(handler(event))
                else:
                    # Wrap sync handler in async
                    async def wrapped():
                        return handler(event)
                    tasks.append(wrapped())

            if tasks:
                results = await asyncio.wait_for(
                    asyncio.gather(*tasks, return_exceptions=True),
                    timeout=timeout
                )

        return results


# Singleton global para facilitar o uso
_global_dispatcher: Optional[EventDispatcher] = None


def get_dispatcher() -> EventDispatcher:
    """Retorna a instância global do dispatcher."""
    global _global_dispatcher
    if _global_dispatcher is None:
        _global_dispatcher = EventDispatcher()
    return _global_dispatcher
