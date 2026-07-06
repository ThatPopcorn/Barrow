"""The highway.

One publish point, many subscribers. Sessions publish Messages; handlers
subscribe by `kind` and decide who receives them. Nothing in the system
talks to anything else directly -- everything goes through here.

Extension point: bus.subscribe("mykind", my_handler). Subscribing to "*"
receives every message (useful for logging, moderation, metrics).
"""
from __future__ import annotations

from typing import Awaitable, Callable

from .message import Message

Handler = Callable[[Message], Awaitable[None]]


class MessageBus:
    def __init__(self) -> None:
        self._handlers: dict[str, list[Handler]] = {}

    def subscribe(self, kind: str, handler: Handler) -> None:
        """Register a coroutine to receive all messages of `kind` ("*" = all)."""
        self._handlers.setdefault(kind, []).append(handler)

    async def publish(self, msg: Message) -> None:
        """Push a message onto the highway. Handlers run sequentially so
        message ordering is preserved (a deliberate choice: chat needs
        order more than it needs parallel dispatch)."""
        for handler in self._handlers.get(msg.kind, []):
            await handler(msg)
        for handler in self._handlers.get("*", []):
            await handler(msg)
