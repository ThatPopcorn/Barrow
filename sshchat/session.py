"""Routing: for each message kind, decide WHO receives it.

Handlers never format text and never touch sockets -- they look up
recipients in the Registry and hand the untouched Message to each
recipient's session. Rendering is the session's job.

To add a feature (e.g. server-wide broadcast, moderation, logging),
write a handler and subscribe it. Nothing else changes.
"""
from __future__ import annotations

from .bus import MessageBus
from .message import DM, PRESENCE, ROOM, SYSTEM, Message
from .state import Registry


class CoreRouter:
    def __init__(self, bus: MessageBus, registry: Registry) -> None:
        self.registry = registry
        bus.subscribe(ROOM, self.on_room)
        bus.subscribe(DM, self.on_dm)
        bus.subscribe(PRESENCE, self.on_presence)
        bus.subscribe(SYSTEM, self.on_system)
        self._bus = bus

    async def on_room(self, msg: Message) -> None:
        """Room message -> every member of the room (including sender,
        which doubles as delivery confirmation)."""
        for name in self.registry.members(msg.target):
            session = self.registry.get_user(name)
            if session:
                session.deliver(msg)

    async def on_dm(self, msg: Message) -> None:
        """DM -> the target, plus an echo back to the sender.
        Unknown target -> a system error back to the sender only."""
        target = self.registry.get_user(msg.target)
        sender = self.registry.get_user(msg.sender)
        if target is None:
            if sender:
                sender.deliver(Message(SYSTEM, "server", msg.sender,
                                       f"no such user: {msg.target}"))
            return
        target.deliver(msg)
        if sender and msg.sender != msg.target:
            sender.deliver(msg)

    async def on_presence(self, msg: Message) -> None:
        """Join/leave notice -> everyone in the affected room."""
        for name in self.registry.members(msg.target):
            session = self.registry.get_user(name)
            if session:
                session.deliver(msg)

    async def on_system(self, msg: Message) -> None:
        """Server notice -> exactly one user."""
        session = self.registry.get_user(msg.target)
        if session:
            session.deliver(msg)
