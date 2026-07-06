"""One connected user.

A Session does exactly three things:
  1. read lines from the SSH channel and turn them into Messages (or commands)
  2. render Messages it receives into text for this user's screen
  3. keep an outbound queue so one slow client never blocks the highway

Data flow, traced:
  bob types "hi" -> handle_line -> bus.publish(Message(ROOM, "bob", "lobby", "hi"))
  -> CoreRouter.on_room -> alice.deliver(msg) + bob.deliver(msg)
  -> each session formats it and its writer task sends it down the wire.
"""
from __future__ import annotations

import asyncio
import time

from .bus import MessageBus
from .message import DM, PRESENCE, ROOM, SYSTEM, Message
from .state import Registry

DEFAULT_ROOM = "lobby"

HELP = """commands:
  /join <room>        join (or create) a room; you leave your current one
  /msg <user> <text>  send a private message
  /who                list users in your current room
  /rooms              list active rooms
  /help               this text
  /quit               disconnect
anything else you type goes to your current room."""


class Session:
    def __init__(self, process, bus: MessageBus, registry: Registry) -> None:
        self.process = process              # asyncssh SSHServerProcess
        self.bus = bus
        self.registry = registry
        self.name: str = ""
        self.room: str = ""
        self.outbox: asyncio.Queue[str | None] = asyncio.Queue()
        self._writer_task: asyncio.Task | None = None

    # ------------------------------------------------------------------
    # lifecycle
    # ------------------------------------------------------------------
    async def run(self) -> None:
        wanted = self.process.get_extra_info("username") or "anon"
        self.name = self.registry.claim_name(wanted, self)
        self._writer_task = asyncio.create_task(self._writer())

        self._out(f"welcome, {self.name}. type /help for commands.")
        if self.name != wanted:
            self._out(f"(the name '{wanted}' was taken)")
        await self._join(DEFAULT_ROOM)

        try:
            async for raw in self.process.stdin:
                line = raw.rstrip("\r\n")
                if line.strip():
                    if not await self.handle_line(line):
                        break  # /quit
        except Exception:
            pass  # channel dropped; fall through to cleanup
        finally:
            await self._cleanup()

    async def _cleanup(self) -> None:
        if self.room:
            self.registry.leave_room(self.room, self.name)
            await self.bus.publish(Message(PRESENCE, self.name, self.room, "leave"))
        self.registry.release_name(self.name)
        await self.outbox.put(None)  # stop the writer
        if self._writer_task:
            await self._writer_task
        try:
            self.process.exit(0)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # input: lines -> Messages on the bus
    # ------------------------------------------------------------------
    async def handle_line(self, line: str) -> bool:
        """Returns False when the session should end."""
        if not line.startswith("/"):
            # Plain text -> current room. The body is passed through verbatim.
            await self.bus.publish(Message(ROOM, self.name, self.room, line))
            return True

        cmd, _, rest = line.partition(" ")
        cmd, rest = cmd.lower(), rest.strip()

        if cmd == "/join":
            if not rest:
                self._out("usage: /join <room>")
            else:
                await self._join(rest.lstrip("#").lower())
        elif cmd == "/msg":
            user, _, text = rest.partition(" ")
            if not user or not text.strip():
                self._out("usage: /msg <user> <text>")
            else:
                await self.bus.publish(Message(DM, self.name, user, text))
        elif cmd == "/who":
            names = sorted(self.registry.members(self.room))
            self._out(f"#{self.room}: {', '.join(names)}")
        elif cmd == "/rooms":
            rooms = self.registry.room_list()
            self._out("active rooms: " +
                      (", ".join(f"#{r}({n})" for r, n in rooms) or "none"))
        elif cmd == "/help":
            self._out(HELP)
        elif cmd == "/quit":
            self._out("bye.")
            return False
        else:
            self._out(f"unknown command: {cmd} (try /help)")
        return True

    async def _join(self, room: str) -> None:
        if room == self.room:
            self._out(f"you are already in #{room}")
            return
        if self.room:
            self.registry.leave_room(self.room, self.name)
            await self.bus.publish(Message(PRESENCE, self.name, self.room, "leave"))
        self.room = room
        # Announce BEFORE adding ourselves so we don't narrate our own arrival...
        await self.bus.publish(Message(PRESENCE, self.name, room, "join"))
        self.registry.join_room(room, self.name)
        self._out(f"joined #{room} ({len(self.registry.members(room))} here)")

    # ------------------------------------------------------------------
    # output: Messages -> this user's screen
    # ------------------------------------------------------------------
    def deliver(self, msg: Message) -> None:
        """Called by handlers. Non-blocking by design: format, enqueue, return."""
        self.outbox.put_nowait(self.render(msg))

    def render(self, msg: Message) -> str:
        t = time.strftime("%H:%M", time.localtime(msg.ts))
        if msg.kind == ROOM:
            return f"[{t}] {msg.sender}: {msg.body}"
        if msg.kind == DM:
            if msg.sender == self.name:
                return f"[{t}] [dm -> {msg.target}] {msg.body}"
            return f"[{t}] [dm] {msg.sender}: {msg.body}"
        if msg.kind == PRESENCE:
            verb = "joined" if msg.body == "join" else "left"
            return f"[{t}] * {msg.sender} {verb} #{msg.target}"
        return f"[{t}] -- {msg.body}"  # SYSTEM and anything unknown

    def _out(self, text: str) -> None:
        self.outbox.put_nowait(text)

    async def _writer(self) -> None:
        """Single task draining the outbox, so writes never interleave."""
        while True:
            item = await self.outbox.get()
            if item is None:
                return
            try:
                self.process.stdout.write(item.replace("\n", "\r\n") + "\r\n")
            except Exception:
                return  # connection is gone; run() will clean up
