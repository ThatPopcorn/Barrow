"""Who is online, and who is in which room.

Deliberately dumb: dicts and sets, no persistence. The Registry never
sends messages -- it only answers questions. Routing decisions belong to
handlers; state lives here. Swap this for a persistent store later
without touching anything else.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from .session import Session


class Registry:
    def __init__(self) -> None:
        self.users: dict[str, "Session"] = {}   # username -> live session
        self.rooms: dict[str, set[str]] = {}     # room name -> usernames

    # -- users ---------------------------------------------------------
    def claim_name(self, wanted: str, session: "Session") -> str:
        """Reserve a username. If taken, suffix a number: bob, bob2, bob3..."""
        name, n = wanted, 1
        while name in self.users:
            n += 1
            name = f"{wanted}{n}"
        self.users[name] = session
        return name

    def release_name(self, name: str) -> None:
        self.users.pop(name, None)

    def get_user(self, name: str) -> Optional["Session"]:
        return self.users.get(name)

    # -- rooms ---------------------------------------------------------
    def join_room(self, room: str, name: str) -> None:
        self.rooms.setdefault(room, set()).add(name)

    def leave_room(self, room: str, name: str) -> None:
        members = self.rooms.get(room)
        if members is None:
            return
        members.discard(name)
        if not members:          # garbage-collect empty rooms
            del self.rooms[room]

    def members(self, room: str) -> set[str]:
        return set(self.rooms.get(room, ()))

    def room_list(self) -> list[tuple[str, int]]:
        return sorted((r, len(m)) for r, m in self.rooms.items())
