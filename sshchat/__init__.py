"""The one and only unit of traffic in the system.

Every event -- room chat, DM, join/leave, server notice -- is a Message.
If you want to add a feature, you add a new `kind` and a handler for it.

IMPORTANT INVARIANT: the server never inspects or transforms `body`.
It is an opaque payload. This is what makes client-side encryption a
drop-in later: ciphertext travels the same highway as plaintext.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import time

# Built-in kinds. Add your own freely; the bus doesn't care.
ROOM = "room"          # target = room name, delivered to all members
DM = "dm"              # target = username, delivered to target + echoed to sender
PRESENCE = "presence"  # target = room name, body = "join" | "leave"
SYSTEM = "system"      # target = username, server -> one user (errors, info)


@dataclass(frozen=True)
class Message:
    kind: str    # routing key, e.g. "room", "dm", "presence", "system"
    sender: str  # username, or "server" for system-originated messages
    target: str  # room name or username, depending on kind
    body: str    # OPAQUE payload -- never parsed by the server
    ts: float = field(default_factory=time.time)
