# sshchat

A minimal, open SSH chatroom server in Python, built as a **message highway**:
one data type, one bus, everything else is a subscriber. Fork it, reinterpret it.

```
pip install asyncssh
python -m sshchat            # listens on :2222 (SSHCHAT_PORT to change)
ssh yourname@localhost -p 2222
```

No accounts, no passwords: your SSH username is your handle (ssh.chat model).

## The highway

Every event in the system — room chat, DMs, joins, leaves, server notices —
is one immutable `Message(kind, sender, target, body, ts)`. Messages travel
one road:

```
 user types a line
        │
        ▼
   Session (input)          turns lines into Messages, nothing else
        │ publish
        ▼
   MessageBus               the highway: one publish point, subscribers by kind
        │
        ▼
   CoreRouter (handlers)    decides WHO gets it, via the Registry
        │ deliver
        ▼
   Session (output)         decides HOW it looks, queues it to the wire
```

Strict separation of jobs:

| file          | job                            | knows about            |
|---------------|--------------------------------|------------------------|
| `message.py`  | the one unit of traffic        | nothing                |
| `bus.py`      | routing fabric                 | Message                |
| `state.py`    | who's online, who's where      | nothing (pure state)   |
| `handlers.py` | who receives each kind         | bus, registry          |
| `session.py`  | one user: parse in, render out | bus, registry          |
| `server.py`   | SSH plumbing only              | asyncssh, session      |

## The invariant that matters

**The server never parses, transforms, or inspects `Message.body`.**
Commands (`/join`, `/msg`, ...) are extracted *before* a body exists; after
that the payload is opaque bytes-as-string all the way to the recipient's
screen. This is deliberate: a future client-side encryption layer can put
ciphertext in `body` and this server ships it untouched — zero changes here.

(Honest scoping note: SSH already encrypts the transport. A client-side
crypto layer defends against the *server operator* — a valid threat model —
but true E2E also needs client key exchange, which is client work, not
server work. This design keeps that door open; it doesn't walk through it.)

## Extending it

Add a feature = add a `kind` + a handler. Examples:

```python
# server-wide announcements
BROADCAST = "broadcast"
async def on_broadcast(msg):
    for s in registry.users.values():
        s.deliver(msg)
bus.subscribe(BROADCAST, on_broadcast)

# a logger / moderation tap that sees everything
bus.subscribe("*", audit_log)
```

Swap points, each isolated to one file:
- different transport (TCP, websockets) → rewrite `server.py` only
- persistent rooms / history → replace `state.py`'s dicts
- richer rendering (colors, ANSI) → `Session.render` only
- new commands → `Session.handle_line` only

## Commands

```
/join <room>         join or create a room (you leave your current one)
/msg <user> <text>   private message
/who                 who's in your room
/rooms               active rooms
/help                help
/quit                disconnect
```

## Current limits (known, not hidden)

- No persistence: rooms and history vanish on restart.
- No identity: usernames are claims, not verified accounts.
- One room per user at a time (simplest model; multi-room = make
  `Session.room` a set and add a targeting syntax).
- No rate limiting or flood control yet — add a `"*"` subscriber for it.

## Test

```
python tests/smoke_test.py   # boots the server, connects 4 real SSH clients
```
