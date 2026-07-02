#!/usr/bin/env python3
"""
onionchat server.

An SSH server (asyncssh) that relays end-to-end-encrypted chat. It never holds
any user's private key, so it physically cannot read message contents. It
stores opaque ciphertext envelopes and a public key directory (id -> pubkey ->
nickname). It routes by envelope metadata only.

  - No signup. First key to connect is registered (trust on first use).
  - Identity = the ed25519 key you authenticate with. The SSH username is only
    used as a *requested* nickname on first connect; after that your stored
    nickname wins.
  - The server rejects any posted message that is not a well-formed E2EE
    envelope, which is what forces clients to use the protocol/app.

Run behind a Tor onion service. See README.md.
"""

import argparse
import asyncio
import json
import os
import sqlite3
import sys
import time

import asyncssh

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from protocol import (  # noqa: E402
    user_id, fingerprint, validate_envelope_shape, encode_frame, decode_frame,
    b64e, PROTOCOL_VERSION,
)

DB_PATH = os.environ.get("ONIONCHAT_DB", "onionchat.db")
HOSTKEY_PATH = os.environ.get("ONIONCHAT_HOSTKEY", "ssh_host_ed25519_key")
HISTORY_LIMIT = 500          # max messages returned to a client
STORE_CAP = 20000            # total messages kept in the DB (oldest pruned)
MAX_LINE = 1 << 20           # 1 MiB per frame, rejects abuse


# ---------------------------------------------------------------------------
# storage
# ---------------------------------------------------------------------------
class Store:
    def __init__(self, path):
        self.db = sqlite3.connect(path)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS identities(
                id         TEXT PRIMARY KEY,
                vk_b64     TEXT NOT NULL,
                nick       TEXT UNIQUE,
                first_seen INTEGER NOT NULL,
                last_seen  INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS messages(
                seq        INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_id  TEXT NOT NULL,
                env        TEXT NOT NULL,   -- opaque ciphertext envelope (JSON)
                ts         INTEGER NOT NULL
            );
        """)
        self.db.commit()

    def register(self, uid, vk_b64, requested_nick):
        now = int(time.time())
        row = self.db.execute(
            "SELECT nick FROM identities WHERE id=?", (uid,)).fetchone()
        if row is None:
            nick = self._unique_nick(requested_nick) if requested_nick else None
            self.db.execute(
                "INSERT INTO identities(id,vk_b64,nick,first_seen,last_seen)"
                " VALUES(?,?,?,?,?)", (uid, vk_b64, nick, now, now))
        else:
            nick = row[0]
            self.db.execute(
                "UPDATE identities SET last_seen=? WHERE id=?", (now, uid))
        self.db.commit()
        return nick

    def _unique_nick(self, nick):
        base = "".join(c for c in nick if c.isprintable()).strip()[:32] or None
        if base is None:
            return None
        candidate, n = base, 1
        while self.db.execute(
                "SELECT 1 FROM identities WHERE nick=?", (candidate,)).fetchone():
            n += 1
            candidate = f"{base}{n}"
        return candidate

    def set_nick(self, uid, nick):
        clean = "".join(c for c in nick if c.isprintable()).strip()[:32]
        if not clean:
            return None, "empty nickname"
        taken = self.db.execute(
            "SELECT id FROM identities WHERE nick=?", (clean,)).fetchone()
        if taken and taken[0] != uid:
            return None, "nickname taken"
        self.db.execute("UPDATE identities SET nick=? WHERE id=?", (clean, uid))
        self.db.commit()
        return clean, None

    def roster(self):
        rows = self.db.execute(
            "SELECT id,vk_b64,nick FROM identities ORDER BY first_seen").fetchall()
        return [{"id": r[0], "vk": r[1], "nick": r[2]} for r in rows]

    def add_message(self, sender_id, env):
        self.db.execute(
            "INSERT INTO messages(sender_id,env,ts) VALUES(?,?,?)",
            (sender_id, json.dumps(env, separators=(",", ":")), int(time.time())))
        # prune oldest beyond the cap
        self.db.execute(
            "DELETE FROM messages WHERE seq <= "
            "(SELECT MAX(seq) FROM messages) - ?", (STORE_CAP,))
        self.db.commit()

    def history(self, limit):
        limit = max(1, min(limit, HISTORY_LIMIT))
        rows = self.db.execute(
            "SELECT env FROM messages ORDER BY seq DESC LIMIT ?", (limit,)
        ).fetchall()
        return [json.loads(r[0]) for r in reversed(rows)]


STORE = None                       # set in main()
ONLINE = {}                        # uid -> set of asyncio.Queue (one per session)


# ---------------------------------------------------------------------------
# SSH server: capture the authenticated key (TOFU)
# ---------------------------------------------------------------------------
# conn object -> authenticated public key bytes, filled in validate_public_key.
CONN_KEYS = {}


class ChatSSHServer(asyncssh.SSHServer):
    def connection_made(self, conn):
        self._conn = conn

    def connection_lost(self, exc):
        CONN_KEYS.pop(getattr(self, "_conn", None), None)

    def begin_auth(self, username):
        return True                # authentication is required

    def public_key_auth_supported(self):
        return True

    def validate_public_key(self, username, key):
        # TOFU: accept ANY ed25519 key. The key *is* the identity.
        # get_extra_info('client_public_key') is unreliable in the session
        # handler, so we parse and stash the raw ed25519 pubkey here, now,
        # while we definitely have the key object.
        try:
            if key.algorithm == b"ssh-ed25519":
                CONN_KEYS[self._conn] = vk_bytes_from_asyncssh_key(key)
        except Exception:
            return False
        return True

    def password_auth_supported(self):
        return False


# ---------------------------------------------------------------------------
# session handling
# ---------------------------------------------------------------------------
def vk_bytes_from_asyncssh_key(key) -> bytes:
    """Extract the raw 32-byte ed25519 public key from an asyncssh key object,
    independent of asyncssh's internal blob layout."""
    # export_public_key('openssh') -> b'ssh-ed25519 AAAA... comment'
    import base64 as _b64
    b64blob = key.export_public_key("openssh").split()[1]
    blob = _b64.b64decode(b64blob)
    # ssh wire format: string "ssh-ed25519", string pubkey(32)
    import struct
    off = 0
    (ln,) = struct.unpack(">I", blob[off:off + 4]); off += 4 + ln  # skip type
    (ln,) = struct.unpack(">I", blob[off:off + 4]); off += 4
    return blob[off:off + ln]


async def handle_session(process: asyncssh.SSHServerProcess):
    conn = process.get_extra_info("connection")
    username = process.get_extra_info("username") or ""
    vk_bytes = CONN_KEYS.get(conn)          # stashed during validate_public_key
    if vk_bytes is None:
        process.stdout.write(encode_frame({
            "event": "error", "error": "no_key",
            "detail": "could not determine your ed25519 public key",
        }))
        process.exit(1)
        return

    uid = user_id(vk_bytes)
    nick = STORE.register(uid, b64e(vk_bytes), username)

    queue: asyncio.Queue = asyncio.Queue()
    ONLINE.setdefault(uid, set()).add(queue)

    async def push_events():
        """Deliver live messages / presence to this session."""
        try:
            while True:
                event = await queue.get()
                if event is None:
                    return
                process.stdout.write(encode_frame(event))
        except (BrokenPipeError, asyncssh.BreakReceived, ConnectionResetError):
            return

    pusher = asyncio.ensure_future(push_events())

    # greet: tell the client who it is. Also serves as the banner for a human
    # who connected with raw `ssh` and has no client.
    process.stdout.write(encode_frame({
        "event": "welcome",
        "v": PROTOCOL_VERSION,
        "id": uid,
        "nick": nick,
        "fingerprint": fingerprint(vk_bytes),
        "note": "E2EE room. Messages must be encrypted envelopes. Use the "
                "onionchat client; plaintext is rejected.",
    }))

    try:
        async for line in _read_lines(process):
            await _dispatch(process, uid, vk_bytes, nick, line)
            # nickname may have changed; refresh cheaply
            r = STORE.db.execute(
                "SELECT nick FROM identities WHERE id=?", (uid,)).fetchone()
            nick = r[0] if r else nick
    except (asyncssh.BreakReceived, asyncssh.TerminalSizeChanged):
        pass
    except Exception as e:                          # noqa: BLE001
        try:
            process.stderr.write(f"session error: {e}\n")
        except Exception:
            pass
    finally:
        ONLINE.get(uid, set()).discard(queue)
        await queue.put(None)
        pusher.cancel()
        process.exit(0)


async def _read_lines(process):
    """Yield newline-delimited frames from the SSH stdin, bounded in size."""
    buf = ""
    while True:
        try:
            chunk = await process.stdin.read(4096)
        except asyncssh.BreakReceived:
            return
        if not chunk:
            return
        buf += chunk
        if len(buf) > MAX_LINE:
            process.stderr.write("frame too large\n")
            return
        while "\n" in buf:
            line, buf = buf.split("\n", 1)
            line = line.strip()
            if line:
                yield line


async def _dispatch(process, uid, vk_bytes, nick, line):
    try:
        msg = decode_frame(line)
        cmd = msg.get("cmd")
    except Exception:
        # not JSON -> a human on raw ssh. Tell them what this is.
        process.stdout.write(encode_frame({
            "event": "error",
            "error": "not_a_client",
            "detail": "This room speaks the onionchat JSON protocol. "
                      "Connect with the onionchat client.",
        }))
        return

    if cmd == "hello":
        process.stdout.write(encode_frame({
            "event": "hello_ok", "id": uid, "nick": nick,
            "fingerprint": fingerprint(vk_bytes),
        }))

    elif cmd == "roster":
        process.stdout.write(encode_frame({
            "event": "roster", "members": STORE.roster(),
        }))

    elif cmd == "set_nick":
        new, err = STORE.set_nick(uid, str(msg.get("nick", "")))
        if err:
            process.stdout.write(encode_frame(
                {"event": "error", "error": "set_nick", "detail": err}))
        else:
            process.stdout.write(encode_frame({"event": "nick_ok", "nick": new}))
            _broadcast_presence()

    elif cmd == "history":
        process.stdout.write(encode_frame({
            "event": "history",
            "messages": STORE.history(int(msg.get("limit", 50))),
        }))

    elif cmd == "send":
        env = msg.get("env")
        if not validate_envelope_shape(env):
            process.stdout.write(encode_frame({
                "event": "error", "error": "bad_envelope",
                "detail": "message rejected: not a valid E2EE envelope",
            }))
            return
        if env.get("sender") != uid:
            process.stdout.write(encode_frame({
                "event": "error", "error": "sender_mismatch",
                "detail": "envelope sender does not match your key",
            }))
            return
        STORE.add_message(uid, env)
        process.stdout.write(encode_frame({"event": "ack", "ts": env.get("ts")}))
        # fan out to every recipient who is online (including sender's other
        # sessions). The server routes by the wrap ids; it still can't read.
        for rid in env["wraps"].keys():
            for q in list(ONLINE.get(rid, ())):
                q.put_nowait({"event": "msg", "env": env})

    else:
        process.stdout.write(encode_frame({
            "event": "error", "error": "unknown_cmd", "detail": str(cmd),
        }))


def _broadcast_presence():
    roster = STORE.roster()
    for sessions in ONLINE.values():
        for q in list(sessions):
            q.put_nowait({"event": "presence", "members": roster,
                          "online": list(ONLINE.keys())})


# ---------------------------------------------------------------------------
# entrypoint
# ---------------------------------------------------------------------------
async def start(host, port):
    if not os.path.exists(HOSTKEY_PATH):
        # stable host key so the onion service identity/fingerprint persists
        k = asyncssh.generate_private_key("ssh-ed25519")
        with open(HOSTKEY_PATH, "wb") as f:
            f.write(k.export_private_key("openssh"))
        os.chmod(HOSTKEY_PATH, 0o600)

    server = await asyncssh.create_server(
        ChatSSHServer, host, port,
        server_host_keys=[HOSTKEY_PATH],
        process_factory=handle_session,
        # accept any username; auth is purely by key
        server_version="SSH-2.0-onionchat",
    )
    print(f"onionchat server listening on {host}:{port}")
    print(f"host key fingerprint: "
          f"{asyncssh.read_private_key(HOSTKEY_PATH).get_fingerprint()}")
    await server.wait_closed()


def main():
    global STORE
    ap = argparse.ArgumentParser(description="onionchat E2EE SSH server")
    ap.add_argument("--host", default="127.0.0.1",
                    help="bind address (keep 127.0.0.1; Tor connects locally)")
    ap.add_argument("--port", type=int, default=8022)
    args = ap.parse_args()
    STORE = Store(DB_PATH)
    try:
        asyncio.run(start(args.host, args.port))
    except (OSError, asyncssh.Error) as e:
        sys.exit(f"failed to start: {e}")
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
