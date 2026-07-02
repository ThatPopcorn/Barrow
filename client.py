#!/usr/bin/env python3
"""
onionchat client -- the minimal reference client.

Usage:
    python client.py NICK@HOST[:PORT] [--key PATH] [--no-tor]

  HOST ending in .onion is routed through Tor's SOCKS proxy (127.0.0.1:9050)
  automatically. NICK is only a *requested* nickname on first connect.

Identity: a single ed25519 key. By default it uses ~/.ssh/id_ed25519 if present,
otherwise it generates one at ~/.config/onionchat/id_ed25519. The same key is
your SSH auth, your signature, and (converted to curve25519) your decryption key.

This client is deliberately small so you can read it, trust it, or fork it.
All the crypto lives in protocol.py. Type /help once connected.
"""

import argparse
import asyncio
import base64
import os
import struct
import sys

import asyncssh

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from protocol import (  # noqa: E402
    build_envelope, open_envelope, encode_frame, decode_frame,
    user_id, fingerprint, b64d, CryptoError, BadSignatureError,
)
from nacl.signing import SigningKey  # noqa: E402

DEFAULT_KEY = os.path.expanduser("~/.ssh/id_ed25519")
FALLBACK_KEY = os.path.expanduser("~/.config/onionchat/id_ed25519")
TOR_SOCKS = ("127.0.0.1", 9050)


# ---------------------------------------------------------------------------
# key loading: one ed25519 key -> asyncssh auth key + NaCl SigningKey
# ---------------------------------------------------------------------------
def _seed_from_openssh(priv_bytes: bytes) -> bytes:
    """Parse the 32-byte ed25519 seed out of an unencrypted OpenSSH key."""
    text = priv_bytes.decode()
    body = "".join(l for l in text.splitlines() if not l.startswith("-----"))
    blob = base64.b64decode(body)
    if blob[:15] != b"openssh-key-v1\x00":
        raise ValueError("unsupported private key format")
    off = 15

    def rd(b, o):
        (ln,) = struct.unpack(">I", b[o:o + 4]); o += 4
        return b[o:o + ln], o + ln

    _c, off = rd(blob, off)          # cipher
    kdf, off = rd(blob, off)         # kdf
    _o, off = rd(blob, off)          # kdf options
    off += 4                         # nkeys
    _pub, off = rd(blob, off)        # public blob
    priv, off = rd(blob, off)        # private section
    if kdf != b"none":
        raise ValueError("encrypted key: decrypt it first "
                         "(ssh-keygen -p -f <key>) or use --no-tor test key")
    o = 8                            # skip two check ints
    _ktype, o = rd(priv, o)
    _pubk, o = rd(priv, o)
    privk, o = rd(priv, o)           # 64 bytes: seed(32) || pub(32)
    return privk[:32]


def load_identity(path):
    if not os.path.exists(path):
        if path == DEFAULT_KEY:              # fall back to a dedicated key
            path = FALLBACK_KEY
        if not os.path.exists(path):
            os.makedirs(os.path.dirname(path), exist_ok=True)
            k = asyncssh.generate_private_key("ssh-ed25519")
            with open(path, "wb") as f:
                f.write(k.export_private_key("openssh"))
            os.chmod(path, 0o600)
            print(f"[generated new identity at {path}]")
    with open(path, "rb") as f:
        priv_bytes = f.read()
    seed = _seed_from_openssh(priv_bytes)
    signing_key = SigningKey(seed)
    ssh_key = asyncssh.import_private_key(priv_bytes)
    return signing_key, ssh_key, path


# ---------------------------------------------------------------------------
# connection (direct or via Tor SOCKS)
# ---------------------------------------------------------------------------
async def open_socket(host, port, use_tor):
    if use_tor:
        import socks
        s = socks.socksocket()
        s.set_proxy(socks.SOCKS5, *TOR_SOCKS, rdns=True)  # resolve .onion in Tor
        await asyncio.get_event_loop().run_in_executor(
            None, s.connect, (host, port))
        s.setblocking(False)
        return s
    return None


# ---------------------------------------------------------------------------
# client session
# ---------------------------------------------------------------------------
class Client:
    def __init__(self, signing_key, my_id):
        self.sk = signing_key
        self.my_id = my_id
        self.roster = {}          # id -> {"nick":..., "vk": bytes}
        self.conn = None
        self.writer = None

    def _recipients(self):
        """Everyone we currently know a key for, including ourselves so we can
        read our own messages back from history."""
        return {rid: m["vk"] for rid, m in self.roster.items()}

    def _name(self, rid):
        m = self.roster.get(rid)
        if m and m.get("nick"):
            return m["nick"]
        return rid[:10]

    def send_frame(self, obj):
        self.writer.write(encode_frame(obj))

    async def run(self, host, port, use_tor, requested_nick):
        sock = await open_socket(host, port, use_tor)
        connect_kwargs = dict(
            username=requested_nick or "anon",
            client_keys=[self.ssh_key],
            known_hosts=None,          # onion + TOFU: host key pinning is manual
        )
        if sock is not None:
            connect_kwargs["sock"] = sock
            connect_kwargs["host"] = host
            self.conn = await asyncssh.connect(**connect_kwargs)
        else:
            self.conn = await asyncssh.connect(host, port, **connect_kwargs)

        self.proc = await self.conn.create_process()
        self.writer = self.proc.stdin

        # know our own key immediately so we're never without a recipient
        self.roster[self.my_id] = {"nick": requested_nick,
                                   "vk": bytes(self.sk.verify_key)}

        print(f"[connected to {host}]  your fingerprint: "
              f"{fingerprint(bytes(self.sk.verify_key))}")
        print("[type /help for commands]\n")

        # initial handshake
        self.send_frame({"cmd": "hello"})
        if requested_nick:
            self.send_frame({"cmd": "set_nick", "nick": requested_nick})
        self.send_frame({"cmd": "roster"})
        self.send_frame({"cmd": "history", "limit": 50})

        reader_task = asyncio.ensure_future(self._read_server())
        input_task = asyncio.ensure_future(self._read_input())
        done, pending = await asyncio.wait(
            [reader_task, input_task], return_when=asyncio.FIRST_COMPLETED)
        for t in pending:
            t.cancel()
        self.conn.close()

    async def _read_server(self):
        buf = ""
        while True:
            chunk = await self.proc.stdout.read(4096)
            if not chunk:
                print("\n[disconnected]")
                return
            buf += chunk
            while "\n" in buf:
                line, buf = buf.split("\n", 1)
                if line.strip():
                    self._handle_event(line.strip())

    def _handle_event(self, line):
        try:
            ev = decode_frame(line)
        except Exception:
            return
        kind = ev.get("event")

        if kind in ("welcome", "hello_ok"):
            if ev.get("nick"):
                print(f"[you are '{ev['nick']}'  fp {ev.get('fingerprint','')}]")
        elif kind in ("roster", "presence"):
            self._update_roster(ev.get("members", []))
            if kind == "presence":
                online = ", ".join(self._name(i) for i in ev.get("online", []))
                print(f"[online: {online}]")
        elif kind == "history":
            for env in ev.get("messages", []):
                self._show(env, historical=True)
        elif kind == "msg":
            self._show(ev.get("env"))
        elif kind == "ack":
            pass
        elif kind == "nick_ok":
            print(f"[nickname set to '{ev.get('nick')}']")
            self.send_frame({"cmd": "roster"})
        elif kind == "error":
            print(f"[server error: {ev.get('error')}: {ev.get('detail','')}]")

    def _update_roster(self, members):
        self.roster = {}
        for m in members:
            try:
                self.roster[m["id"]] = {"nick": m.get("nick"),
                                        "vk": b64d(m["vk"])}
            except Exception:
                continue

    def _show(self, env, historical=False):
        if not env:
            return
        try:
            text = open_envelope(env, self.my_id, self.sk)
        except (ValueError, CryptoError, BadSignatureError):
            return  # not for us, or tampered; silently skip
        who = self._name(env.get("sender", ""))
        prefix = "  " if historical else ""
        print(f"{prefix}<{who}> {text}")

    async def _read_input(self):
        loop = asyncio.get_event_loop()
        while True:
            line = await loop.run_in_executor(None, sys.stdin.readline)
            if not line:
                return
            line = line.rstrip("\n")
            if not line:
                continue
            if line.startswith("/"):
                if self._command(line):
                    return
                continue
            self._send_message(line)

    def _send_message(self, text):
        recipients = self._recipients()
        if not recipients:
            print("[no known recipients yet; try /who]")
            return
        env = build_envelope(text, self.sk, recipients)
        self.send_frame({"cmd": "send", "env": env})
        print(f"<{self._name(self.my_id)}> {text}")

    def _command(self, line):
        parts = line.split(" ", 1)
        cmd = parts[0].lower()
        arg = parts[1].strip() if len(parts) > 1 else ""
        if cmd in ("/quit", "/exit"):
            return True
        elif cmd == "/help":
            print("  /who            list members\n"
                  "  /nick NAME      change your nickname\n"
                  "  /fp             show your own fingerprint\n"
                  "  /verify NAME    show a member's fingerprint to compare\n"
                  "  /history [N]    reload last N messages\n"
                  "  /quit           leave")
        elif cmd == "/who":
            self.send_frame({"cmd": "roster"})
            for rid, m in self.roster.items():
                mark = " (you)" if rid == self.my_id else ""
                print(f"  {self._name(rid)}{mark}  {rid[:12]}")
        elif cmd == "/nick":
            if arg:
                self.send_frame({"cmd": "set_nick", "nick": arg})
        elif cmd == "/fp":
            print(f"  your fingerprint: {fingerprint(bytes(self.sk.verify_key))}")
        elif cmd == "/verify":
            target = None
            for rid, m in self.roster.items():
                if m.get("nick") == arg or rid.startswith(arg):
                    target = (rid, m); break
            if target:
                rid, m = target
                print(f"  {self._name(rid)} fingerprint: "
                      f"{fingerprint(m['vk'])}")
                print("  compare this with them over a trusted channel.")
            else:
                print("  no such member")
        elif cmd == "/history":
            n = int(arg) if arg.isdigit() else 50
            self.send_frame({"cmd": "history", "limit": n})
        else:
            print("  unknown command; /help")
        return False


# ---------------------------------------------------------------------------
def parse_target(target):
    if "@" not in target:
        sys.exit("target must be NICK@HOST[:PORT]")
    nick, host = target.split("@", 1)
    port = 8022
    if ":" in host:
        host, p = host.rsplit(":", 1)
        port = int(p)
    return nick, host, port


def main():
    ap = argparse.ArgumentParser(description="onionchat minimal E2EE client")
    ap.add_argument("target", help="NICK@HOST[:PORT] (HOST may be an .onion)")
    ap.add_argument("--key", default=DEFAULT_KEY, help="ed25519 private key path")
    ap.add_argument("--no-tor", action="store_true",
                    help="direct TCP (for local testing; never use for .onion)")
    args = ap.parse_args()

    nick, host, port = parse_target(args.target)
    use_tor = host.endswith(".onion") and not args.no_tor

    signing_key, ssh_key, path = load_identity(args.key)
    my_id = user_id(bytes(signing_key.verify_key))
    print(f"[identity: {path}]  id {my_id[:16]}...")

    client = Client(signing_key, my_id)
    client.ssh_key = ssh_key
    try:
        asyncio.run(client.run(host, port, use_tor, nick))
    except (OSError, asyncssh.Error) as e:
        sys.exit(f"connection failed: {e}")
    except KeyboardInterrupt:
        print("\n[bye]")


if __name__ == "__main__":
    main()
