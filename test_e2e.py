"""
End-to-end test against the real server code, no Tor, no interactive stdin.
Proves: auth+register, roster key directory, encrypted send, live fanout,
history, and — most importantly — that the server DB holds only ciphertext.
"""
import asyncio, os, tempfile, struct, base64, sqlite3, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import asyncssh
import server as srv
from protocol import (build_envelope, open_envelope, encode_frame, decode_frame,
                      user_id, b64d)
from nacl.signing import SigningKey

PORT = 8123
SECRET_TEXT = "meet at the bridge at dawn -- SECRETPLAINTEXT123"


def make_identity():
    k = asyncssh.generate_private_key("ssh-ed25519")
    priv = k.export_private_key("openssh")
    # derive nacl seed the same way the client does
    from client import _seed_from_openssh
    seed = _seed_from_openssh(priv)
    return SigningKey(seed), k


class Peer:
    def __init__(self, sk, ssh_key, nick):
        self.sk = sk; self.ssh_key = ssh_key; self.nick = nick
        self.my_id = user_id(bytes(sk.verify_key))
        self.roster = {}; self.inbox = []

    async def connect(self):
        self.conn = await asyncssh.connect(
            "127.0.0.1", PORT, username=self.nick,
            client_keys=[self.ssh_key], known_hosts=None)
        self.proc = await self.conn.create_process()
        asyncio.ensure_future(self._reader())

    async def _reader(self):
        buf = ""
        while True:
            chunk = await self.proc.stdout.read(4096)
            if not chunk:
                return
            buf += chunk
            while "\n" in buf:
                line, buf = buf.split("\n", 1)
                if line.strip():
                    self._on(decode_frame(line.strip()))

    def _on(self, ev):
        k = ev.get("event")
        if k in ("roster", "presence"):
            self.roster = {m["id"]: b64d(m["vk"]) for m in ev.get("members", [])}
        elif k == "msg":
            self.inbox.append(ev["env"])
        elif k == "history":
            for env in ev.get("messages", []):
                self.inbox.append(env)

    def send(self, obj):
        self.proc.stdin.write(encode_frame(obj))

    def say(self, text):
        env = build_envelope(text, self.sk, self.roster)
        self.send({"cmd": "send", "env": env})


async def main():
    tmp = tempfile.mkdtemp()
    srv.DB_PATH = os.path.join(tmp, "test.db")
    srv.HOSTKEY_PATH = os.path.join(tmp, "hostkey")
    srv.STORE = srv.Store(srv.DB_PATH)
    if not os.path.exists(srv.HOSTKEY_PATH):
        k = asyncssh.generate_private_key("ssh-ed25519")
        open(srv.HOSTKEY_PATH, "wb").write(k.export_private_key("openssh"))

    server = await asyncssh.create_server(
        srv.ChatSSHServer, "127.0.0.1", PORT,
        server_host_keys=[srv.HOSTKEY_PATH],
        process_factory=srv.handle_session)

    results = []
    def check(name, ok):
        results.append((name, ok))
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}")

    a_sk, a_ssh = make_identity()
    b_sk, b_ssh = make_identity()
    alice = Peer(a_sk, a_ssh, "alice")
    bob = Peer(b_sk, b_ssh, "bob")

    await alice.connect(); await bob.connect()
    await asyncio.sleep(0.3)
    alice.send({"cmd": "set_nick", "nick": "alice"})
    bob.send({"cmd": "set_nick", "nick": "bob"})
    await asyncio.sleep(0.3)
    alice.send({"cmd": "roster"}); bob.send({"cmd": "roster"})
    await asyncio.sleep(0.3)

    check("both peers see 2 members in roster",
          len(alice.roster) == 2 and len(bob.roster) == 2)
    check("alice knows bob's key",
          bob.my_id in alice.roster and
          alice.roster[bob.my_id] == bytes(b_sk.verify_key))

    # alice sends an encrypted message
    alice.say(SECRET_TEXT)
    await asyncio.sleep(0.4)

    # bob received it live and can decrypt
    got = None
    for env in bob.inbox:
        try:
            got = open_envelope(env, bob.my_id, bob.sk)
        except Exception:
            pass
    check("bob decrypts alice's live message", got == SECRET_TEXT)

    # a fresh peer using bob's key gets it from history too
    bob.inbox.clear()
    bob.send({"cmd": "history", "limit": 10})
    await asyncio.sleep(0.4)
    hist_ok = any(_safe_open(env, bob) == SECRET_TEXT for env in bob.inbox)
    check("message retrievable from server history (encrypted at rest)", hist_ok)

    # THE KEY CLAIM: the server DB must not contain the plaintext anywhere.
    srv.STORE.db.commit()
    raw = open(srv.DB_PATH, "rb").read()
    # also read WAL if present
    for ext in ("-wal", "-shm"):
        p = srv.DB_PATH + ext
        if os.path.exists(p):
            raw += open(p, "rb").read()
    plaintext_absent = SECRET_TEXT.encode() not in raw
    check("plaintext NOT present anywhere in server storage", plaintext_absent)

    # server rejects a non-envelope 'send' (enforces the protocol)
    bob._rejected = False
    orig_on = bob._on
    def spy(ev):
        if ev.get("event") == "error" and ev.get("error") == "bad_envelope":
            bob._rejected = True
        orig_on(ev)
    bob._on = spy
    bob.send({"cmd": "send", "env": {"hello": "plaintext"}})
    await asyncio.sleep(0.3)
    check("server rejects malformed (non-E2EE) message", bob._rejected)

    server.close()
    print()
    passed = sum(1 for _, ok in results if ok)
    print(f"{passed}/{len(results)} checks passed")
    return 0 if passed == len(results) else 1


def _safe_open(env, peer):
    try:
        return open_envelope(env, peer.my_id, peer.sk)
    except Exception:
        return None


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))