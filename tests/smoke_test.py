"""End-to-end smoke test: boots the real server, connects real SSH clients,
and asserts on what each user actually sees on screen.

Run: python tests/smoke_test.py
"""
import asyncio
import sys

sys.path.insert(0, ".")

import asyncssh

from sshchat.server import start_server

PORT = 2299


async def read_until(proc, needle: str, timeout: float = 3.0) -> str:
    """Read output until `needle` appears (or fail loudly)."""
    buf = ""
    try:
        async with asyncio.timeout(timeout):
            while needle not in buf:
                chunk = await proc.stdout.read(1024)
                if not chunk:
                    break
                buf += chunk
    except TimeoutError:
        raise AssertionError(f"timed out waiting for {needle!r}; got:\n{buf!r}")
    return buf


async def connect(name: str):
    conn = await asyncssh.connect("127.0.0.1", PORT, username=name,
                                  known_hosts=None)
    proc = await conn.create_process()
    return conn, proc


async def main() -> None:
    server = await start_server(host="127.0.0.1", port=PORT)
    passed = []

    # -- alice connects, lands in #lobby --------------------------------
    a_conn, alice = await connect("alice")
    await read_until(alice, "joined #lobby")
    passed.append("alice auto-joins #lobby")

    # -- bob connects; alice sees the presence notice -------------------
    b_conn, bob = await connect("bob")
    await read_until(bob, "joined #lobby")
    await read_until(alice, "* bob joined #lobby")
    passed.append("presence: alice sees bob join")

    # -- room message flows both ways -----------------------------------
    bob.stdin.write("hello room\n")
    await read_until(alice, "bob: hello room")
    await read_until(bob, "bob: hello room")  # sender echo = delivery confirm
    passed.append("room message reaches alice and echoes to bob")

    # -- DM: private, echoed, and NOT visible to a third party ----------
    c_conn, carol = await connect("carol")
    await read_until(carol, "joined #lobby")
    alice.stdin.write("/msg bob secret handshake\n")
    await read_until(bob, "[dm] alice: secret handshake")
    await read_until(alice, "[dm -> bob] secret handshake")
    passed.append("dm delivered to bob, echoed to alice")

    # -- /who ------------------------------------------------------------
    alice.stdin.write("/who\n")
    out = await read_until(alice, "#lobby:")
    assert "alice" in out and "bob" in out and "carol" in out
    passed.append("/who lists all three users")

    # -- /join isolates rooms: bob leaves, lobby chat no longer reaches him
    bob.stdin.write("/join dev\n")
    await read_until(bob, "joined #dev")
    await read_until(alice, "* bob left #lobby")
    alice.stdin.write("lobby only\n")
    await read_until(alice, "alice: lobby only")
    bob.stdin.write("/who\n")
    who = await read_until(bob, "#dev:")
    assert "lobby only" not in who, "bob received a message from a room he left!"
    passed.append("room isolation: bob in #dev doesn't see #lobby traffic")

    # -- carol checks the DM never leaked to her -------------------------
    carol.stdin.write("/rooms\n")
    carol_screen = await read_until(carol, "active rooms:")
    assert "secret handshake" not in carol_screen, "DM leaked to third party!"
    assert "#dev(1)" in carol_screen and "#lobby(2)" in carol_screen
    passed.append("dm privacy + /rooms shows dev(1), lobby(2)")

    # -- DM to a nonexistent user -> error to sender only ----------------
    alice.stdin.write("/msg ghost boo\n")
    await read_until(alice, "no such user: ghost")
    passed.append("dm to unknown user returns error")

    # -- duplicate username gets suffixed --------------------------------
    d_conn, alice2 = await connect("alice")
    await read_until(alice2, "welcome, alice2")
    passed.append("name collision -> alice2")
    d_conn.close()

    # -- /quit cleans up: presence notice + name freed -------------------
    bob.stdin.write("/quit\n")
    await read_until(bob, "bye.")
    b2_conn, bob2 = await connect("bob")
    await read_until(bob2, "welcome, bob.")  # name was released, no suffix
    passed.append("/quit releases the username")

    for p in passed:
        print(f"  PASS  {p}")
    print(f"\n{len(passed)}/{len(passed)} checks passed")

    for c in (a_conn, b2_conn, c_conn):
        c.close()
    server.close()


asyncio.run(main())
