<div align="center">

# 🗿

# barrow

**Anonymous, end-to-end-encrypted chat you SSH into — living inside a Tor onion service.**

*What is buried cannot be read.*

<!-- Prefer a famous line? Swap the epigraph above for:
     *"Three may keep a secret, if two of them are dead."* — Benjamin Franklin -->

<!-- Prefer earthy over ancient? Swap the 🗿 logo above for 🕳️ -->

`MIT` · `Python 3` · `ed25519 / X25519` · `Tor onion service`

</div>

---

A barrow is a sealed mound: you speak into it and nothing comes back out. That is
the whole design. You SSH into a relay hidden behind a Tor onion service, and it
buries what you give it — storing and forwarding **only ciphertext it cannot read.**

- **No signup.** No email, no phone, no password. Your ed25519 keypair *is* your
  identity. First key to connect is registered (trust on first use).
- **One key, three jobs.** The same key (your `~/.ssh/id_ed25519` works) logs you
  in, *signs* your messages, and — converted to Curve25519 — *decrypts* them.
- **End-to-end.** The relay holds no private keys and rejects anything that isn't a
  valid encrypted envelope. It routes by metadata; it never sees plaintext.
- **Underground.** Reachable only as a `.onion` — no public IP, no DNS.

Connecting is meant to feel like SSH:

```bash
python client.py you@y782hd7…onion
```

---

## Quickstart

```bash
pip install pynacl asyncssh python-socks PySocks

# --- server (run behind Tor; see below) ---
python server.py --host 127.0.0.1 --port 8022

# --- client ---
python client.py alice@y782hd7…onion
```

`.onion` hosts route through Tor's SOCKS proxy (`127.0.0.1:9050`) automatically.
`alice` is only a *requested* nickname on your first connect — your identity is the
key, not the name. Commands once inside: `/who`, `/nick`, `/fp`, `/verify`,
`/history`, `/quit`.

### Publish the relay as an onion service

In your `torrc`:

```
HiddenServiceDir /var/lib/tor/barrow/
HiddenServicePort 8022 127.0.0.1:8022
```

Reload Tor, then `sudo cat /var/lib/tor/barrow/hostname` for your `.onion` address.
Keep the server bound to `127.0.0.1` so it is only reachable through Tor.

### Try it locally (no Tor)

```bash
python server.py --port 8022
python client.py alice@127.0.0.1:8022 --no-tor --key /tmp/alice
python client.py bob@127.0.0.1:8022  --no-tor --key /tmp/bob
```

---

## How it works

Hybrid encryption, per message: pick a random content key, lock the message body
once with it, seal a copy of that key to each recipient's public key, then sign the
whole envelope with your ed25519 key. The relay validates only the *shape* of that
envelope — so plaintext is refused — and stores the opaque result.

```
plaintext ──SecretBox(K)──▶ body            (encrypted once)
K ──SealedBox(recipient_pub)──▶ wraps[id]    (one sealed copy per recipient)
envelope ──ed25519 sign──▶ sig               (authenticity + integrity)
```

Full wire format and framing: **[PROTOCOL.md](PROTOCOL.md)**. It's ~180 lines of
`protocol.py`; port it or write your own client. barrow is a protocol first and an
app second.

---

## What barrow is — and isn't

Standard, inspectable primitives, and an honest account of the edges. Read this
before trusting it with anything that matters.

**Holds:**
- The relay cannot read message contents — it has no keys. (There is a test that
  asserts the plaintext never appears in the server's storage.)
- Messages are authenticated and integrity-protected by the sender's signature.
- Anyone can run their own client; the server can't force plaintext out of you.

**Does not hold — do not assume otherwise:**
- **Key-directory trust.** You learn recipients' keys *from the relay*, so a hostile
  relay could advertise its own key and MITM you. **Verify fingerprints out of band**
  (`/verify`) over a channel you already trust. The app can't do this for you.
- **No forward secrecy.** Keys are long-term; if one leaks later, stored ciphertext
  it could open is exposed. A ratchet (Double Ratchet / MLS) would fix this and is
  out of scope for "minimal."
- **Metadata is visible to the relay**: who sent, when, to which ids, sizes, who is
  online. Tor hides your network location; it does not hide these.
- **Shape, not honesty.** The relay enforces that messages are well-formed
  envelopes, not that a client actually encrypted honestly. Confidentiality assumes
  every participant runs an honest client.

This is a solid teaching-grade / small-trusted-group system, not a drop-in Signal.

---

## Repository layout

| file | purpose |
|------|---------|
| `protocol.py` | crypto + wire format — the entire protocol |
| `server.py`   | the relay (asyncssh + SQLite), TOFU auth, ciphertext-only storage |
| `client.py`   | the minimal reference client |
| `test_e2e.py` | end-to-end test, incl. "relay stores only ciphertext" |
| `PROTOCOL.md` | spec for building interoperable clients |

## License

MIT. Don't trust it — read it.