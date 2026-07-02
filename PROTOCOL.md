# onionchat protocol v1

A minimal, honest spec. If your client speaks this, it works with the server.
Reference implementation: `protocol.py` (~200 lines). Port it or trim it.

## 1. Transport & identity

- Transport is SSH. The server is an SSH server (reached over a Tor onion
  service). Auth is **public-key only**, ed25519, **trust-on-first-use**: the
  server accepts any key and treats it as a new identity. There is no signup
  and no password.
- Your identity is one ed25519 keypair. The same key does three jobs:
  1. SSH authentication,
  2. signing envelopes (ed25519),
  3. decrypting message keys (converted to curve25519 via the standard
     ed25519→X25519 map).
- Your **id** is `base64url(sha256(ed25519_pubkey))` with padding stripped.
  Because it is derived from the key, no one can claim an id they don't hold
  the key for, and the server can't hand you a different id.
- The SSH **username** you connect with is only a *requested* nickname on your
  first connection. After that your stored nickname wins; the username is
  ignored. So `ssh alice@…onion` asks for the nick "alice" the first time.

## 2. Framing

After the SSH session opens, both sides exchange **newline-delimited JSON**
objects (UTF-8, one compact object per line, `\n` terminated). Max 1 MiB/line.

## 3. Client → server commands

| line | meaning |
|------|---------|
| `{"cmd":"hello"}` | request your identity summary |
| `{"cmd":"roster"}` | request the member/key directory |
| `{"cmd":"set_nick","nick":"..."}` | claim/change your nickname (unique, ≤32 chars) |
| `{"cmd":"history","limit":N}` | request last N stored envelopes (≤500) |
| `{"cmd":"send","env":{…}}` | post an encrypted envelope (see §5) |

## 4. Server → client events

| event | payload |
|-------|---------|
| `welcome` | `id`, `nick`, `fingerprint`, `note` — sent on connect |
| `hello_ok` | `id`, `nick`, `fingerprint` |
| `roster` / `presence` | `members`: list of `{id, vk, nick}`; presence also has `online` |
| `history` | `messages`: list of envelopes |
| `msg` | `env`: one envelope, pushed live |
| `ack` | `ts` — your send was accepted |
| `nick_ok` | `nick` |
| `error` | `error`, `detail` |

`vk` is base64 of the raw 32-byte ed25519 public key. That directory is how
you learn who to encrypt to. **See the trust warning in §6.**

## 5. The message envelope

Hybrid encryption. To send plaintext `P` to recipients `R` (each known by
`id → ed25519_pubkey`):

1. `K = random 32 bytes` (content key).
2. `body = SecretBox(K).encrypt(P)` — XSalsa20-Poly1305, nonce prepended. Once.
3. For each recipient `r`: `wraps[r] = SealedBox(curve25519_pub_r).encrypt(K)`
   (anonymous sealed box; `curve25519_pub_r` is `ed25519_pub_r` converted).
4. Build the object below **without** `sig`, canonicalise it
   (`json.dumps(sort_keys=True, separators=(",",":"))`), ed25519-sign that,
   and attach the signature as `sig`.

```json
{
  "v": 1,
  "type": "msg",
  "sender": "<sender id>",
  "sender_vk": "<base64 ed25519 pubkey>",
  "ts": 1700000000,
  "body": "<base64 SecretBox output>",
  "wraps": { "<recipient id>": "<base64 SealedBox output>", ... },
  "sig": "<base64 ed25519 signature over the object minus sig>"
}
```

To open one: check `sha256(sender_vk)` equals `sender`; verify `sig` with
`sender_vk`; take `wraps[your_id]`, unseal it with your curve25519 private key
to get `K`; open `body` with `SecretBox(K)`.

The server validates only the **shape** of this object (fields present, base64
decodes, `sender` matches `sender_vk`, `wraps` non-empty). It has no keys, so
it stores and routes ciphertext and never sees `P`.

## 6. Security properties — and their limits (read this)

What holds:
- The server cannot read message contents. It has no private keys. Verified by
  test: plaintext never appears in its storage.
- Messages are authenticated and integrity-protected by the sender signature.
- Anyone can run their own client; the server can't force plaintext out of you.

What does **not** hold — do not assume otherwise:
- **Key-directory trust.** You learn recipients' keys *from the server*. A
  malicious server can advertise its own key as "alice" and read anything you
  send "to alice". The signature only proves consistency with whatever key you
  were given. **Mitigation is mandatory:** compare fingerprints out of band
  (`/verify`, or the `fingerprint` field) over a channel you already trust.
- **No forward secrecy.** Keys are long-term. If a private key later leaks,
  every stored ciphertext that key could open is exposed. A real ratchet
  (Double Ratchet / MLS) would fix this and is out of scope for "minimal".
- **The server can't force clients to actually encrypt.** It enforces envelope
  *shape*, not that the payload is genuinely secret. Confidentiality assumes
  every participant runs an honest client.
- **Metadata is visible to the server**: who sent, when, to which ids, sizes,
  who is online. Tor hides network location; it does not hide these.
- Group membership is whoever has ever connected. There is no invite/removal
  and no per-group key rotation.

Treat this as a solid teaching-grade / small-trusted-group system, not as a
drop-in replacement for Signal.
