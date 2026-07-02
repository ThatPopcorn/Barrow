"""
barrow protocol / crypto core.

This module is the entire "protocol". A client is anything that speaks the
newline-delimited JSON frames documented in PROTOCOL.md and produces envelopes
that pass `validate_envelope_shape`. This file is the reference implementation
of the crypto so people can port it to another language or trim it down.

Identity is a single ed25519 keypair (your ~/.ssh/id_ed25519 works). The same
key is used for SSH auth, for signing envelopes, and — converted to
curve25519 — for decrypting the per-message content key. Nothing else.

Message confidentiality is hybrid encryption:
  1. pick a random 32-byte content key K
  2. SecretBox(K) the plaintext ONCE            -> body (nonce is prepended)
  3. for each recipient r: SealedBox(curve_pub_r).encrypt(K) -> wraps[r]
  4. ed25519-sign the whole envelope (minus the sig) with the sender key

Recipient reverses it: unwrap K with their curve private key, open the body,
verify the signature, and check the sender fingerprint matches sender_vk.

Security properties and their limits are documented honestly in PROTOCOL.md.
Read them before trusting this with anything that matters.
"""

import base64
import hashlib
import json
import time

from nacl.signing import SigningKey, VerifyKey
from nacl.public import SealedBox
from nacl.secret import SecretBox
import nacl.utils
from nacl.exceptions import CryptoError, BadSignatureError

PROTOCOL_VERSION = 1


# ---------------------------------------------------------------------------
# encoding helpers
# ---------------------------------------------------------------------------
def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def canonical(obj: dict) -> bytes:
    """Deterministic JSON used for signing. sort_keys makes it reproducible
    regardless of dict insertion order, including nested dicts like `wraps`."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


# ---------------------------------------------------------------------------
# identity
# ---------------------------------------------------------------------------
def user_id(verify_key_bytes: bytes) -> str:
    """Stable identity id = urlsafe base64 of sha256(pubkey), no padding.
    This is what the server keys everything on. Deriving it from the pubkey
    means the server cannot let anyone claim an id they don't hold the key for."""
    digest = hashlib.sha256(verify_key_bytes).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def fingerprint(verify_key_bytes: bytes) -> str:
    """Human-comparable fingerprint for out-of-band verification.
    Grouped hex of sha256(pubkey). Compare this over a trusted channel (in
    person, Signal, etc.) to detect a server substituting keys."""
    h = hashlib.sha256(verify_key_bytes).hexdigest()
    return ":".join(h[i:i + 4] for i in range(0, 32, 4))  # first 16 bytes, grouped


# ---------------------------------------------------------------------------
# envelope construction / opening
# ---------------------------------------------------------------------------
def build_envelope(plaintext: str, signing_key: SigningKey,
                   recipients: dict) -> dict:
    """recipients: {recipient_id: verify_key_bytes}. The sender is normally
    included in recipients so they can read their own message back from
    history. Returns a JSON-serialisable envelope dict."""
    if not recipients:
        raise ValueError("refusing to build an envelope with zero recipients")

    content_key = nacl.utils.random(SecretBox.KEY_SIZE)          # 32 bytes
    body = bytes(SecretBox(content_key).encrypt(plaintext.encode("utf-8")))

    wraps = {}
    for rid, vk_bytes in recipients.items():
        curve_pub = VerifyKey(vk_bytes).to_curve25519_public_key()
        wraps[rid] = b64e(bytes(SealedBox(curve_pub).encrypt(content_key)))

    vk_bytes = bytes(signing_key.verify_key)
    env = {
        "v": PROTOCOL_VERSION,
        "type": "msg",
        "sender": user_id(vk_bytes),
        "sender_vk": b64e(vk_bytes),
        "ts": int(time.time()),
        "body": b64e(body),
        "wraps": wraps,
    }
    env["sig"] = b64e(signing_key.sign(canonical(env)).signature)
    return env


def open_envelope(env: dict, my_id: str, signing_key: SigningKey) -> str:
    """Verify + decrypt. Raises on tampering, wrong sender id, or if you are
    not a listed recipient. Returns the plaintext."""
    sender_vk_bytes = b64d(env["sender_vk"])

    # 1. the claimed sender id must actually be the hash of the attached key.
    #    stops a relay from re-signing under its own key while keeping a
    #    victim's displayed identity.
    if user_id(sender_vk_bytes) != env["sender"]:
        raise ValueError("sender id does not match sender_vk")

    # 2. verify the signature over everything except `sig`.
    unsigned = {k: v for k, v in env.items() if k != "sig"}
    VerifyKey(sender_vk_bytes).verify(canonical(unsigned), b64d(env["sig"]))

    # 3. unwrap the content key meant for us, then open the body.
    wrap = env["wraps"].get(my_id)
    if wrap is None:
        raise ValueError("not a recipient of this message")
    curve_priv = signing_key.to_curve25519_private_key()
    content_key = SealedBox(curve_priv).decrypt(b64d(wrap))
    plaintext = SecretBox(content_key).decrypt(b64d(env["body"]))
    return plaintext.decode("utf-8")


# ---------------------------------------------------------------------------
# server-side structural validation
# ---------------------------------------------------------------------------
def validate_envelope_shape(env) -> bool:
    """The server runs this on every posted message. It cannot decrypt (it has
    no keys) but it refuses anything that is not a well-formed E2EE envelope.
    This is what makes the room 'require the app': plaintext will not pass.

    HONEST LIMIT: this enforces *shape*, not *confidentiality*. A hostile
    client could put readable data inside a valid-looking envelope. The server
    cannot detect that. Confidentiality relies on every participant running an
    honest client. See PROTOCOL.md."""
    if not isinstance(env, dict):
        return False
    if env.get("v") != PROTOCOL_VERSION or env.get("type") != "msg":
        return False
    required = ("sender", "sender_vk", "ts", "body", "wraps", "sig")
    if not all(k in env for k in required):
        return False
    if not isinstance(env["wraps"], dict) or not env["wraps"]:
        return False
    try:
        # base64 fields must actually decode; ids must be hash of the key.
        vk = b64d(env["sender_vk"])
        b64d(env["body"])
        b64d(env["sig"])
        for w in env["wraps"].values():
            b64d(w)
        if user_id(vk) != env["sender"]:
            return False
    except Exception:
        return False
    return True


# ---------------------------------------------------------------------------
# newline-delimited JSON framing over the SSH channel
# ---------------------------------------------------------------------------
def encode_frame(obj: dict) -> str:
    return json.dumps(obj, separators=(",", ":")) + "\n"


def decode_frame(line: str):
    return json.loads(line)


__all__ = [
    "PROTOCOL_VERSION", "b64e", "b64d", "canonical", "user_id", "fingerprint",
    "build_envelope", "open_envelope", "validate_envelope_shape",
    "encode_frame", "decode_frame", "CryptoError", "BadSignatureError",
]