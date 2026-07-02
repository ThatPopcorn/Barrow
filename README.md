# onionchat

Anonymous, end-to-end-encrypted group chat over SSH, hosted behind a Tor onion
service. No signup. Your identity is a single ed25519 keypair — the same one
that authenticates you also encrypts your messages. The server relays and
stores only ciphertext; it cannot read anything.

```
you ──ed25519 SSH auth──▶ onion service ──▶ onionchat server (stores ciphertext)
        (TOFU, no signup)                     routes envelopes by recipient id
message body: E2EE (SecretBox + per-recipient SealedBox + ed25519 signature)
```

**Files**
- `protocol.py` — the crypto + wire format (the whole "protocol")
- `server.py` — the relay (asyncssh + SQLite)
- `client.py` — the minimal reference client
- `PROTOCOL.md` — spec so anyone can write their own client
- `test_e2e.py` — end-to-end test incl. "server stores only ciphertext"

## Install

```bash
pip install pynacl asyncssh python-socks PySocks
```

## Read this first (the honest part)

- The stock `ssh` binary **cannot** give you E2EE — it only encrypts the hop to
  the server, which would then see plaintext. That is exactly why a client is
  required. `ssh alice@…onion` will connect and just get a "use the client"
  notice. Real confidentiality needs `client.py` (or any client that speaks
  `PROTOCOL.md`).
- You **must** verify fingerprints out of band (`/verify`) or a malicious server
  can MITM the key directory. There is no forward secrecy. See §6 of
  `PROTOCOL.md` before trusting this with anything serious.

## Run the server behind Tor

1. Start the server on localhost only (Tor reaches it locally):

   ```bash
   python server.py --host 127.0.0.1 --port 8022
   ```

   It creates `ssh_host_ed25519_key` (stable host key) and `onionchat.db` on
   first run.

2. Publish it as an onion service. In `torrc`:

   ```
   HiddenServiceDir /var/lib/tor/onionchat/
   HiddenServicePort 8022 127.0.0.1:8022
   ```

   Reload Tor, then read the address:

   ```bash
   sudo cat /var/lib/tor/onionchat/hostname     # -> y782hd7….onion
   ```

Nothing about the server needs a public IP or DNS. Keep `--host 127.0.0.1` so
it is only reachable through the onion service.

## Connect (the client)

```bash
python client.py alice@y782hd7….onion
```

- `.onion` hosts are routed through Tor's SOCKS proxy at `127.0.0.1:9050`
  automatically. Make sure Tor is running locally.
- `alice` is only your requested nickname on first connect.
- Key selection: uses `~/.ssh/id_ed25519` if it exists, otherwise generates and
  reuses `~/.config/onionchat/id_ed25519`. Override with `--key PATH`.
  (Encrypted private keys: decrypt a copy first with
  `ssh-keygen -p -f <copy>` and an empty passphrase, or point `--key` at a
  dedicated unencrypted onionchat key.)

Commands once connected: `/who`, `/nick NAME`, `/fp`, `/verify NAME`,
`/history [N]`, `/quit`. Anything else you type is encrypted to every current
member and sent.

### Optional: reaching the onion with the stock `ssh` too

If you want `ssh alice@…onion` to at least connect (you'll only get the
"use the client" banner, since raw ssh can't do E2EE), add to `~/.ssh/config`:

```
Host *.onion
    ProxyCommand nc -X 5 -x 127.0.0.1:9050 %h %p
    StrictHostKeyChecking accept-new
```

## Test

```bash
python test_e2e.py
```

Spins up the real server, connects two independent keys, sends an encrypted
message, and asserts (among other things) that the plaintext is absent from the
server's database.

## Local testing without Tor

```bash
python server.py --port 8022
python client.py alice@127.0.0.1:8022 --no-tor --key /tmp/alice
python client.py bob@127.0.0.1:8022  --no-tor --key /tmp/bob
```
