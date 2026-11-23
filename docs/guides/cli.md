# CLI

`pytrat-cli` installs the `pytrat` command: a runnable demo, development keys, policy validation,
token inspection and the reference TTS.

```bash
pip install "pytrat[cli]"      # or: uv add --dev "pytrat[cli]"
pytrat --help
```

The CLI never prints secrets: private keys are written only to files created with mode `0600`,
tokens are read from standard input (never from arguments, which leak into shell history and
process listings), and token inspection never prints the signature. Every command exits with
status 1 and a message on standard error when it fails.

## Commands

### `pytrat version`

Show the specification revisions this release implements.

```console
$ pytrat version
transaction-tokens: draft-ietf-oauth-transaction-tokens-11
agent-profile: draft-araut-oauth-transaction-tokens-for-agents-03
```

No options.

### `pytrat init`

Create a runnable starter project: development keys for a TTS and a gateway, a TTS configuration,
a FastAPI service protected by PyTraT, its tests (which use the [`pytrat_kit`](testing.md)
fixture), and a gateway script that obtains a token and calls the service.

```console
$ pytrat init my-service --trust-domain example.internal
Created a PyTraT starter project in my-service/
$ cd my-service && pytest
5 passed
```

| Argument or option | Default | Meaning |
|---|---|---|
| `DIRECTORY` | `pytrat-starter` | Where to create the project. Created if missing. |
| `--trust-domain` | `example.internal` | Trust Domain the TTS issues tokens for and the service accepts. |
| `--force` / `--no-force` | `--no-force` | Overwrite files from an earlier `init`, including the keys. Without it, an existing file is never replaced. |

Private keys are written with mode `0600` and listed in the generated `.gitignore`. They are for
development only.

### `pytrat demo`

Run the payment-transfer story in-process: a gateway, a payment service, a ledger and the reference
TTS, with keys generated into a temporary directory. A $100 transfer is recorded; then a
compromised payment service rewrites it to $9,000, and the ledger refuses it with
`403 TRANSACTION_CONTEXT_MISMATCH` and prints the audit event explaining why.

```console
$ pytrat demo
...
2. payment-service is compromised and rewrites $100.00 to $9,000.00
   ledger: 403 refused (TRANSACTION_CONTEXT_MISMATCH)
   ledger entries recorded: 0
...
```

| Option | Default | Meaning |
|---|---|---|
| `--audit` / `--no-audit` | `--audit` | Print the ledger's audit event for the refused transfer. |

Nothing listens on a port and no token is printed. Exits with status 1 if the story does not hold,
which would be a bug.

### `pytrat keys generate`

Generate a signing key: a `0600` PEM private key and a public JWKS (development use).

```console
$ pytrat keys generate --kid tts-2026-11 --out keys/
private key: keys/tts-2026-11.pem (mode 0600)
public JWKS: keys/tts-2026-11.jwks.json
```

| Option | Default | Meaning |
|---|---|---|
| `--kid` | required | Key identifier to publish in the JWKS. Must be file-name safe (no `/`, no leading `.`). |
| `--out` | required | Directory for `<kid>.pem` and `<kid>.jwks.json`; created if missing. |
| `--alg` | `ES256` | Signing algorithm: `ES256`, `ES384`, `ES512`, `EdDSA`, `PS256`, `PS384`, `PS512`, `RS256`, `RS384` or `RS512`. |
| `--force` / `--no-force` | `--no-force` | Overwrite existing files. Without it, existing files are never replaced. |

### `pytrat keys jwks`

Print a public JWKS combining several keys, for example the active and the retiring key during
rotation.

```console
$ pytrat keys jwks tts-2026-11=ES256=keys/tts-2026-11.pem tts-2026-10=ES256=keys/tts-2026-10.pem
{"keys": [...]}
```

| Argument | Meaning |
|---|---|
| `KEYS` | One or more entries of the form `KID=ALG=PATH.pem`. The PEM may be a private or a public key; only the public half is printed. |

### `pytrat policy check`

Compile a policy file exactly as a service would at startup, and list its routes.

```console
$ pytrat policy check policy.yaml --trust-domain payments.internal
OK: 2 route(s)
  POST /internal/ledger/entries -> ledger-entry
  GET /internal/accounts/{account_id} -> account-read
```

| Argument / option | Default | Meaning |
|---|---|---|
| `PATH` | required | The policy YAML file. |
| `--trust-domain` | none | Fail unless the policy targets this Trust Domain. |

!!! note
    The check runs without a replay store or agent directory, so resources with
    `single_use: true` or `agents.require_verified_agent: true` are reported as invalid. See
    [Policies](policies.md#validating-a-policy).

### `pytrat token inspect`

Decode a token read from standard input. Without `--jwks` the output is labelled `UNVERIFIED`;
with it, the token is fully verified and only verified claims are printed. The signature is never
printed.

```console
$ pbpaste | pytrat token inspect --jwks keys/tts-2026-11.jwks.json --trust-domain payments.internal
VERIFIED (kid=tts-2026-11, alg=ES256)
{
  "header": {"alg": "ES256", "kid": "tts-2026-11", "typ": "txntoken+jwt"},
  "payload": {"aud": "payments.internal", "scope": "payments.transfer", "tctx": {...}, ...}
}
```

A rejected token prints `REJECTED: <REASON_CODE>: <check>` and exits with status 1.

| Option | Default | Meaning |
|---|---|---|
| `--jwks` | none | Trusted JWKS file. When given, the token is verified. |
| `--trust-domain` | none | Trust Domain for verification; required with `--jwks`. |
| `--alg` | `ES256`, `EdDSA`, `PS256` | Allowed algorithm; repeat the option to allow several. |
| `--max-lifetime` | `300` | Maximum `exp - iat` in seconds. |

### `pytrat tts serve`

Run the reference Transaction Token Service with uvicorn. See [Running the TTS](tts.md) for the
configuration file.

```console
$ pytrat tts serve --config tts.yaml --port 8080
```

| Option | Default | Meaning |
|---|---|---|
| `--config` | required | TTS YAML configuration file (must exist). |
| `--host` | `127.0.0.1` | Bind address. |
| `--port` | `8080` | Bind port. |

`python -m pytrat.server --config tts.yaml` is equivalent (default port `8000`) and additionally
suppresses uvicorn's `Server` header.
