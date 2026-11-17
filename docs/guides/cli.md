# CLI

`pytrat-cli` installs the `pytrat` command: development keys, policy validation, token
inspection and the reference TTS.

```bash
uv add --dev pytrat-cli
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
