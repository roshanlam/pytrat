# pytrat-cli

The `pytrat` developer command for PyTraT (OAuth Transaction Tokens).

```bash
pip install pytrat-cli
```

```bash
pytrat version                                            # implemented draft revisions
pytrat keys generate --kid tts-2026-11 --out keys/        # 0600 PEM + public JWKS
pytrat keys jwks tts-2026-11=ES256=keys/tts-2026-11.pem   # combine keys for rotation
pytrat policy check policy.yaml --trust-domain payments.internal
pytrat token inspect --jwks keys/tts-2026-11.jwks.json --trust-domain payments.internal < token.txt
pytrat tts serve --config tts.yaml                        # the reference TTS
```

The CLI never prints secrets: private keys go only to files created with mode `0600`, tokens are
read from standard input (never from arguments), and inspection never prints the signature. Without
`--jwks`, `token inspect` labels its output `UNVERIFIED`.

## Documentation

PyTraT documentation: *CLI* (every command and option; sources in `docs/` of the repository).

Apache-2.0.
