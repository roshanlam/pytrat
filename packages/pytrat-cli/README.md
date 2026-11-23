# pytrat-cli

The `pytrat` developer command for PyTraT (OAuth Transaction Tokens).

```bash
pip install pytrat-cli          # or: pip install "pytrat[cli]"
```

```bash
pytrat demo                                               # watch a $100 -> $9,000 attack fail
pytrat init my-service                                    # runnable starter: keys, TTS, service, tests
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

Every command and option: <https://pytrat.readthedocs.io/en/latest/guides/cli/>.

Apache-2.0.
