# pytrat-server

The reference **Transaction Token Service** for PyTraT: the token endpoint of
`draft-ietf-oauth-transaction-tokens-11` (RFC 8693 token exchange with RFC 7523 workload
authentication), replacement (§13.15), per-workload issuance policy with `tctx`/`rctx` allowlists,
key rotation, rate limiting, a hash-chained SQLite issuance log and the experimental agent profile.
It is the only PyTraT package that holds signing keys.

```bash
pip install pytrat-server
```

## Run it

```bash
python -m pytrat.server --config tts.yaml --host 127.0.0.1 --port 8000
```

Or embed it:

```python
from pytrat.server import build_components, create_app, load_settings

app = create_app(build_components(load_settings("tts.yaml")))
```

Routes: `POST /token`, `GET /.well-known/jwks.json`, `GET /healthz`. The configuration is validated
strictly at startup (unknown keys and wrong types stop the process); an annotated example is in
`examples/tts.yaml`.

Production notes: terminate TLS in front of it, set `audit_db_path`, keep private keys at mode
`0600`, and add an ingress rate limiter (the built-in limiter is per authenticated workload).

## Documentation

PyTraT documentation: *Running the TTS* (every configuration key) and the `pytrat.server` API
reference (sources in `docs/` of the repository).

Apache-2.0.
