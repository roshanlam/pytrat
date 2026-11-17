# Deploying with Docker Compose

!!! info "Coming with M9"
    A Docker Compose deployment with TLS between the TTS and the services is part of milestone M9
    and is documented here when it lands.

Until then, `examples/payment-transfer/serve.py` runs the demo services and the reference TTS on
real sockets on `127.0.0.1`, and [Running the TTS](../guides/tts.md) has the production checklist.
