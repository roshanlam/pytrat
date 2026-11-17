# Tokenetes interoperability stack for PyTraT's live `interop` tests. Test infrastructure only.
#
# Images are pinned by digest. The Tokenetes images are the upstream `latest` builds as of
# 2026-11-17 (tokenetes built 2026-07-30 from main @ f9b7acf; tokenetes-agent built 2025-04-14 from
# main @ b848c12). Upstream publishes no versioned image tags.
FROM ghcr.io/spiffe/spire-server:1.11.2 AS spire-server
FROM ghcr.io/spiffe/spire-agent:1.11.2 AS spire-agent
FROM ghcr.io/tokenetes/tokenetes-agent@sha256:22cc6a48385c2b9fa5650706506dfa02d92b9e8fcaddeceae95c90a5976cd777 AS tokenetes-agent

FROM ghcr.io/tokenetes/tokenetes@sha256:fa5c3947b8290c8b9952b06f6a7a3f9c43e8a1b18020d7028950cfee1102b4e3
RUN apk add --no-cache python3 py3-websockets su-exec
COPY --from=spire-server /opt/spire/bin/spire-server /opt/spire/bin/spire-server
COPY --from=spire-agent /opt/spire/bin/spire-agent /opt/spire/bin/spire-agent
COPY --from=tokenetes-agent /app/tokenetes-agent /opt/interop/tokenetes-agent
COPY spire/ /etc/interop/spire/
COPY rules/ /etc/interop/rules/
COPY mock_tconfigd.py entrypoint.sh /opt/interop/
ENTRYPOINT ["/bin/sh", "/opt/interop/entrypoint.sh"]
