#!/bin/sh
# Starts a self-contained Tokenetes test stack in one container:
#   SPIRE server + agent (join token, unix workload attestor)  -> SPIFFE identities by uid
#   mock tconfigd (uid 1002)                                    -> configuration + JWKS relay
#   Tokenetes (uid 1001)                                        -> the Transaction Token Service
#   tokenetes-agent (uid 1004)                                  -> the Tokenetes verifier
# and writes an X.509-SVID for spiffe://interop.test/gateway (uid 1003) to /run/interop-out, so the
# host test run can call Tokenetes' mTLS token endpoint as an authorized requesting workload.
set -eu

TD=interop.test
SOCK=/run/spire/sockets/agent.sock
SERVER=/opt/spire/bin/spire-server
AGENT=/opt/spire/bin/spire-agent

mkdir -p /run/spire/sockets /opt/spire/data/server /opt/spire/data/agent /run/tconfigd /run/interop-out
chown 1002 /run/tconfigd

"$SERVER" run -config /etc/interop/spire/server.conf &
until "$SERVER" healthcheck >/dev/null 2>&1; do sleep 0.5; done

JOIN_TOKEN=$("$SERVER" token generate -spiffeID "spiffe://$TD/node" | awk '{print $2}')
for entry in tokenetes:1001 tconfigd:1002 gateway:1003 tokenetes-agent:1004; do
    "$SERVER" entry create -parentID "spiffe://$TD/node" -spiffeID "spiffe://$TD/${entry%%:*}" \
        -selector "unix:uid:${entry##*:}" >/dev/null
done

"$AGENT" run -config /etc/interop/spire/agent.conf -joinToken "$JOIN_TOKEN" &
until "$AGENT" healthcheck -socketPath "$SOCK" >/dev/null 2>&1; do sleep 0.5; done
chmod 0777 /run/spire/sockets

fetch_svid() {  # uid, directory
    until su-exec "$1" "$AGENT" api fetch x509 -socketPath "$SOCK" -write "$2" >/dev/null 2>&1; do
        sleep 1
    done
}

fetch_svid 1002 /run/tconfigd
su-exec 1002 env TCONFIGD_SVID_DIR=/run/tconfigd python3 /opt/interop/mock_tconfigd.py &

fetch_svid 1003 /run/interop-out
chmod 0644 /run/interop-out/*

export TCONFIGD_HOST=127.0.0.1:8443
export TCONFIGD_SPIFFE_ID="spiffe://$TD/tconfigd"
export SPIFFE_ENDPOINT_SOCKET="unix://$SOCK"
export MY_NAMESPACE=interop

(cd /app && exec su-exec 1001 ./tokenetes) &
(cd /opt/interop && AGENT_API_PORT=9030 AGENT_INTERCEPTOR_PORT=9050 INTERCEPTION_MODE=false \
    exec su-exec 1004 ./tokenetes-agent) &

# The compose healthcheck reports the stack unhealthy if Tokenetes or the agent disconnects.
wait
