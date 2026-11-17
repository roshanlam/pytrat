# syntax=docker/dockerfile:1
#
# One image for every container of the payment-transfer Compose demo (init, tts, gateway,
# payment, ledger, client). The build context is the repository root; see compose.yaml.
#
# No key material, certificate or secret is ever written into the image: the `init` container
# generates all of it into Docker volumes at startup.

ARG PYTHON_IMAGE=python:3.12-slim-bookworm
ARG UV_IMAGE=ghcr.io/astral-sh/uv:0.13.5

FROM ${UV_IMAGE} AS uv

# ---------------------------------------------------------------- build: resolve and install
FROM ${PYTHON_IMAGE} AS build
COPY --from=uv /uv /bin/uv
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=0 \
    UV_PROJECT_ENVIRONMENT=/opt/venv
WORKDIR /src

# Third-party dependencies first, in their own layer. Only the workspace members the demo runs
# (pytrat-server and pytrat-fastapi) and their dependencies are installed.
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    --mount=type=bind,source=packages,target=packages \
    uv sync --frozen --no-dev --no-install-workspace \
        --package pytrat-server --package pytrat-fastapi

# Then the workspace packages themselves, as regular (non-editable) installs into the venv.
COPY pyproject.toml uv.lock ./
COPY packages ./packages
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-editable \
        --package pytrat-server --package pytrat-fastapi

# ---------------------------------------------------------------- runtime
FROM ${PYTHON_IMAGE} AS runtime

# One unprivileged user. Mount points exist in the image, owned by that user, so fresh named
# volumes inherit the ownership; private mount points are 0700.
RUN groupadd --system --gid 10001 pytrat \
 && useradd --system --uid 10001 --gid pytrat --no-create-home --home-dir /nonexistent \
        --shell /usr/sbin/nologin pytrat \
 && install -d -o pytrat -g pytrat -m 0755 /pki /pki/public /pki/out \
 && install -d -o pytrat -g pytrat -m 0700 /pki/private \
        /pki/out/tts /pki/out/gateway /pki/out/payment /pki/out/ledger /pki/out/client

COPY --from=build /opt/venv /opt/venv
COPY examples/payment-transfer/payment_demo /app/payment_demo
RUN python -m compileall -q /app

ENV PATH=/opt/venv/bin:$PATH \
    PYTHONPATH=/app \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
WORKDIR /app
USER 10001:10001
EXPOSE 8443
# Each compose service sets its own command; running the image bare just prints usage.
CMD ["python", "-m", "payment_demo.container", "--help"]
