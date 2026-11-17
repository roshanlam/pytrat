# check=skip=FromPlatformFlagConstDisallowed
# Coverage-guided fuzzing image for PyTraT (see fuzz/README.md).
#
# Atheris publishes manylinux x86-64 wheels only, so the image is pinned to linux/amd64; on an
# arm64 host Docker runs it under emulation. Build from the repository root:
#
#     docker build -f fuzz/Dockerfile -t pytrat-fuzz .
#     docker run --rm pytrat-fuzz 60            # every harness, 60 s each
#     docker run --rm pytrat-fuzz 300 jwks      # one harness
ARG PYTHON_VERSION=3.13
FROM --platform=linux/amd64 python:${PYTHON_VERSION}-slim

COPY --from=ghcr.io/astral-sh/uv:0.13.5 /uv /bin/uv

ENV UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/opt/venv \
    PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /src
COPY . .
RUN uv sync --frozen --all-packages --no-dev --group fuzz \
    && python -c "import atheris, pytrat.core, pytrat.server, pytrat.client, pytrat.policy, pytrat.agents"

ENTRYPOINT ["fuzz/run.sh"]
CMD ["60"]
