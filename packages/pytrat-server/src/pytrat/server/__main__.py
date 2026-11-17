"""Run the reference TTS: ``python -m pytrat.server --config tts.yaml [--host H] [--port P]``."""

from __future__ import annotations

import argparse
from collections.abc import Sequence

import uvicorn

from pytrat.server.app import create_app_from_settings

__all__ = ["main"]


def main(argv: Sequence[str] | None = None) -> None:
    """Parse arguments, build the app from the configuration file and serve it with uvicorn.

    Raises:
        ConfigurationError: If the configuration is invalid (the process refuses to start).
    """
    parser = argparse.ArgumentParser(prog="python -m pytrat.server", description=__doc__)
    parser.add_argument("--config", required=True, help="path to the TTS YAML configuration")
    parser.add_argument("--host", default="127.0.0.1", help="bind address (default 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="bind port (default 8000)")
    args = parser.parse_args(argv)
    app = create_app_from_settings(args.config)
    uvicorn.run(app, host=args.host, port=args.port, server_header=False)


if __name__ == "__main__":  # pragma: no cover
    main()
