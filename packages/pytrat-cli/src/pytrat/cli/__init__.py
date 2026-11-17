"""PyTraT developer CLI.

Commands never print secrets: private keys go only to files created with mode 0600, and token
inspection never prints the signature.
"""

from pytrat.cli.app import app, main

__all__ = ["app", "main"]
