"""Coverage-guided fuzz harnesses (Atheris) for every PyTraT parser that sees untrusted input.

Each ``fuzz_<target>.py`` module defines ``TestOneInput(data: bytes)`` and ``seeds()``. See
``fuzz/README.md``.
"""
