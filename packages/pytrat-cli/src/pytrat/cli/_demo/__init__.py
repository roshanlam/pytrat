"""The payment-transfer demo behind ``pytrat demo``: one gateway, two internal services and a TTS.

``lab`` generates keys and configuration; ``services`` builds the four FastAPI apps; ``scenario``
deploys them in-process; ``narrative`` tells the story on the terminal. The repository's
``examples/payment-transfer`` reuses these modules for its socket and Docker Compose deployments.

Private: this is demonstration code, not API, and may change in any release.
"""
