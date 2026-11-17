"""Settings for the ledger example. Keys are read from JWKS files named by environment variables."""

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY", "insecure-example-only")
DEBUG = False
ALLOWED_HOSTS = ["localhost", "127.0.0.1"]
ROOT_URLCONF = "ledger.urls"
USE_TZ = True

INSTALLED_APPS = ["pytrat.django"]
MIDDLEWARE = ["pytrat.django.middleware.TransactionMiddleware"]

PYTRAT = {
    "ENFORCER": "ledger.security.build_enforcer",
    "POLICY": str(BASE_DIR / "policy.yaml"),
    "PROTECTED_PREFIXES": ["/internal/"],
    "DEBUG_ERRORS": DEBUG,
}
