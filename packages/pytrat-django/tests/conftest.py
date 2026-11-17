from __future__ import annotations

import sys
from collections.abc import Iterator
from pathlib import Path

import django
import pytest
from django.conf import settings
from django.test import AsyncClient, Client

sys.path.insert(0, str(Path(__file__).parent))

import pytrat_django_support as support

TEST_SETTINGS = support.TEST_SETTINGS
reload_runtime = support.reload_runtime

# All packages' tests share one process: configure Django once, only if nobody else has.
if not settings.configured:
    settings.configure(
        DEBUG=False,
        SECRET_KEY="pytrat-django-tests",
        ALLOWED_HOSTS=["testserver"],
        INSTALLED_APPS=["pytrat.django"],
        USE_TZ=True,
        **TEST_SETTINGS,
    )
    django.setup()


@pytest.fixture(autouse=True)
def world(settings_override) -> Iterator[support.World]:
    fresh = support.World()
    previous = support.CURRENT["world"]
    support.CURRENT["world"] = fresh
    reload_runtime()
    yield fresh
    support.CURRENT["world"] = previous
    reload_runtime()


@pytest.fixture
def settings_override() -> Iterator[None]:
    from django.test.utils import override_settings

    with override_settings(**TEST_SETTINGS):
        yield


@pytest.fixture
def client() -> Client:
    return Client()


@pytest.fixture
def async_client() -> AsyncClient:
    return AsyncClient()
