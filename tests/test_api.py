import importlib
import os

from fastapi.testclient import TestClient

import crucible.core.api


def test_default_cors_origins() -> None:
    # Ensure environment variable is clear
    if "CRUCIBLE_ALLOWED_ORIGINS" in os.environ:
        del os.environ["CRUCIBLE_ALLOWED_ORIGINS"]

    # Reload api module to apply env var settings
    importlib.reload(crucible.core.api)

    client = TestClient(crucible.core.api.app)

    # Test allowed origin
    headers = {"Origin": "http://localhost:3000"}
    response = client.get("/", headers=headers)
    assert response.status_code == 200
    assert (
        response.headers.get("access-control-allow-origin") == "http://localhost:3000"
    )

    # Test disallowed origin
    headers = {"Origin": "http://evil.com"}
    response = client.get("/", headers=headers)
    assert "access-control-allow-origin" not in response.headers


def test_custom_cors_origins() -> None:
    os.environ["CRUCIBLE_ALLOWED_ORIGINS"] = (
        "https://dashboard.crucible.enterprise,https://admin.crucible.enterprise"
    )
    try:
        importlib.reload(crucible.core.api)

        client = TestClient(crucible.core.api.app)

        # Test allowed custom origin
        headers = {"Origin": "https://dashboard.crucible.enterprise"}
        response = client.get("/", headers=headers)
        assert response.status_code == 200
        assert (
            response.headers.get("access-control-allow-origin")
            == "https://dashboard.crucible.enterprise"
        )

        # Test disallowed origin
        headers = {"Origin": "http://localhost:3000"}
        response = client.get("/", headers=headers)
        assert "access-control-allow-origin" not in response.headers
    finally:
        del os.environ["CRUCIBLE_ALLOWED_ORIGINS"]


def test_wildcard_cors_origin() -> None:
    os.environ["CRUCIBLE_ALLOWED_ORIGINS"] = "*"
    try:
        importlib.reload(crucible.core.api)

        client = TestClient(crucible.core.api.app)

        # Test wildcard origin
        headers = {"Origin": "http://random-domain.com"}
        response = client.get("/", headers=headers)
        assert response.headers.get("access-control-allow-origin") == "*"
    finally:
        del os.environ["CRUCIBLE_ALLOWED_ORIGINS"]
