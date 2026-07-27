"""Tests for base platform HTTP request construction."""

from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from scripts.soc_client.base import PlatformClient


class FakeResponse:
    status = 200
    headers = {"Content-Type": "application/json"}

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self, _limit):
        return json.dumps({"ok": True}).encode("utf-8")


class FakeOpener:
    def open(self, request, timeout):
        self.request = request
        self.timeout = timeout
        return FakeResponse()


class PlatformClientRequestTests(unittest.TestCase):
    def test_request_builds_headers_without_type_error(self):
        client = PlatformClient("https://example.com", "example")
        opener = FakeOpener()
        with patch("urllib.request.build_opener", return_value=opener):
            result = client.get("/", headers={"X-Test": "yes"})

        self.assertEqual(result, {"ok": True})
        self.assertEqual(opener.timeout, 30)


if __name__ == "__main__":
    raise SystemExit(unittest.main())
