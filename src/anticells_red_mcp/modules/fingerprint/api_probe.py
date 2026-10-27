"""API-level probing — discover rate limits, moderation layers, and endpoint behavior."""

import time
from typing import Any, Dict, List, Optional, Tuple

import httpx
from ..utils.safe_http import make_http_client
from ...catalog.runtime import snapshot_for
from ...catalog.model import CatalogError


class ApiProber:
    """Probes the target LLM API for configuration and rate-limit information."""

    def __init__(self):
        self._catalog = snapshot_for()
        self._http_client: Optional[httpx.AsyncClient] = None

    def _get_client(self) -> httpx.AsyncClient:
        if self._http_client is None:
            self._http_client = make_http_client(timeout=30.0)
        return self._http_client

    async def close(self):
        if self._http_client:
            await self._http_client.aclose()
            self._http_client = None

    async def probe_endpoint(
        self, url: str, payload: str, headers: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """Send a probe to the API and capture response metadata."""
        client = self._get_client()
        start = time.monotonic()

        try:
            response = await client.post(
                url,
                json={
                    "model": "gpt-4o-mini",
                    "messages": [{"role": "user", "content": payload}],
                    "max_tokens": 100,
                },
                headers=headers or {"Content-Type": "application/json"},
                timeout=30.0,
            )
            elapsed = time.monotonic() - start

            response_headers = dict(response.headers)

            return {
                "status_code": response.status_code,
                "response_time_ms": round(elapsed * 1000),
                "headers": {k: v for k, v in response_headers.items()
                           if k.lower() in ("server", "x-request-id", "x-ratelimit-limit",
                                            "x-ratelimit-remaining", "x-ratelimit-reset",
                                            "x-model", "openai-version", "content-type",
                                            "retry-after", "cf-ray")},
                "body_length": len(response.text),
                "has_error": response.status_code >= 400,
                "rate_limited": response.status_code == 429,
            }
        except httpx.ConnectError:
            return {"error": "connection_failed", "response_time_ms": round((time.monotonic() - start) * 1000)}
        except httpx.TimeoutException:
            return {"error": "timeout", "response_time_ms": round((time.monotonic() - start) * 1000)}
        except CatalogError:
            raise
        except Exception as e:
            return {"error": str(e), "response_time_ms": round((time.monotonic() - start) * 1000)}

    async def check_rate_limits(self, url: str, num_requests: int = 5) -> Dict[str, Any]:
        """Burst requests to discover rate-limit thresholds."""
        client = self._get_client()
        results = []
        rate_limited_at = None

        for i in range(num_requests):
            try:
                response = await client.post(
                    url,
                    json={
                        "model": "gpt-4o-mini",
                        "messages": [{"role": "user", "content": self._catalog.asset('fingerprint.api_probe/check_rate_limits_001')}],
                        "max_tokens": 10,
                    },
                    timeout=15.0,
                )

                hdr = dict(response.headers)
                result = {
                    "request_num": i + 1,
                    "status": response.status_code,
                    "rate_limit_limit": hdr.get("x-ratelimit-limit"),
                    "rate_limit_remaining": hdr.get("x-ratelimit-remaining"),
                    "rate_limit_reset": hdr.get("x-ratelimit-reset"),
                }
                results.append(result)

                if response.status_code == 429 and rate_limited_at is None:
                    rate_limited_at = i + 1
            except CatalogError:
                raise
            except Exception as e:
                results.append({"request_num": i + 1, "error": str(e)})

        return {
            "total_requests": num_requests,
            "successful": sum(1 for r in results if r.get("status") == 200),
            "rate_limited_at": rate_limited_at,
            "results": results,
        }

    async def detect_moderation_layer(self, url: str) -> Dict[str, Any]:
        """Probe for content moderation / filtering at the API level."""
        test_payloads = [
            {"label": "benign", "content": self._catalog.asset('fingerprint.api_probe/detect_moderation_layer_001')},
            {"label": "borderline", "content": self._catalog.asset('fingerprint.api_probe/detect_moderation_layer_002')},
            {"label": "harmful", "content": self._catalog.asset('fingerprint.api_probe/detect_moderation_layer_003')},
        ]

        results = {}
        for test in test_payloads:
            probe_result = await self.probe_endpoint(url, test["content"])
            results[test["label"]] = probe_result

        return {
            "has_moderation": any(
                r.get("status_code") in (400, 403, 451)
                for r in results.values()
            ),
            "probe_results": results,
        }