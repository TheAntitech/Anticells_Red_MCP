"""
LLM FINGERPRINT SCANNER
Identifies model family, provider, version, architecture, safety layers, context limits.
30+ probing techniques for complete behavioral fingerprinting.
"""

from ...reports.runtime import recorded, record_candidates
import asyncio
import json
import time
import re
import httpx
from typing import Dict, List, Optional, Any
from datetime import datetime

from ...mcp_server.config import MCPConfig
from ..utils.requests import fingerprint_request
from ..utils.chat_endpoint import make_chat_client, post_chat, response_text as extract_text, request_error, normalize_response
from ...mcp_server.targets import TargetConfigurationError
from ...catalog.runtime import snapshot_for
from ...catalog.model import CatalogError


class FingerprintScanner:
    """Probe and identify target LLM characteristics"""

    def __init__(self, config: MCPConfig):
        self.config = config
        self._catalog = snapshot_for(self.config)
        self._techniques_cache = None
        self._client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = make_chat_client(self.config, timeout=30.0, user_agent="anticells_red_mcp_fingerprint")
        return self._client

    async def close(self):
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    def get_techniques(self) -> List[Dict[str, Any]]:
        """Return all fingerprint techniques"""
        if self._techniques_cache:
            return self._techniques_cache

        self._techniques_cache = self._build_techniques()
        return self._techniques_cache

    def _build_techniques(self) -> List[Dict[str, Any]]:
        return self._catalog.techniques('fingerprint.scanner')

    async def scan(
        self,
        target_url: str,
        intensity: int = 3,
        technique_filter: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Run fingerprint scan against target"""
        techniques = self.get_techniques()

        if technique_filter:
            techniques = [t for t in techniques if t["name"] in technique_filter]

        techniques.sort(key=lambda t: t["weight"], reverse=True)
        num_to_try = min(len(techniques), intensity * 6)
        selected = techniques[:num_to_try]

        results = []
        indicators = []
        model_signatures: Dict[str, float] = {}
        all_responses: List[Dict[str, Any]] = []

        for technique in selected:
            result = await self._probe(target_url, technique)
            results.append(result)
            if result.get("success"):
                indicators.extend(result.get("indicators", []))
                for sig, conf in result.get("signatures", {}).items():
                    model_signatures[sig] = max(model_signatures.get(sig, 0), conf)
                all_responses.append({
                    "technique": technique["name"],
                    "category": technique.get("category"),
                    "refused": result.get("refused", False),
                    "response_text": result.get("response_text", ""),
                    "headers": result.get("headers", {}),
                    "latency_ms": result.get("latency_ms", 0),
                })

        detected_model = self._identify_model(model_signatures, all_responses)

        return {
            "model": detected_model.get("name", "unknown"),
            "provider": detected_model.get("provider", "unknown"),
            "confidence": detected_model.get("confidence", 0.0),
            "architecture": detected_model.get("architecture", "unknown"),
            "context_window": detected_model.get("context_window", 0),
            "safety_level": detected_model.get("safety_level", "unknown"),
            "techniques_used": len(results),
            "indicators": list(set(indicators)),
            "signatures": model_signatures,
            "vulnerabilities": self._assess_vulnerabilities(detected_model, results),
            "raw_results": results[:50],
        }

    @recorded('fingerprint')
    async def _probe(self, target_url: str, technique: Dict) -> Dict[str, Any]:
        """Execute a single fingerprint probe via real HTTP request"""
        start_time = time.monotonic()
        api_url = target_url or self.config.target_api_url
        if not api_url:
            return {
                "technique": technique["name"],
                "category": technique.get("category"),
                "success": False,
                "indicators": [],
                "signatures": {},
                "response_snippet": "No target API URL configured",
                "timestamp": datetime.now().isoformat(),
                "error": "no_target_url",
            }

        request_body = fingerprint_request(technique["payload"])

        try:
            client = await self._get_client()

            response = await post_chat(client, api_url, request_body, self.config, prompt=technique["payload"])
            latency_ms = (time.monotonic() - start_time) * 1000
            response_headers = dict(response.headers)
            status_code = response.status_code

            if response.status_code != 200:
                return {
                    "technique": technique["name"],
                    "category": technique.get("category"),
                    "success": False,
                    "indicators": [],
                    "signatures": {},
                    "response_snippet": f"HTTP {status_code}",
                    "timestamp": datetime.now().isoformat(),
                    "status_code": status_code,
                    "latency_ms": latency_ms,
                    "headers": response_headers,
                }

            body = normalize_response(response.json(), self.config)
            response_text = extract_text(body)
            if not response_text.strip():
                return {"technique": technique["name"], "category": technique.get("category"),
                        "success": False, "indicators": [], "signatures": {},
                        "response_snippet": "Empty or unsupported response", "error": "empty_response",
                        "status_code": status_code, "latency_ms": latency_ms}
            choices = body.get("choices", [])
            finish_reason = ""
            if choices:
                finish_reason = choices[0].get("finish_reason", "")

            usage = body.get("usage", {})
            model_from_response = body.get("model", "")
            response_id = body.get("id", "")

            indicators = []
            signatures: Dict[str, float] = {}
            refused = False

            # --- Analyze response headers ---
            server = response_headers.get("server", "").lower()
            x_request_id = response_headers.get("x-request-id", "")
            x_ratelimit = response_headers.get("x-ratelimit-remaining-requests", "")
            cf_ray = response_headers.get("cf-ray", "")
            via_header = response_headers.get("via", "")

            if "cloudflare" in server or cf_ray:
                indicators.append("cloudflare_proxy")
            if "openai" in server or "sophos" in server:
                signatures["openai"] = signatures.get("openai", 0) + 0.3
                indicators.append("openai_header")
            if "claude" in server or "anthropic" in response_headers.get("anthropic-version", ""):
                signatures["anthropic"] = signatures.get("anthropic", 0) + 0.4
                indicators.append("anthropic_header")
            if x_request_id:
                indicators.append("request_id_present")
            if x_ratelimit:
                indicators.append("rate_limit_headers")

            # --- Analyze response text for model self-identification ---
            text_lower = response_text.lower()

            openai_patterns = [
                (r"\bgpt-?4", "gpt4"),
                (r"\bgpt-?4o", "gpt4o"),
                (r"\bgpt-?4\s*turbo", "gpt4_turbo"),
                (r"\bgpt-?4\s*omni", "gpt4_omni"),
                (r"\bgpt-?3\.?5", "gpt35"),
                (r"\bopenai\b", "openai"),
                (r"\bchatgpt\b", "chatgpt"),
                (r"\bo1\b", "o1"),
                (r"\bo3\b", "o3"),
            ]
            for pattern, key in openai_patterns:
                if re.search(pattern, text_lower):
                    signatures[f"openai_{key}"] = signatures.get(f"openai_{key}", 0) + 0.4
                    indicators.append(f"identified_{key}")

            anthropic_patterns = [
                (r"\bclaude\s*[-.\s]*\d", "claude_versioned"),
                (r"\bclaude\b", "claude"),
                (r"\banthropic\b", "anthropic"),
                (r"\bsonnet\b", "sonnet"),
                (r"\bopus\b", "opus"),
                (r"\bhaiku\b", "haiku"),
            ]
            for pattern, key in anthropic_patterns:
                if re.search(pattern, text_lower) and "anthropic" not in key:
                    if re.search(pattern, text_lower):
                        signatures[f"anthropic_{key}"] = signatures.get(f"anthropic_{key}", 0) + 0.4
                        indicators.append(f"identified_{key}")
                elif re.search(pattern, text_lower):
                    signatures[f"anthropic_{key}"] = signatures.get(f"anthropic_{key}", 0) + 0.4
                    indicators.append(f"identified_{key}")

            google_patterns = [
                (r"\bgemini\b", "gemini"),
                (r"\bgoogle\b", "google"),
                (r"\bdeepmind\b", "deepmind"),
                (r"\bgemma\b", "gemma"),
            ]
            for pattern, key in google_patterns:
                if re.search(pattern, text_lower):
                    signatures[f"google_{key}"] = signatures.get(f"google_{key}", 0) + 0.4
                    indicators.append(f"identified_{key}")

            meta_patterns = [
                (r"\bllama\b", "llama"),
                (r"\bmeta\b", "meta"),
                (r"\bllama\s*[-.\s]*\d", "llama_versioned"),
            ]
            for pattern, key in meta_patterns:
                if re.search(pattern, text_lower):
                    signatures[f"meta_{key}"] = signatures.get(f"meta_{key}", 0) + 0.4
                    indicators.append(f"identified_{key}")

            mistral_patterns = [
                (r"\bmixtral\b", "mixtral"),
                (r"\bmistral\b", "mistral"),
            ]
            for pattern, key in mistral_patterns:
                if re.search(pattern, text_lower):
                    signatures[f"mistral_{key}"] = signatures.get(f"mistral_{key}", 0) + 0.4
                    indicators.append(f"identified_{key}")

            # --- Context window extraction ---
            ctx_match = re.search(r"(\d+)[,\s]*tokens?\s*(?:context|window|limit)", text_lower)
            if ctx_match:
                ctx_val = int(ctx_match.group(1).replace(",", ""))
                if ctx_val > 1000 and ctx_val < 2000000:
                    indicators.append(f"context_window_{ctx_val}")
                    signatures["context_window_identified"] = signatures.get("context_window_identified", 0) + 0.5

            # --- Safety refusal detection ---
            refusal_patterns = [
                r"\bi\s*(?:cannot|can'?t|am unable|am not able)\b",
                r"\bi\s*(?:apologize|sorry)[,;]?\s+but\s+i\s*(?:cannot|can'?t)",
                r"\b(?:against|violates?)\s+(?:my|our)\s+(?:policy|policies|guidelines|principles)",
                r"\bi'?m\s+(?:not|unable)\s+(?:comfortable|allowed|able|willing)",
                r"\b(?:i would|let me)\s+(?:not|refrain|decline)",
                r"\bas an (?:AI|artificial intelligence)\b.*\b(?:cannot|can'?t|unable)",
                r"\bthis request\b.*\b(?:harmful|dangerous|inappropriate|unethical|illegal)",
                r"\bcontent policy\b",
                r"\bsafety (?:guidelines|policy|protocol)\b",
                r"\bresponsible (?:AI|use)\b",
            ]
            if finish_reason in ("content_filter", "stop"):
                for pattern in refusal_patterns:
                    if re.search(pattern, text_lower):
                        refused = True
                        indicators.append("safety_refusal_detected")
                        break

            # Also check for model identity in body.model
            if model_from_response:
                model_lower = model_from_response.lower()
                if "gpt" in model_lower:
                    signatures["openai_model_field"] = signatures.get("openai_model_field", 0) + 0.6
                elif "claude" in model_lower:
                    signatures["anthropic_model_field"] = signatures.get("anthropic_model_field", 0) + 0.6
                elif "gemini" in model_lower:
                    signatures["google_model_field"] = signatures.get("google_model_field", 0) + 0.6
                elif "llama" in model_lower:
                    signatures["meta_model_field"] = signatures.get("meta_model_field", 0) + 0.6
                elif "mixtral" in model_lower or "mistral" in model_lower:
                    signatures["mistral_model_field"] = signatures.get("mistral_model_field", 0) + 0.6
                indicators.append(f"model_field_{model_from_response}")

            # --- Score aggregation per provider ---
            openai_score = sum(v for k, v in signatures.items() if k.startswith("openai"))
            anthropic_score = sum(v for k, v in signatures.items() if k.startswith("anthropic"))
            google_score = sum(v for k, v in signatures.items() if k.startswith("google"))
            meta_score = sum(v for k, v in signatures.items() if k.startswith("meta"))
            mistral_score = sum(v for k, v in signatures.items() if k.startswith("mistral"))

            final_signatures = {
                "gpt_family": min(openai_score, 1.0),
                "claude_family": min(anthropic_score, 1.0),
                "gemini_family": min(google_score, 1.0),
                "llama_family": min(meta_score, 1.0),
                "mistral_family": min(mistral_score, 1.0),
            }

            response_snippet = response_text[:300] if response_text else f"finish_reason={finish_reason}, model={model_from_response}"

            return {
                "technique": technique["name"],
                "category": technique.get("category"),
                "success": True,
                "indicators": list(set(indicators)),
                "signatures": final_signatures,
                "response_snippet": response_snippet,
                "response_text": response_text,
                "refused": refused,
                "headers": response_headers,
                "status_code": status_code,
                "latency_ms": round(latency_ms, 2),
                "finish_reason": finish_reason,
                "model_from_response": model_from_response,
                "usage": usage,
                "timestamp": datetime.now().isoformat(),
            }

        except (TargetConfigurationError, CatalogError):
            raise
        except httpx.TimeoutException:
            return {
                "technique": technique["name"],
                "category": technique.get("category"),
                "success": False,
                "indicators": [],
                "signatures": {},
                "response_snippet": "Request timed out",
                "timestamp": datetime.now().isoformat(),
                "latency_ms": (time.monotonic() - start_time) * 1000,
                "error": "timeout",
            }
        except httpx.ConnectError:
            return {
                "technique": technique["name"],
                "category": technique.get("category"),
                "success": False,
                "indicators": [],
                "signatures": {},
                "response_snippet": "Connection failed - target unreachable",
                "timestamp": datetime.now().isoformat(),
                "latency_ms": (time.monotonic() - start_time) * 1000,
                "error": "connection_failed",
            }
        except Exception as e:
            return {
                "technique": technique["name"],
                "category": technique.get("category"),
                "success": False,
                "indicators": [],
                "signatures": {},
                "response_snippet": request_error(e),
                "timestamp": datetime.now().isoformat(),
                "latency_ms": (time.monotonic() - start_time) * 1000,
                "error": type(e).__name__,
            }

    def _aggregate_provider_scores(self, signatures: Dict[str, float]) -> Dict[str, float]:
        """Aggregate raw signature scores into per-provider confidence scores"""
        return {
            "OpenAI": signatures.get("gpt_family", 0),
            "Anthropic": signatures.get("claude_family", 0),
            "Google": signatures.get("gemini_family", 0),
            "Meta": signatures.get("llama_family", 0),
            "Mistral": signatures.get("mistral_family", 0),
        }

    def _identify_model(self, signatures: Dict[str, float], responses: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        """Identify model from real signature scores and response analysis"""
        candidates = {
            "gpt-4o": {"provider": "OpenAI", "architecture": "GPT-4 Omni", "context_window": 128000, "safety_level": "high", "match_keys": ["gpt_family"]},
            "gpt-4-turbo": {"provider": "OpenAI", "architecture": "GPT-4 Turbo", "context_window": 128000, "safety_level": "high", "match_keys": ["gpt_family"]},
            "gpt-3.5-turbo": {"provider": "OpenAI", "architecture": "GPT-3.5 Turbo", "context_window": 16384, "safety_level": "medium", "match_keys": ["gpt_family"]},
            "claude-3.5-sonnet": {"provider": "Anthropic", "architecture": "Claude 3.5 Sonnet", "context_window": 200000, "safety_level": "very_high", "match_keys": ["claude_family"]},
            "claude-3-opus": {"provider": "Anthropic", "architecture": "Claude 3 Opus", "context_window": 200000, "safety_level": "very_high", "match_keys": ["claude_family"]},
            "gemini-1.5-pro": {"provider": "Google", "architecture": "Gemini 1.5 Pro", "context_window": 1000000, "safety_level": "high", "match_keys": ["gemini_family"]},
            "llama-3.1-70b": {"provider": "Meta", "architecture": "LLaMA 3.1 70B", "context_window": 128000, "safety_level": "medium", "match_keys": ["llama_family"]},
            "mixtral-8x7b": {"provider": "Mistral", "architecture": "Mixtral 8x7B MoE", "context_window": 32768, "safety_level": "low", "match_keys": ["mistral_family"]},
        }

        if not signatures:
            return {"name": "unknown", "provider": "unknown", "confidence": 0.0, "architecture": "unknown", "context_window": 0, "safety_level": "unknown"}

        # Rank candidates by sum of matching signature values
        scored = []
        for model, info in candidates.items():
            score = sum(signatures.get(k, 0) for k in info["match_keys"])
            if score > 0:
                scored.append((model, score, info))

        scored.sort(key=lambda x: x[1], reverse=True)

        if scored:
            best_model, best_score, best_info = scored[0]

            # Normalize confidence: if multiple probes contributed, higher confidence
            total_sig_sum = sum(signatures.values())
            confidence = min(best_score / max(total_sig_sum, 0.1), 1.0)

            # Boost confidence if we have multiple consistent probes
            if responses:
                positive_count = sum(1 for r in responses if r.get("response_text") and len(r.get("response_text", "")) > 0)
                if positive_count >= 3:
                    confidence = min(confidence * 1.3, 1.0)

            return {
                "name": best_model,
                "confidence": round(confidence, 4),
                **{k: v for k, v in best_info.items() if k != "match_keys"},
            }

        return {"name": "unknown", "provider": "unknown", "confidence": 0.0, "architecture": "unknown", "context_window": 0, "safety_level": "unknown"}

    def _assess_vulnerabilities(self, model: Dict, results: List[Dict]) -> List[str]:
        """Identify potential vulnerabilities based on real fingerprint results"""
        vulns = []
        safety = model.get("safety_level", "medium")

        if safety in ["low", "medium"]:
            vulns.append("Low safety resistance - susceptible to basic jailbreaks")
        elif safety == "high":
            vulns.append("High safety resistance - requires advanced jailbreak techniques")
        elif safety == "very_high":
            vulns.append("Very high safety resistance - only sophisticated multi-step jailbreaks may succeed")

        if model.get("context_window", 0) < 32000:
            vulns.append("Limited context window - vulnerable to context exhaustion attacks")
        elif model.get("context_window", 0) >= 128000:
            vulns.append("Large context window - long-context injection attacks may work")

        # Analyze real probe results
        refusal_count = 0
        success_count = 0
        openai_score = 0
        anthropic_score = 0
        safety_probe_refusals = 0

        for r in results:
            if r.get("success"):
                success_count += 1
            if r.get("refused"):
                refusal_count += 1
                if r.get("category") == "safety":
                    safety_probe_refusals += 1
            for sig_key, sig_val in r.get("signatures", {}).items():
                if sig_key.startswith("openai"):
                    openai_score += sig_val
                if sig_key.startswith("anthropic"):
                    anthropic_score += sig_val

        if success_count > 0:
            vulns.append(f"Fingerprint information disclosed via {success_count} successful probes - aids targeted attacks")

        if refusal_count > 0 and refusal_count >= success_count * 0.5:
            vulns.append("Strict safety filtering detected - may interfere with operational use")
        elif refusal_count == 0 and success_count > 3:
            vulns.append("No safety refusals detected - model highly permissive, critical risk")

        # Provider-specific assessments
        if anthropic_score > openai_score and anthropic_score > 0.5:
            vulns.append("Anthropic Claude detected - constitutional AI training, resistant to simple jailbreaks but susceptible to multi-turn persuasion")
        elif openai_score > 0.5:
            vulns.append("OpenAI GPT detected - instruction-following bias exploitable for roleplay-based jailbreaks")

        return vulns

    @recorded('fingerprint')
    async def execute(self, technique: Dict, attack_id: str) -> Any:
        """Execute a single technique (MCP-compatible)"""
        from ...mcp_server.engine import AttackResult
        result = await self._probe(self.config.target_api_url or "", technique)
        confidence = 0.0
        if result.get("success"):
            sigs = dict(result.get("signatures", {}))
            max_sig = max(sigs.values()) if sigs else 0
            refusal_penalty = 0.3 if result.get("refused") else 0
            confidence = min(max(0.5, max_sig - refusal_penalty), 0.99)
        return AttackResult(
            attack_id=attack_id,
            module="fingerprint",
            technique=technique["name"],
            payload=technique["payload"],
            success=result.get("success", False),
            confidence=confidence,
            response=result.get("response_snippet"),
            indicators=result.get("indicators", []),
            metadata=result,
        )
