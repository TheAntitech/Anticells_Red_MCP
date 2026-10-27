"""Model detection engine — identifies LLM model/provider from response patterns."""

import re
from typing import Any, Dict, List, Optional, Tuple

# Provider/Model fingerprints based on response headers, content patterns, and behaviors
MODEL_FINGERPRINTS: Dict[str, Dict[str, Any]] = {
    "openai/gpt-4o": {
        "provider": "OpenAI", "model_family": "GPT-4",
        "header_patterns": {"server": r"openai", "x-request-id": r"req_"},
        "content_patterns": [r"GPT", r"OpenAI", r"ChatGPT", r"GPT-4"],
        "refusal_phrases": [r"I('m| am) sorry", r"I cannot", r"I'm unable"],
    },
    "openai/gpt-4o-mini": {
        "provider": "OpenAI", "model_family": "GPT-4",
        "header_patterns": {"server": r"openai"},
        "content_patterns": [r"GPT-4o-mini", r"GPT-4o mini", r"smaller model"],
        "refusal_phrases": [r"I('m| am) sorry", r"I cannot"],
    },
    "openai/o1": {
        "provider": "OpenAI", "model_family": "o1",
        "header_patterns": {"server": r"openai"},
        "content_patterns": [r"o1", r"reasoning model", r"chain of thought"],
        "refusal_phrases": [r"I('m| am) sorry"],
    },
    "anthropic/claude-3.5-sonnet": {
        "provider": "Anthropic", "model_family": "Claude 3.5",
        "header_patterns": {"server": r"claude|anthropic"},
        "content_patterns": [r"Claude", r"Anthropic", r"I appreciate", r"I understand"],
        "refusal_phrases": [r"I apologize", r"I('m| am) not able", r"against my ethical"],
    },
    "anthropic/claude-3-opus": {
        "provider": "Anthropic", "model_family": "Claude 3",
        "header_patterns": {"server": r"claude|anthropic"},
        "content_patterns": [r"Claude", r"Anthropic", r"I will not", r"let me reflect"],
        "refusal_phrases": [r"I apologize", r"not appropriate"],
    },
    "google/gemini-1.5-pro": {
        "provider": "Google", "model_family": "Gemini",
        "header_patterns": {},
        "content_patterns": [r"Gemini", r"Google", r"as a language model"],
        "refusal_phrases": [r"I('m| am) not able", r"I cannot help with"],
    },
    "meta/llama-3.1-70b": {
        "provider": "Meta", "model_family": "Llama 3",
        "header_patterns": {},
        "content_patterns": [r"Llama", r"Meta AI", r"open source"],
        "refusal_phrases": [r"I cannot", r"I('m| am) not able to"],
    },
    "meta/llama-3.1-405b": {
        "provider": "Meta", "model_family": "Llama 3",
        "header_patterns": {},
        "content_patterns": [r"Llama 3.1", r"405", r"large model"],
        "refusal_phrases": [r"I cannot", r"I('m| am) not able to"],
    },
    "mistral/mistral-large": {
        "provider": "Mistral", "model_family": "Mistral Large",
        "header_patterns": {},
        "content_patterns": [r"Mistral", r"Le Chat", r"french"],
        "refusal_phrases": [r"I cannot", r"not possible"],
    },
    "cohere/command-r": {
        "provider": "Cohere", "model_family": "Command R",
        "header_patterns": {},
        "content_patterns": [r"Cohere", r"Command", r"retrieval"],
        "refusal_phrases": [r"I('m| am) not able", r"cannot provide"],
    },
    "deepseek/deepseek-v3": {
        "provider": "DeepSeek", "model_family": "DeepSeek V3",
        "header_patterns": {},
        "content_patterns": [r"DeepSeek", r"深度求索"],
        "refusal_phrases": [r"I cannot", r"unable to"],
    },
    "xai/grok": {
        "provider": "xAI", "model_family": "Grok",
        "header_patterns": {},
        "content_patterns": [r"Grok", r"xAI", r"Elon"],
        "refusal_phrases": [r"I cannot", r"not appropriate"],
    },
}

# Provider-specific header analysis
PROVIDER_HEADER_KEYS = {
    "OpenAI": ["x-request-id", "openai-version", "openai-organization"],
    "Anthropic": ["x-request-id", "request-id"],
    "Google": ["x-goog-api-key", "x-goog-request"],
    "Azure": ["apim-request-id", "x-ms-region"],
}


class ModelDetector:
    """Detects the target LLM model and provider from API responses."""

    def __init__(self):
        self._compiled_fingerprints: Dict[str, Dict] = {}
        self._compile_patterns()

    def _compile_patterns(self):
        for model_id, fp in MODEL_FINGERPRINTS.items():
            compiled = {
                "provider": fp["provider"],
                "model_family": fp["model_family"],
                "content_re": [re.compile(p, re.IGNORECASE) for p in fp["content_patterns"]],
                "refusal_re": [re.compile(p, re.IGNORECASE) for p in fp["refusal_phrases"]],
                "header_patterns": fp["header_patterns"],
            }
            self._compiled_fingerprints[model_id] = compiled

    def detect_from_response(
        self, response_text: str, headers: Optional[Dict[str, str]] = None, model_field: Optional[str] = None
    ) -> Dict[str, Any]:
        """Return best-guess model identification with confidence scores."""
        scores: Dict[str, float] = {}
        details: Dict[str, List[str]] = {}

        for model_id, fp in self._compiled_fingerprints.items():
            score = 0.0
            matches = []

            # Check API model field
            if model_field and model_field.lower() in model_id.lower():
                score += 2.0
                matches.append(f"model_field:{model_field}")

            # Check content patterns
            for pattern in fp["content_re"]:
                if pattern.search(response_text):
                    score += 0.5
                    matches.append(f"content:{pattern.pattern[:40]}")

            # Check headers
            if headers:
                for hdr_name, hdr_pattern in fp["header_patterns"].items():
                    hdr_val = headers.get(hdr_name, "")
                    if hdr_val and re.search(hdr_pattern, hdr_val, re.IGNORECASE):
                        score += 0.8
                        matches.append(f"header:{hdr_name}={hdr_val[:30]}")

            if score > 0:
                scores[model_id] = score
                details[model_id] = matches

        if not scores:
            return {"model": "unknown", "provider": "unknown", "confidence": 0.0, "candidates": []}

        # Sort by score descending
        ranked = sorted(scores.items(), key=lambda x: x[1], reverse=True)
        total_score = sum(s[1] for s in ranked)
        best_id, best_score = ranked[0]

        candidates = []
        for model_id, score in ranked[:5]:
            fp = self._compiled_fingerprints.get(model_id, {})
            candidates.append({
                "model_id": model_id,
                "provider": fp.get("provider", "unknown"),
                "model_family": fp.get("model_family", "unknown"),
                "score": round(score, 3),
                "confidence_pct": round(score / total_score * 100, 1) if total_score > 0 else 0.0,
                "indicators": details.get(model_id, []),
            })

        return {
            "model": best_id,
            "provider": self._compiled_fingerprints.get(best_id, {}).get("provider", "unknown"),
            "confidence": round(best_score / total_score, 3) if total_score > 0 else 0.0,
            "candidates": candidates,
        }

    def analyze_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Extract provider hints from response headers."""
        hints = {}
        for provider, keys in PROVIDER_HEADER_KEYS.items():
            for key in keys:
                val = headers.get(key)
                if val:
                    hints[provider] = val
                    break
        return hints