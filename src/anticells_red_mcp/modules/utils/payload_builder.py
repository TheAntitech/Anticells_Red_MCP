import base64
import codecs
import random
import string
import urllib.parse
from typing import Any, Dict, List, Optional, Union


class PayloadBuilder:
    def __init__(self):
        self._default_obfuscation_chars = string.ascii_letters + string.digits
        self._built_payloads: Dict[str, Dict[str, Any]] = {}

    def build(self, technique: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        params = params or {}
        payload = {
            "technique": technique,
            "params": params,
            "content": None,
            "encoding": None,
            "obfuscation_level": 0,
            "metadata": {
                "built_at": None,
                "source_params": params.copy(),
            },
        }
        import datetime
        payload["metadata"]["built_at"] = datetime.datetime.now().isoformat()
        return payload

    def customize(self, payload: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        customized = payload.copy()
        customized["params"] = {**payload.get("params", {}), **context}
        customized["metadata"] = {**customized.get("metadata", {}), "context": context}
        return customized

    def combine(
        self,
        payloads: List[Dict[str, Any]],
        strategy: str = "sequential",
        separator: str = "\n",
    ) -> Dict[str, Any]:
        if strategy == "sequential":
            content_parts = []
            for p in payloads:
                c = p.get("content", "")
                if c is not None:
                    content_parts.append(str(c))
            combined_content = separator.join(content_parts)
        elif strategy == "interleave":
            max_len = max(
                len(p.get("content", "")) if isinstance(p.get("content"), str) else 0
                for p in payloads
            )
            chars: List[str] = []
            for i in range(max_len):
                for p in payloads:
                    c = p.get("content", "")
                    if isinstance(c, str) and i < len(c):
                        chars.append(c[i])
            combined_content = "".join(chars)
        elif strategy == "wrap":
            if len(payloads) >= 2:
                combined_content = f"{payloads[0].get('content', '')}{payloads[1].get('content', '')}{payloads[0].get('content', '')}"
            else:
                combined_content = payloads[0].get("content", "") if payloads else ""
        else:
            content_parts = [str(p.get("content", "")) for p in payloads]
            combined_content = separator.join(content_parts)

        return {
            "technique": "combined",
            "params": {"strategy": strategy, "source_count": len(payloads)},
            "content": combined_content,
            "encoding": None,
            "obfuscation_level": 0,
            "metadata": {
                "sources": [p.get("technique") for p in payloads],
                "strategy": strategy,
            },
        }

    def encode(self, payload: Dict[str, Any], encoding: str = "base64") -> Dict[str, Any]:
        content = payload.get("content", "")
        if content is None:
            content = ""

        if not isinstance(content, str):
            content = str(content)

        content_bytes = content.encode("utf-8", errors="replace")

        if encoding == "base64":
            encoded = base64.b64encode(content_bytes).decode("ascii")
        elif encoding == "hex":
            encoded = content_bytes.hex()
        elif encoding == "rot13":
            encoded = codecs.encode(content, "rot_13")
        elif encoding == "url":
            encoded = urllib.parse.quote(content)
        elif encoding == "unicode_escape":
            encoded = content.encode("unicode_escape").decode("ascii")
        else:
            raise ValueError(f"Unsupported encoding: {encoding}")

        result = payload.copy()
        result["content"] = encoded
        result["encoding"] = encoding
        return result

    def decode(self, payload: Dict[str, Any], encoding: str = "base64") -> Dict[str, Any]:
        content = payload.get("content", "")
        if content is None:
            content = ""

        if not isinstance(content, str):
            content = str(content)

        if encoding == "base64":
            decoded = base64.b64decode(content).decode("utf-8", errors="replace")
        elif encoding == "hex":
            decoded = bytes.fromhex(content).decode("utf-8", errors="replace")
        elif encoding == "rot13":
            decoded = codecs.decode(content, "rot_13")
        elif encoding == "url":
            decoded = urllib.parse.unquote(content)
        elif encoding == "unicode_escape":
            decoded = content.encode("ascii").decode("unicode_escape")
        else:
            raise ValueError(f"Unsupported encoding: {encoding}")

        result = payload.copy()
        result["content"] = decoded
        result["encoding"] = None
        return result

    def obfuscate(self, payload: Dict[str, Any], level: int = 1) -> Dict[str, Any]:
        content = payload.get("content", "")
        if content is None:
            content = ""

        if not isinstance(content, str):
            content = str(content)

        obfuscated = content
        if level >= 1:
            obfuscated = "".join(
                f"\u200b{ch}" if ch.isalpha() else ch
                for ch in obfuscated
            )
        if level >= 2:
            parts = []
            for ch in obfuscated:
                if ch.isalpha():
                    parts.append(f"\\x{ord(ch):02x}")
                else:
                    parts.append(ch)
            obfuscated = "".join(parts)
        if level >= 3:
            shuffled = list(obfuscated)
            random.shuffle(shuffled)
            obfuscated = "".join(shuffled)

        result = payload.copy()
        result["content"] = obfuscated
        result["obfuscation_level"] = level
        return result