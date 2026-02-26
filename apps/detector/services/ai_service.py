import hashlib
import json
import os
import re
from typing import Any, Dict

import openai
from django.core.cache import cache

# Lazy initialization flag
_initialized = False


def _get_client():
    """Initialize OpenAI client (set API key) and return the `openai` module.

    Attempts the following environment variables, in order:
    - `OPENAI_API_KEY`
    - `OPENAI_KEY`
    - `GOOGLE_API_KEY` (fallback when migrating)
    Values are first read from `os.environ`; if not present we try
    `decouple.config()` to allow reading from a local `.env` file.
    """
    global _initialized
    if _initialized:
        return openai

    api_key = os.getenv("OPENAI_API_KEY") or os.getenv("OPENAI_KEY") 
    if not api_key:
        try:
            from decouple import config
            api_key = config('OPENAI_API_KEY', default=None) or config('OPENAI_KEY', default=None)
        except Exception:
            api_key = None

    if not api_key:
        raise ValueError(
            "OPENAI_API_KEY (or OPENAI_KEY / GOOGLE_API_KEY) environment variable is not set. "
            "Please set it before using the AI service."
        )

    openai.api_key = api_key
    _initialized = True
    return openai


def _extract_json_from_text(text: str) -> Dict[str, Any]:
    """Try to extract the first JSON object from model text output and parse it.

    This is tolerant to some common formatting issues (like surrounding text
    or single quotes) but will raise ValueError if parsing fails.
    """
    # Find the first {...} block
    m = re.search(r"\{.*\}", text, flags=re.S)
    if not m:
        raise ValueError("No JSON object found in model response")
    s = m.group(0)
    try:
        return json.loads(s)
    except json.JSONDecodeError:
        # Try a quick fix: replace single quotes with double quotes
        try:
            fixed = s.replace("'", '"')
            return json.loads(fixed)
        except json.JSONDecodeError as e:
            raise ValueError(f"Failed to parse JSON from model response: {e}")


def _generate_structured(prompt: str) -> Dict[str, Any]:
    """Call OpenAI Responses API with the prompt and extract JSON from the reply."""
    try:
        # cache key based on prompt hash to avoid repeated model calls
        prompt_hash = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
        cache_key = f"ai:prompt:{prompt_hash}"
        cached = cache.get(cache_key)
        if cached is not None:
            return cached

        client = _get_client()
        resp = client.responses.create(
            model="gpt-5-mini",
            input=prompt,
            max_output_tokens=1024,
        )

        # Try common extraction points for the returned text. New SDKs
        # provide `output_text` on the response or structured `output`.
        text = None
        if hasattr(resp, 'output_text') and getattr(resp, 'output_text'):
            text = resp.output_text
        else:
            out = None
            try:
                out = getattr(resp, 'output')
            except Exception:
                out = resp.get('output') if isinstance(resp, dict) else None

            if out and isinstance(out, list) and len(out) > 0:
                first = out[0]
                if isinstance(first, dict):
                    content = first.get('content') or first.get('data') or None
                    if isinstance(content, list) and len(content) > 0:
                        piece = content[0]
                        if isinstance(piece, dict):
                            text = piece.get('text') or piece.get('content') or str(piece)
                        else:
                            text = str(piece)
                    else:
                        text = first.get('text') or str(first)
                else:
                    text = str(first)
            else:
                text = str(resp)

        # Ensure we always work with a string before JSON extraction
        if text is None:
            raise ValueError("Empty response from model")
        if not isinstance(text, str):
            text = str(text)

        # Try to parse JSON; if the model didn't return valid JSON (which can
        # happen on long / tricky inputs), fall back to a safe default structure
        # so that the rest of the pipeline (scores, PDF, history) still works
        # instead of failing the whole request.
        try:
            data = _extract_json_from_text(text)
        except ValueError as parse_err:
            data = {
                "is_phishing": False,
                "confidence": 0,
                "attack_type": "unknown",
                "signals": [],
                "reasoning": f"Model response could not be parsed as JSON: {parse_err}",
            }

        # cache AI response for 24 hours
        cache.set(cache_key, data, timeout=60 * 60 * 24)
        return data
    except Exception as e:
        raise ValueError(f"AI service error: {str(e)}")


def analyze_parsed(parsed: Dict[str, Any], reputation: Dict[str, Any]) -> Dict[str, Any]:
    """Build a detailed prompt from parsed indicators and reputation results,
    call the model and return the structured JSON expected by the system:

    {
      "is_phishing": bool,
      "confidence": 0-100,
      "attack_type": "...",
      "signals": [],
      "reasoning": "..."
    }
    """
    # Compose a concise prompt containing parsed and reputation summaries
    prompt_lines = [
        "You are an automated email security analyst.",
        "Analyze the provided parsed email indicators and external reputation checks.",
        "Respond ONLY with a JSON object EXACTLY matching the schema:",
        "{\"is_phishing\": bool, \"confidence\": number(0-100), \"attack_type\": string, \"signals\": array, \"reasoning\": string}",
        "Do not include any extra text.\n",
        "Parsed indicators:\n",
        json.dumps(parsed, ensure_ascii=False),
        "\nReputation results:\n",
        json.dumps(reputation, ensure_ascii=False),
        "\nProvide the JSON now.",
    ]
    prompt = "\n".join(prompt_lines)
    data = _generate_structured(prompt)

    # Normalize expected fields
    out = {
        "is_phishing": bool(data.get("is_phishing", False)),
        "confidence": float(data.get("confidence", 0)),
        "attack_type": str(data.get("attack_type", "unknown")),
        "signals": data.get("signals", []),
        "reasoning": str(data.get("reasoning", data.get("explanation", ""))),
    }
    return out