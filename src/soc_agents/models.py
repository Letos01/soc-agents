from __future__ import annotations

import json
from typing import Any


def resolve_model(name: str, extra_body: str = "") -> Any:
    """``litellm/<provider>/<model>`` goes through LiteLLM (e.g. Claude, OpenRouter); anything else is a Gemini id.

    ``extra_body`` is a JSON object sent with every LiteLLM request, e.g. OpenRouter's Jev router plugin
    ``{"plugins": [{"id": "jev-router", "cost_tier": "low", "models": ["*flash*"]}]}``.
    """
    if name.startswith("litellm/"):
        from google.adk.models.lite_llm import LiteLlm

        kwargs: dict[str, Any] = {}
        if extra_body:
            body = json.loads(extra_body)
            if not isinstance(body, dict):
                raise ValueError("MODEL_EXTRA_BODY must be a JSON object")
            kwargs["extra_body"] = body
        return LiteLlm(model=name.removeprefix("litellm/"), **kwargs)
    if extra_body:
        raise ValueError("MODEL_EXTRA_BODY only applies to litellm/ models")
    return name
