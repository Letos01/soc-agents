from __future__ import annotations

from typing import Any


def resolve_model(name: str) -> Any:
    """``litellm/<provider>/<model>`` goes through LiteLLM (e.g. Claude); anything else is a Gemini model id."""
    if name.startswith("litellm/"):
        from google.adk.models.lite_llm import LiteLlm

        return LiteLlm(model=name.removeprefix("litellm/"))
    return name
