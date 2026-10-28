"""Lazy LLM access shared by the multi-agent workers."""

import json
import os
from pathlib import Path
from typing import Any


def load_env_file(path: Path) -> None:
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        key, separator, value = line.partition("=")
        if separator and key.strip() and key.strip() not in os.environ:
            os.environ[key.strip()] = value.strip().strip('"').strip("'")


def ask_llm(system_prompt: str, user_prompt: str, *, timeout: float | None = None) -> str:
    """Call the configured model and return text, failing clearly when unavailable."""
    if not os.getenv("OPENAI_API_KEY"):
        raise RuntimeError("OPENAI_API_KEY is not configured")
    try:
        from langchain_openai import ChatOpenAI
    except ImportError as exc:
        raise RuntimeError("install langchain-openai to enable LLM agents") from exc
    model = ChatOpenAI(
        model=os.getenv("IOT_AUDIT_MODEL", "gpt-4.1-mini"),
        temperature=0,
        base_url=os.getenv("OPENAI_BASE_URL") or None,
        reasoning_effort=os.getenv("IOT_AUDIT_REASONING_EFFORT", "medium"),
        **({"timeout": timeout, "max_retries": 0} if timeout is not None else {}),
    )
    try:
        response = model.invoke([
            ("system", system_prompt),
            ("human", user_prompt),
        ])
    except Exception as exc:
        raise RuntimeError(f"LLM request failed: {exc}") from exc
    return str(response.content)


def ask_json(system_prompt: str, user_prompt: str, *, timeout: float | None = None) -> dict[str, Any]:
    content = ask_llm(
        system_prompt,
        user_prompt + "\nReturn only a valid JSON object. Do not use markdown fences.",
        **({"timeout": timeout} if timeout is not None else {}),
    )
    try:
        return json.loads(content)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"LLM returned invalid JSON: {exc}") from exc
