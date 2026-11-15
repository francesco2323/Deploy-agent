"""Optional LLM front door: natural language → DeploySpec. Output is untrusted and re-validated.

The model never sees plan output/stderr from Terraform (prompt-injection surface via resource names,
tags, variable values) and never sits in the gate or apply path.

Cache layout: static prefix (system + tool schema, both cache_control'd) first; dynamic request last.
"""
from __future__ import annotations

import os

from .spec import Registry, SpecError, validate_spec

_SYSTEM = (
    "You translate a deployment request into a DeploySpec by calling submit_spec exactly once.\n"
    "Rules: choose only a stack from the enum; set only variables listed for that stack; never invent values;\n"
    "if the request is ambiguous or names no known stack, set needs_clarification and leave stack empty.\n"
    "Known stacks and their allowed variables:\n{catalog}"
)


def _tool(registry: Registry) -> dict:
    return {
        "name": "submit_spec",
        "description": "Submit the deployment spec.",
        "input_schema": {
            "type": "object",
            "properties": {
                "stack": {"type": "string", "enum": [*registry.stacks, ""]},
                "vars": {"type": "object"},
                "allow_destroy": {"type": "boolean"},
                "needs_clarification": {"type": "string"},
            },
            "required": ["stack"],
        },
        "cache_control": {"type": "ephemeral"},
    }


def extract_spec(request: str, registry: Registry, model: str | None = None):
    import anthropic  # lazy: optional dependency

    catalog = "\n".join(f"- {s.name} (env={s.env}): {', '.join(s.allowed_vars) or 'no variables'}" for s in registry.stacks.values())
    client = anthropic.Anthropic()
    msg = client.messages.create(
        model=model or os.environ.get("DEPLOY_AGENT_MODEL", "claude-haiku-5-5"),
        max_tokens=512,
        system=[{"type": "text", "text": _SYSTEM.format(catalog=catalog), "cache_control": {"type": "ephemeral"}}],
        tools=[_tool(registry)],
        tool_choice={"type": "tool", "name": "submit_spec"},
        messages=[{"role": "user", "content": request}],
    )
    block = next(b for b in msg.content if b.type == "tool_use")
    raw = dict(block.input)
    if raw.get("needs_clarification") or not raw.get("stack"):
        raise SpecError(f"clarification needed: {raw.get('needs_clarification') or 'no stack matched'}")
    return validate_spec(raw, registry)
