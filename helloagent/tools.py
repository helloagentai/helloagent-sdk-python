"""Client-side tool registry for `@agent.tool` decorator.

Tools are invoked by the developer's own LLM — the SDK just holds the registry
and exposes OpenAI/Anthropic-compatible schema so devs can pass `agent.tools`
straight into their model call.
"""
from __future__ import annotations

import inspect
from dataclasses import dataclass, field
from typing import Any, Callable, Optional, get_type_hints

_PY_TO_JSON = {
    str: "string", int: "integer", float: "number",
    bool: "boolean", list: "array", dict: "object",
}


@dataclass
class Tool:
    name: str
    description: str
    fn: Callable[..., Any]
    parameters: dict = field(default_factory=dict)

    def schema(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "parameters": self.parameters,
        }

    async def invoke(self, **kwargs) -> Any:
        result = self.fn(**kwargs)
        if inspect.isawaitable(result):
            return await result
        return result


def _infer_parameters(fn: Callable) -> dict:
    sig = inspect.signature(fn)
    hints = get_type_hints(fn)
    props: dict = {}
    required: list[str] = []
    for name, param in sig.parameters.items():
        if name == "self":
            continue
        t = hints.get(name, str)
        props[name] = {"type": _PY_TO_JSON.get(t, "string")}
        if param.default is inspect.Parameter.empty:
            required.append(name)
    return {"type": "object", "properties": props, "required": required}


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, Tool] = {}

    def register(
        self,
        fn: Callable,
        name: Optional[str] = None,
        description: Optional[str] = None,
        parameters: Optional[dict] = None,
    ) -> Tool:
        tool = Tool(
            name=name or fn.__name__,
            description=description or (fn.__doc__ or "").strip(),
            fn=fn,
            parameters=parameters or _infer_parameters(fn),
        )
        self._tools[tool.name] = tool
        return tool

    def __iter__(self):
        return iter(self._tools.values())

    def __len__(self) -> int:
        return len(self._tools)

    def __getitem__(self, name: str) -> Tool:
        return self._tools[name]

    def __contains__(self, name: str) -> bool:
        return name in self._tools

    def schemas(self) -> list[dict]:
        return [t.schema() for t in self._tools.values()]
