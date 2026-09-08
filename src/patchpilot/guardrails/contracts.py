"""Validate-or-halt contracts for tools.

A tool is a plain function whose input and output are Pydantic models. `@contract` re-validates both
sides (so a tool that returns a dict, or a model built with `model_construct`, still gets checked),
and converts any validation failure into `ContractViolation`, which the graph turns into
`decision = "halted"` rather than letting bad data flow forward.
"""

from __future__ import annotations

import functools
from collections.abc import Callable
from typing import Any, TypeVar

from pydantic import BaseModel, ValidationError

TIn = TypeVar("TIn", bound=BaseModel)
TOut = TypeVar("TOut", bound=BaseModel)


class ContractViolation(RuntimeError):
    def __init__(self, tool: str, side: str, error: Exception):
        self.tool = tool
        self.side = side
        self.error = error
        super().__init__(f"{tool}: {side} contract violated: {error}")


def contract(
    input_model: type[TIn], output_model: type[TOut]
) -> Callable[[Callable[[TIn], Any]], Callable[[TIn | dict[str, Any]], TOut]]:
    def decorator(fn: Callable[[TIn], Any]) -> Callable[[TIn | dict[str, Any]], TOut]:
        @functools.wraps(fn)
        def wrapper(payload: TIn | dict[str, Any]) -> TOut:
            try:
                validated_in = (
                    payload
                    if isinstance(payload, input_model)
                    else input_model.model_validate(payload)
                )
                validated_in = input_model.model_validate(validated_in.model_dump())
            except ValidationError as e:
                raise ContractViolation(fn.__name__, "input", e) from e
            result = fn(validated_in)
            try:
                dumped = result.model_dump() if isinstance(result, BaseModel) else result
                return output_model.model_validate(dumped)
            except ValidationError as e:
                raise ContractViolation(fn.__name__, "output", e) from e

        wrapper.input_model = input_model  # type: ignore[attr-defined]
        wrapper.output_model = output_model  # type: ignore[attr-defined]
        return wrapper

    return decorator
