"""Typed accessors for untyped vendor JSON (the one place `Any` is narrowed)."""

from __future__ import annotations

from typing import Any, cast


def obj(value: object) -> dict[str, Any]:
    """`value` if it is a JSON object, else an empty dict."""
    return cast("dict[str, Any]", value) if isinstance(value, dict) else {}


def arr(value: object) -> list[Any]:
    """`value` if it is a JSON array, else an empty list."""
    return cast("list[Any]", value) if isinstance(value, list) else []
