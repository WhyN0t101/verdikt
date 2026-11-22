"""One rule for text that came from a feed (a vendor, a name server, a certificate)."""

from __future__ import annotations

import unicodedata

_FLAT = str.maketrans("\t\n\r", "   ")
_DROP = frozenset({"Cc", "Cf", "Zl", "Zp"})  # controls, format (bidi, zero-width, tags), separators


def clean_text(text: str) -> str:
    """Tabs and line breaks become a space; every control, format and line/paragraph separator
    character is dropped. That removes terminal escapes (ESC), bidi overrides, zero-width and
    tag characters, so feed text cannot recolour a terminal, retitle it or reorder a line."""
    return "".join(c for c in text.translate(_FLAT) if unicodedata.category(c) not in _DROP)
