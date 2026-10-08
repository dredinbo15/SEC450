"""Parser registry: source kind -> parse(line, ctx) -> ParsedEvent."""
from __future__ import annotations

from typing import Callable

from ..models import ParsedEvent
from .app import parse_app
from .common import ParseContext
from .nginx import parse_access, parse_error
from .ssh import parse_auth

Parser = Callable[[str, ParseContext], ParsedEvent]

PARSERS: dict[str, Parser] = {
    "nginx_access": parse_access,
    "nginx_error": parse_error,
    "ssh_auth": parse_auth,
    "app": parse_app,
}

__all__ = ["PARSERS", "ParseContext", "Parser"]
