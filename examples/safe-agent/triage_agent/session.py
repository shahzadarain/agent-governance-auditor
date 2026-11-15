"""The authenticated caller. Created by trusted code, never from model output."""

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Session:
    user_id: str
    tenant: str = "default"
    roles: frozenset = field(default_factory=frozenset)
