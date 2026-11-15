"""Step, time, and token limits for one agent run."""

from dataclasses import dataclass


class LimitExceeded(RuntimeError):
    pass


@dataclass(frozen=True)
class Limits:
    max_steps: int = 8
    max_seconds: float = 30.0
    max_tokens: int = 20000
