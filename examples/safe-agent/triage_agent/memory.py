"""Agent memory, isolated per tenant and user, validated before it is stored."""


class MemoryRejected(ValueError):
    pass


MAX_VALUE_LENGTH = 500
MAX_KEYS_PER_USER = 50


def validate_memory_value(value):
    if not isinstance(value, str):
        raise MemoryRejected("memory values must be text")
    if len(value) > MAX_VALUE_LENGTH:
        raise MemoryRejected("memory value is too long")
    if any(ord(ch) < 32 and ch not in "\n\t" for ch in value):
        raise MemoryRejected("memory value holds control characters")
    return value


class MemoryStore:
    def __init__(self):
        self._spaces = {}

    def remember(self, session, key, value):
        value = validate_memory_value(value)
        if not isinstance(key, str) or not key or len(key) > 64:
            raise MemoryRejected("memory key is not valid")
        space = self._spaces.setdefault((session.tenant, session.user_id), {})
        if key not in space and len(space) >= MAX_KEYS_PER_USER:
            raise MemoryRejected("memory is full for this user")
        space[key] = {"value": value, "source": "user:" + session.user_id}
        return True

    def recall(self, session, key):
        entry = self._spaces.get((session.tenant, session.user_id), {}).get(key)
        return None if entry is None else entry["value"]
