"""Input and output checks around tool calls.

Arguments from the model are checked against the tool schema before a tool
runs. Tool results are turned into bounded, plain data before the model sees
them, so text inside a ticket is never treated as an instruction.
"""

import json


class InvalidArguments(ValueError):
    pass


MAX_RESULT_CHARS = 4000
_TYPES = {"string": str, "integer": int, "number": (int, float), "boolean": bool}


def validate_tool_arguments(schema, arguments):
    if not isinstance(arguments, dict):
        raise InvalidArguments("tool arguments must be an object")
    properties = schema["parameters"]["properties"]
    for key, value in arguments.items():
        if key not in properties:
            raise InvalidArguments("unexpected argument: " + str(key)[:40])
        expected = _TYPES[properties[key]["type"]]
        if (isinstance(value, bool) and expected is not bool) or not isinstance(value, expected):
            raise InvalidArguments("argument has the wrong type: " + key)
    for key in schema["parameters"].get("required", []):
        if key not in arguments:
            raise InvalidArguments("missing argument: " + key)
    return dict(arguments)


def sanitize_tool_result(result):
    text = json.dumps({"tool_result": result}, sort_keys=True, default=str)
    text = "".join(ch for ch in text if ch >= " " or ch in "\n\t")
    if len(text) > MAX_RESULT_CHARS:
        text = text[:MAX_RESULT_CHARS] + "...[truncated]"
    return text
