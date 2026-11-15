"""Model clients. The scripted model is used for tests and the offline demo."""

import json

try:
    import openai
except ImportError:  # optional: the agent runs offline with ScriptedModel
    openai = None


class OpenAIModel:
    """Calls a hosted chat model with the tool schemas. Needs the openai package."""

    def __init__(self, credential, model_name="gpt-4o-mini"):
        if openai is None:
            raise RuntimeError("the openai package is not installed")
        self._client = openai.OpenAI(api_key=credential)
        self._model_name = model_name

    def next_action(self, messages, tools):
        reply = self._client.chat.completions.create(
            model=self._model_name, messages=messages, tools=tools, max_tokens=512, timeout=30,
        )
        used = reply.usage.total_tokens if reply.usage else 0
        choice = reply.choices[0].message
        if choice.tool_calls:
            call = choice.tool_calls[0]
            return {"tool": call.function.name, "arguments": json.loads(call.function.arguments), "tokens": used}
        return {"final": choice.content or "", "tokens": used}


class ScriptedModel:
    """Returns a fixed list of actions. It makes no network calls."""

    def __init__(self, actions, on_call=None):
        self._actions = list(actions)
        self._on_call = on_call
        self.calls = 0

    def next_action(self, messages, tools):
        self.calls += 1
        if self._on_call is not None:
            self._on_call(self.calls)
        if not self._actions:
            return {"final": "done", "tokens": 1}
        return dict(self._actions.pop(0))
