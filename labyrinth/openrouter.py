import os


def complete(messages, model, timeout=8, tools=None, extra_body=None, reasoning=None, tool_choice=None):
    if os.getenv("COUNTERPROMPT_OFFLINE", "").lower() in {"1", "true"}:
        raise RuntimeError("OpenRouter is disabled in offline mode")
    key = os.getenv("OPENROUTER_API_KEY")
    if not key:
        raise RuntimeError("OPENROUTER_API_KEY is not set")
    from openai import OpenAI

    client = OpenAI(
        api_key=key,
        base_url="https://openrouter.ai/api/v1",
        timeout=timeout,
    )
    kwargs = {"model": model, "messages": messages}
    if tools:
        kwargs["tools"] = tools
        kwargs["tool_choice"] = tool_choice or "auto"
    if extra_body:
        kwargs["extra_body"] = dict(extra_body)
    if reasoning is not None:
        kwargs.setdefault("extra_body", {})["reasoning"] = reasoning
    return client.chat.completions.create(**kwargs)
