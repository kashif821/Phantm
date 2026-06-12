from openai import OpenAIError
from litellm import completion
from phantm.config.settings import PhantmSettings


class PhantmLLMError(Exception):
    pass


def ask_model(
    system_prompt: str,
    user_prompt: str,
    model: str | None = None,
) -> str:
    if model is None:
        settings = PhantmSettings()
        model = settings.default_model

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]

    try:
        response = completion(model=model, messages=messages)
    except OpenAIError as e:
        exc_type = type(e).__name__
        msg = str(e)

        if "AuthenticationError" in exc_type or "auth" in msg.lower():
            hint = "authentication failed — check your API key"
        elif "RateLimitError" in exc_type or "rate_limit" in msg.lower():
            hint = "rate limit exceeded — try again later"
        elif "APIConnectionError" in exc_type or "connection" in msg.lower():
            hint = "network error — check your connection"
        else:
            hint = f"{exc_type}: {msg}"

        raise PhantmLLMError(hint) from e

    return response.choices[0].message.content
