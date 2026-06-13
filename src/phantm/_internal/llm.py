import os
import litellm
from dotenv import load_dotenv
from openai import OpenAIError
from litellm import completion
from phantm.config.settings import PhantmSettings

litellm.suppress_debug_info = True


class PhantmLLMError(Exception):
    pass


def _load_env() -> None:
    env_path = os.path.expanduser("~/.phantm/.env")
    if os.path.isfile(env_path):
        load_dotenv(env_path, override=True)


def ask_model(
    system_prompt: str,
    user_prompt: str,
    model: str | None = None,
) -> str:
    _load_env()

    if model is None:
        settings = PhantmSettings()
        model = settings.default_model

    raw_provider = model.split("/")[0] if "/" in model else ""
    provider = "".join(char for char in raw_provider if char.isalnum()).upper()
    key_name = f"{provider}_API_KEY" if provider else "_API_KEY"
    dynamic_key = os.getenv(key_name) or os.getenv("OPENAI_API_KEY")

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]

    try:
        response = completion(
            model=model,
            messages=messages,
            num_retries=2,
            timeout=45,
            api_key=dynamic_key,
        )
    except OpenAIError as e:
        exc_type = type(e).__name__
        msg = str(e)

        if "AuthenticationError" in exc_type or "auth" in msg.lower():
            hint = f"Authentication failed for {provider} — check your {key_name} in ~/.phantm/.env"
        elif "RateLimitError" in exc_type or "rate_limit" in msg.lower():
            hint = f"Dynamic provider rate limit hit ({model}) — check your plan"
        elif "Timeout" in exc_type or "timeout" in msg.lower():
            hint = f"LLM provider timed out ({model}) after retries — API is unresponsive"
        elif "APIConnectionError" in exc_type or "connection" in msg.lower():
            hint = "Network error — check your connection"
        else:
            hint = f"{exc_type}: {msg}"

        raise PhantmLLMError(hint) from e

    if not getattr(response, "choices", None) or len(response.choices) == 0:
        raise PhantmLLMError(
            f"Model {model} returned an empty response "
            "(likely tripped a safety filter)."
        )

    return response.choices[0].message.content
