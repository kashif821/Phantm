import re

RISKY_CALLS: set[str] = {
    "os.system", "os.popen", "subprocess.run", "subprocess.Popen",
    "subprocess.call", "subprocess.check_output", "eval", "exec",
    "requests.get", "requests.post", "requests.put", "requests.delete",
    "openai.ChatCompletion.create", "openai.chat.completions.create",
    "litellm.completion",
}

RISKY_KEYWORD_RE: re.Pattern = re.compile(
    r"(os\.system|os\.popen|subprocess\.\w+|eval\(|exec\(|requests\.|openai\.|litellm\.)"
)

IP_RE: re.Pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
URL_RE: re.Pattern = re.compile(r"https?://[^\s'\"\)]+")

MAX_FILE_SIZE: int = 500 * 1024

VALID_SEVERITIES: frozenset[str] = frozenset({"CRITICAL", "HIGH", "MEDIUM", "LOW"})

EXIT_VULNERABLE: int = 1
EXIT_NETWORK_ERROR: int = 3
EXIT_ENGINE_CRASH: int = 4


def is_risky_call(full_name: str) -> bool:
    return full_name in RISKY_CALLS
