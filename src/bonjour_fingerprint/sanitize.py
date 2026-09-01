import re

_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def sanitize_text(value: str | bytes, limit: int = 512) -> str:
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    return _CONTROL.sub("", value)[:limit]
