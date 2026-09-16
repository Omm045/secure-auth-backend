import json
import logging
import uuid

class JsonFormatter(logging.Formatter):
    def format(self, record):
        payload = {
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        request_id = getattr(record, "request_id", None)
        if request_id:
            payload["request_id"] = request_id
        return json.dumps(payload, separators=(",", ":"))

def configure_logging():
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(logging.INFO)

def request_id() -> str:
    return str(uuid.uuid4())

def trusted_request_id(value: str | None) -> str:
    if value:
        try:
            parsed = uuid.UUID(value)
            if str(parsed) == value.lower():
                return value
        except ValueError:
            pass
    return request_id()
