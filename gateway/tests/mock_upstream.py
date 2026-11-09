"""OpenAI-compatible stand-in for the upstream LiteLLM in local tests.

Saves each request body to $RECORDS/req-N.json and answers with the last user
message text, so tests can see exactly what croak-gate forwarded.
"""
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

RECORDS = os.environ.get("RECORDS", "/records")
count = 0


def last_user_text(body):
    for m in reversed(body.get("messages", [])):
        if m.get("role") == "user":
            c = m.get("content")
            if isinstance(c, str):
                return c
            return " ".join(p.get("text", "") for p in c or [] if isinstance(p, dict))
    return ""


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        global count
        body = json.loads(self.rfile.read(int(self.headers.get("content-length", 0))) or b"{}")
        count += 1
        os.makedirs(RECORDS, exist_ok=True)
        with open(os.path.join(RECORDS, f"req-{count}.json"), "w") as f:
            json.dump(body, f, ensure_ascii=False)
        text = "ECHO: " + last_user_text(body)
        usage = {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
        if body.get("stream"):
            self.send_response(200)
            self.send_header("content-type", "text/event-stream")
            self.end_headers()
            base = {"id": "x", "object": "chat.completion.chunk", "created": 0, "model": body.get("model")}
            for chunk in (
                {**base, "choices": [{"index": 0, "delta": {"role": "assistant", "content": text}, "finish_reason": None}]},
                {**base, "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}], "usage": usage},
            ):
                self.wfile.write(f"data: {json.dumps(chunk, ensure_ascii=False)}\n\n".encode())
            self.wfile.write(b"data: [DONE]\n\n")
            return
        out = {
            "id": "x", "object": "chat.completion", "created": 0, "model": body.get("model"),
            "choices": [{"index": 0, "message": {"role": "assistant", "content": text}, "finish_reason": "stop"}],
            "usage": usage,
        }
        data = json.dumps(out, ensure_ascii=False).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


ThreadingHTTPServer(("0.0.0.0", 8000), Handler).serve_forever()
