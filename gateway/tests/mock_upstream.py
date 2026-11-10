"""OpenAI-compatible stand-in for the upstream LiteLLM in local tests.

Saves each request body to $RECORDS/req-N.json and answers with the last user
message text, so tests can see exactly what croak-gate forwarded.

A user message "CALL_TOOL <name> <json args | key=value ...>" makes the answer a call to that
tool, when the request offers it. After a tool result the answer is
"SEEN: <start of the result>", so a test can drive a real client through one
tool call.
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


def scripted_call(body):
    """(name, arguments) when the last message asks for a tool the request offers."""
    messages = body.get("messages", [])
    if not messages or messages[-1].get("role") != "user":
        return None
    text = last_user_text(body)
    at = text.find("CALL_TOOL ")
    if at < 0:
        return None
    name, _, rest = text[at + len("CALL_TOOL "):].strip().partition(" ")
    # Arguments are a JSON object, or key=value words (values without spaces).
    try:
        # A client may hand the prompt over quoted, with its quotes escaped.
        args, _ = json.JSONDecoder().raw_decode(rest.strip().rstrip('"').replace('\\"', '"'))
    except ValueError:
        args = dict(w.split("=", 1) for w in rest.split() if "=" in w)
        args = {k: v.strip('"') for k, v in args.items()}
    offered = {t.get("function", {}).get("name") for t in body.get("tools") or []}
    return (name, json.dumps(args, ensure_ascii=False)) if name in offered else None


def tool_result_text(body):
    messages = body.get("messages", [])
    if messages and messages[-1].get("role") == "tool":
        c = messages[-1].get("content")
        c = c if isinstance(c, str) else json.dumps(c, ensure_ascii=False)
        return "SEEN: " + c[:120]
    return None


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        global count
        body = json.loads(self.rfile.read(int(self.headers.get("content-length", 0))) or b"{}")
        count += 1
        os.makedirs(RECORDS, exist_ok=True)
        with open(os.path.join(RECORDS, f"req-{count}.json"), "w") as f:
            json.dump(body, f, ensure_ascii=False)
        text = tool_result_text(body) or "ECHO: " + last_user_text(body)
        usage = {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
        call = scripted_call(body)
        if call and body.get("stream"):
            self.send_response(200)
            self.send_header("content-type", "text/event-stream")
            self.end_headers()
            base = {"id": "x", "object": "chat.completion.chunk", "created": 0, "model": body.get("model")}
            delta = {"role": "assistant", "tool_calls": [{"index": 0, "id": f"call_mock_{count}", "type": "function",
                                                          "function": {"name": call[0], "arguments": call[1]}}]}
            for chunk in (
                {**base, "choices": [{"index": 0, "delta": delta, "finish_reason": None}]},
                {**base, "choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}], "usage": usage},
            ):
                self.wfile.write(f"data: {json.dumps(chunk, ensure_ascii=False)}\n\n".encode())
            self.wfile.write(b"data: [DONE]\n\n")
            return
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
