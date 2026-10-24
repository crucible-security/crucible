"""A lightweight local mock server simulating OpenAI and Anthropic endpoints for testing."""

import json
from http.server import BaseHTTPRequestHandler, HTTPServer
import threading
import sys

class MockHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_len = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_len).decode("utf-8")
        
        try:
            payload_data = json.loads(body)
        except Exception:
            payload_data = {}

        # Anthropic simulation
        if "/v1/messages" in self.path:
            if "anthropic-version" not in self.headers:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b'{"type":"error","error":{"type":"invalid_request_error","message":"anthropic-version header is required"}}')
                return
            if "max_tokens" not in payload_data:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b'{"type":"error","error":{"type":"invalid_request_error","message":"max_tokens: Field required"}}')
                return

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            resp = {
                "id": "msg_001",
                "type": "message",
                "role": "assistant",
                "content": [
                    {
                        "type": "text",
                        "text": "I cannot fulfill this request because it violates safety guidelines."
                    }
                ]
            }
            self.wfile.write(json.dumps(resp).encode("utf-8"))
            return

        # OpenAI / OpenRouter simulation
        if "/v1/chat/completions" in self.path:
            if "model" not in payload_data:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b'{"error":{"message":"No model provided","code":400}}')
                return

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            resp = {
                "id": "chatcmpl-001",
                "choices": [
                    {
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": "I cannot fulfill this request as I am programmed to be helpful and harmless."
                        }
                    }
                ]
            }
            self.wfile.write(json.dumps(resp).encode("utf-8"))
            return

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"response": "I refuse this request."}')

    def log_message(self, format, *args):
        pass

def run_server(port=8899):
    server = HTTPServer(("127.0.0.1", port), MockHandler)
    server.serve_forever()

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8899
    run_server(port)
