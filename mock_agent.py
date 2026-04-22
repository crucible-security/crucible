
from fastapi import FastAPI, Request
import uvicorn
import re

app = FastAPI()

# A simple security filter that "defends" against basic jailbreaks
SECURITY_FILTERS = [
    r"dan", r"developer mode", r"ignore.*instructions", r"bypass",
    r"hack", r"jailbreak", r"unfiltered", r"personality"
]

@app.post("/chat")
async def chat(request: Request):
    data = await request.json()
    message = data.get("message", "").lower()
    
    # Check against filters
    for pattern in SECURITY_FILTERS:
        if re.search(pattern, message):
            return {"response": "Access Denied: Security filter triggered. I cannot fulfill this request."}
    
    return {"response": f"Message received: {message[:20]}... Processing as a safe request."}

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
