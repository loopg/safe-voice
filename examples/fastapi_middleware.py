"""Guard a chat endpoint with FastAPI.

Screens each user message before it reaches your LLM. Returns a safe refusal on a
block, and a 403 once the session exhausts its strike budget.

Run:  pip install fastapi uvicorn "safe-voice[ml]"
      uvicorn examples.fastapi_middleware:app --reload
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from safevoice import Guard, SecurityConfig, load_scanner

app = FastAPI(title="safe-voice demo")

# Load the ML classifier once at startup (comment out for deterministic-only).
load_scanner()
guard = Guard(SecurityConfig.from_env())


class ChatRequest(BaseModel):
    session_id: str
    message: str


@app.post("/chat")
async def chat(req: ChatRequest):
    decision = await guard.acheck_user_turn(req.message, session_id=req.session_id)

    if decision.blocked:
        if decision.should_shutdown:
            guard.forget(req.session_id)
            raise HTTPException(status_code=403, detail="Session ended: repeated policy violations.")
        return {"reply": "Sorry, I can't help with that request.", "blocked": True, "layer": str(decision.layer)}

    # ... safe to call your LLM here ...
    reply = f"(LLM would answer: {req.message!r})"
    return {"reply": reply, "blocked": False}


@app.on_event("shutdown")
def _cleanup() -> None:
    pass
