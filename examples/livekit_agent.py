"""LiveKit voice-agent integration sketch.

Mirrors how safe-voice is used in a real-time voice pipeline: load the model once
at worker prewarm, then guard every transcribed user turn before it reaches the
LLM. Deflect on a block; end the room once the strike budget is spent.

This is illustrative pseudocode for the LiveKit Agents SDK — adapt to your
version's API.

Run:  pip install "safe-voice[ml]" livekit-agents
"""

from safevoice import Guard, SecurityConfig, load_scanner

# One Guard per worker process; strikes are tracked per session_id inside it.
_guard = Guard(SecurityConfig.from_env())


def prewarm() -> None:
    """LiveKit prewarm hook — load the classifier once per process."""
    load_scanner()


async def on_user_turn(session, room, transcript: str) -> bool:
    """Call at the start of each user turn. Returns True if the turn may proceed.

    ``session`` / ``room`` are your framework objects; the exact calls
    (``say`` / ``shutdown``) depend on the SDK version.
    """
    decision = await _guard.acheck_user_turn(
        transcript,
        session_id=room.name,
        tenant_id=getattr(room, "tenant_id", ""),
    )

    if decision.allowed:
        return True

    if decision.should_shutdown:
        await session.say("I'm ending this call. Take care.")
        await session.shutdown()
        _guard.forget(room.name)
    else:
        await session.say("Sorry, I can't help with that.")
    return False
