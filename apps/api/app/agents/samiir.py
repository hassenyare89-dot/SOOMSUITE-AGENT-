from uuid import uuid4

from app.domain.schemas import ChatRequest, ChatResponse

SAFE_FALLBACK = (
    "I don't have approved company information to answer that accurately. "
    "I'll escalate this to a human team member."
)


class SamiirService:
    async def respond(self, request: ChatRequest) -> ChatResponse:
        # Model execution receives only approved RAG snippets; no privileged tool is registered.
        return ChatResponse(
            conversation_id=request.conversation_id or uuid4(), answer=SAFE_FALLBACK, escalated=True
        )
