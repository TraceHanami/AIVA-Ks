from fastapi import APIRouter, Depends

from app.core.security import require_role
from app.schemas.schemas import ChatMessageIn, ChatMessageOut
from app.services.copilot_service import CopilotService

router = APIRouter()


@router.post("", response_model=ChatMessageOut)
async def send_message(
    body: ChatMessageIn,
    service: CopilotService = Depends(CopilotService),
    user=Depends(require_role("analyst")),
):
    """
    RAG pipeline: embed the question -> retrieve relevant graph/event/
    explanation context from the vector store -> LLM reasoning grounded
    in that context -> persist to chat_history.
    """
    return await service.answer(body.investigation_id, body.message, actor=user.username)
