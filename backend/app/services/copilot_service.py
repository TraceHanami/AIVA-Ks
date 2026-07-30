"""
Security Copilot service — RAG pipeline.

1. Embed the analyst's question (sentence-transformers or the LLM
   provider's embedding endpoint).
2. Retrieve top-k relevant chunks from the vector store: prior
   explanations, graph summaries, MITRE technique descriptions, and
   this investigation's chat history.
3. Build a grounded prompt and call the LLM.
4. Persist the exchange to chat_history for auditability.
"""
import uuid
from datetime import datetime, timezone
from uuid import UUID

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_session
from app.schemas.schemas import ChatMessageOut


class CopilotService:
    def __init__(self, session: AsyncSession = Depends(get_session)):
        self.session = session

    async def answer(self, investigation_id: UUID | None, message: str, actor: str) -> ChatMessageOut:
        context_chunks = await self._retrieve(investigation_id, message)
        answer_text = await self._call_llm(message, context_chunks)

        # persist both the user turn and assistant turn to chat_history here
        return ChatMessageOut(
            message_id=uuid.uuid4(),
            role="assistant",
            content=answer_text,
            retrieved_context=context_chunks,
            created_at=datetime.now(timezone.utc),
        )

    async def _retrieve(self, investigation_id: UUID | None, message: str) -> list[dict]:
        # vector_store.similarity_search(embed(message), top_k=5, filter={"investigation_id": investigation_id})
        return []

    async def _call_llm(self, message: str, context: list[dict]) -> str:
        # build grounded prompt from `context`, call the configured LLM provider
        raise NotImplementedError("wire to LLM provider (see ai/explainability for prompt patterns)")
