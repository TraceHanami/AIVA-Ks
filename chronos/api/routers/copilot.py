"""CHRONOS API — Security Copilot Router (Module 7 & 20)."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter
from pydantic import BaseModel

from chronos.api.state import manager
from chronos.research.explainability.evidence import EvidenceExtractor

router = APIRouter(tags=["Security Copilot"])


class CopilotQuestion(BaseModel):
    message: str


@router.post("/copilot/chat")
async def copilot_chat(req: CopilotQuestion, host: Optional[str] = "live"):
    st = manager.get_state(host)
    user_msg = {
        "id": str(uuid.uuid4()),
        "role": "user",
        "content": req.message,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    st.chat_history.append(user_msg)

    q = req.message.lower()
    bundle = EvidenceExtractor().extract(st.graph, st.mitre_matches)

    if "what happened" in q or "summary" in q or "explain" in q or "attack" in q:
        techniques_summary = ", ".join(f"{t.technique.technique_id} ({t.technique.name})" for t in bundle.technique_matches) or "No critical attack techniques confirmed yet."
        chain = " -> ".join(bundle.highest_risk_path) or "Nominal execution tree"
        reply = (
            f"**Environment Assessment for Host `{st.host_id}` ({host.upper()} MODE):**\n\n"
            f"• **Identified Attack Chain:** `{chain}`\n"
            f"• **Overall Propagated Risk:** {bundle.overall_risk_score * 100:.1f}%\n"
            f"• **MITRE ATT&CK Techniques:** {techniques_summary}\n"
            f"• **Active Graph Entities:** {len(st.graph.g.nodes)} nodes, {len(st.graph.g.edges)} causal relationships\n"
            f"• **Pending Mitigations:** {len([a for a in st.pending_actions if a['status'] == 'pending_approval'])} containment action(s) awaiting approval."
        )
    elif "isolate" in q or "contain" in q or "kill" in q or "response" in q or "policy" in q:
        reply = (
            f"**Policy & Response Status for Host `{st.host_id}`:**\n\n"
            f"• There are currently **{len(st.pending_actions)}** policy actions evaluated by the Response Engine.\n"
            f"• Safety Invariant: In accordance with zero-disruption policy safeguards, destructive actions require explicit human-in-the-loop analyst authorization before enforcement."
        )
    elif "mitre" in q or "technique" in q:
        techniques_str = "\n".join([f"- **[{m.technique.technique_id}] {m.technique.name}**: {m.technique.description} (Confidence: {m.confidence*100:.0f}%)" for m in st.mitre_matches]) if st.mitre_matches else "No anomalous MITRE techniques triggered on this host."
        reply = f"**Identified MITRE ATT&CK Mapping for `{st.host_id}`:**\n\n{techniques_str}"
    else:
        reply = (
            f"Based on real-time graph behavioral analysis for host `{st.host_id}` ({host} mode):\n\n"
            f"- Graph topology: {len(st.graph.g.nodes)} nodes, {len(st.graph.g.edges)} edges\n"
            f"- Peak risk propagation score: {max((d.get('risk', 0.0) for _, d in st.graph.g.nodes(data=True)), default=0.0):.2f}\n"
            f"- Telemetry events recorded: {len(st.events)}. How would you like to investigate further?"
        )

    bot_msg = {
        "id": str(uuid.uuid4()),
        "role": "assistant",
        "content": reply,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    st.chat_history.append(bot_msg)

    return {"reply": bot_msg, "history": st.chat_history}


@router.get("/copilot/history")
async def copilot_history(host: Optional[str] = "live"):
    st = manager.get_state(host)
    return {"history": st.chat_history}
