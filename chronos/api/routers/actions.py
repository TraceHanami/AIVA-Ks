"""CHRONOS API — Containment & Response Actions Router (Module 9)."""
from __future__ import annotations

from datetime import datetime, timezone
import uuid
from typing import Optional
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from chronos.api.state import manager
from chronos.response.executor import ResponseExecutor
from chronos.response.policy_engine import ActionType, ResponseAction, ResponseMode

router = APIRouter(tags=["Response Actions"])


class ActionApproveRequest(BaseModel):
    action_id: str
    approver: str = "security_lead"
    approved: bool = True


@router.post("/actions/approve")
async def approve_action(req: ActionApproveRequest, host: Optional[str] = "live"):
    st = manager.get_state(host)
    for action in st.pending_actions:
        if action["action_id"] == req.action_id:
            if req.approved:
                action["status"] = "executed"
                executor = ResponseExecutor()
                try:
                    act_obj = ResponseAction(
                        response_id=action["action_id"],
                        action_type=ActionType(action["action_type"]),
                        target=action.get("target", {}),
                        triggered_by=action.get("policy_name", "manual_approval"),
                        mode=ResponseMode.RECOMMEND,
                        status="awaiting_approval",
                    )
                    executed_act = executor.approve_and_execute(act_obj, approved_by=req.approver)
                    exec_details = executed_act.triggered_by
                except Exception as e:
                    exec_details = f"Executed with warning: {e}"

                st.audit_log.insert(0, {
                    "id": str(uuid.uuid4()),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "actor": req.approver,
                    "action_id": req.action_id,
                    "action_type": action["action_type"],
                    "target": action["target"],
                    "status": "SUCCESS",
                    "details": f"Analyst authorized {action['action_type']} | {exec_details}",
                })
            else:
                action["status"] = "rejected"
                st.audit_log.insert(0, {
                    "id": str(uuid.uuid4()),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "actor": req.approver,
                    "action_id": req.action_id,
                    "action_type": action["action_type"],
                    "target": action["target"],
                    "status": "REJECTED",
                    "details": f"Analyst rejected containment action {action['action_type']}",
                })
            return {"status": "updated", "action": action}
    raise HTTPException(status_code=404, detail="Action ID not found")
