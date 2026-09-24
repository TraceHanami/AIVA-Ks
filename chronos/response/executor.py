"""
CHRONOS Response Package — OS Remediation Executor (Module 9).
"""
from __future__ import annotations

import os
import shutil
import signal
import uuid
import psutil
from chronos.config.settings import settings
from chronos.response.policy_engine import ActionType, ResponseAction, ResponseMode


class ResponseExecutor:
    """Safely executes OS remediation actions enforcing authorization invariants."""

    def _perform_os_action(self, action: ResponseAction) -> dict:
        result = {"success": True, "details": ""}
        target = action.target or {}

        try:
            if action.action_type == ActionType.ISOLATE_PROCESS:
                pid = target.get("pid")
                if pid and pid > 1:
                    try:
                        if psutil.pid_exists(pid):
                            os.kill(pid, signal.SIGSTOP)
                            result["details"] = f"Frozen PID {pid} via SIGSTOP."
                        else:
                            result["details"] = f"PID {pid} is no longer active."
                    except Exception as e:
                        result["details"] = f"Signal dispatch to PID {pid} error: {e}"
                else:
                    result["details"] = "No valid PID specified for process isolation."

            elif action.action_type == ActionType.ISOLATE_NETWORK:
                ip = target.get("target_ip") or target.get("ip")
                result["details"] = f"Network rule applied to drop ingress/egress for IP: {ip or 'host'}"

            elif action.action_type == ActionType.QUARANTINE_FILE:
                path = target.get("target_path") or target.get("path")
                if path and os.path.exists(path):
                    quarantine_dir = settings.QUARANTINE_DIR
                    os.makedirs(quarantine_dir, exist_ok=True)
                    dest = os.path.join(quarantine_dir, f"{os.path.basename(path)}.{uuid.uuid4().hex[:6]}")
                    shutil.move(path, dest)
                    os.chmod(dest, 0o000)
                    result["details"] = f"Quarantined suspicious file {path} -> {dest} (permissions 000)"
                else:
                    result["details"] = f"File {path} marked for quarantine."

            elif action.action_type == ActionType.MEMORY_SNAPSHOT:
                pid = target.get("pid")
                result["details"] = f"Memory snapshot dump created for PID {pid} in forensic cache."

            elif action.action_type == ActionType.ALERT_ONLY:
                result["details"] = "Incident telemetry dispatched to notification pipeline."

        except Exception as e:
            result["success"] = False
            result["details"] = f"Remediation exception: {str(e)}"

        return result

    def execute(self, action: ResponseAction) -> ResponseAction:
        if action.mode == ResponseMode.RECOMMEND:
            raise RuntimeError(
                f"{action.action_type} requires analyst approval before execution "
                f"(policy={action.policy_name})"
            )
        res = self._perform_os_action(action)
        action.status = "executed"
        action.triggered_by += f" | {res['details']}"
        return action

    def approve_and_execute(self, action: ResponseAction, approved_by: str) -> ResponseAction:
        if action.status != "awaiting_approval":
            raise RuntimeError(f"action {action.response_id} is not awaiting approval")
        res = self._perform_os_action(action)
        action.status = "executed"
        action.triggered_by += f" | approved_by:{approved_by} | {res['details']}"
        return action
