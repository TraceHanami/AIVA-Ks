"""
End-to-end API test suite for CHRONOS FastAPI application.
"""
import pytest
from fastapi.testclient import TestClient

from chronos.api.app import app

client = TestClient(app)


def test_api_health_endpoint():
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"


def test_api_dashboard_summary_endpoint():
    response = client.get("/api/dashboard/summary")
    assert response.status_code == 200
    data = response.json()
    assert "host_id" in data
    assert "overall_risk" in data
    assert "threat_heatmap" in data


def test_api_cases_list_and_create():
    # List cases
    res = client.get("/api/cases")
    assert res.status_code == 200
    body = res.json()
    assert "cases" in body
    assert isinstance(body["cases"], list)

    # Create case
    new_case_payload = {
        "title": "E2E Test Threat Event",
        "host_id": "test-srv-01",
        "severity": "CRITICAL",
        "assigned_to": "soc_lead",
        "evidence_event_ids": [101, 102],
        "mitre_technique_ids": ["T1055"],
    }
    res_create = client.post("/api/cases", json=new_case_payload)
    assert res_create.status_code == 200
    created = res_create.json()
    assert created["status"] == "created"
    assert created["case"]["title"] == "E2E Test Threat Event"


def test_api_threat_intel_lookup():
    res = client.get("/api/threat_intel/lookup", params={"query": "185.220.101.5"})
    assert res.status_code == 200
    data = res.json()
    assert data["hit"] is True
    assert data["indicator"]["threat_actor"] == "APT29 (Cozy Bear)"


def test_api_actions_approval():
    approve_payload = {"action_id": "act-001", "approver": "lead_analyst", "approved": True}
    res_approve = client.post("/api/actions/approve", json=approve_payload, params={"host": "test"})
    assert res_approve.status_code == 200
    result = res_approve.json()
    assert result["status"] == "updated"
    assert result["action"]["status"] == "executed"
