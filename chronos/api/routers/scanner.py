"""CHRONOS API — File & Directory Scanner Router."""
from __future__ import annotations

import os
from typing import Optional
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from chronos.intelligence.scanner import SignatureEngine

router = APIRouter(tags=["Scanner"])
scanner = SignatureEngine()


class ScanRequest(BaseModel):
    path: str
    max_files: Optional[int] = 200


@router.post("/scan/file")
async def scan_file_endpoint(req: ScanRequest):
    if not os.path.exists(req.path):
        raise HTTPException(status_code=404, detail="File path not found")
    res = scanner.scan_file(req.path)
    return {
        "status": "threat_detected" if res.is_threat else "clean",
        "result": {
            "path": res.target_path,
            "is_threat": res.is_threat,
            "threat_name": res.threat_name,
            "threat_type": res.threat_type,
            "severity": res.severity,
            "confidence": res.confidence,
            "sha256": res.sha256,
            "description": res.description,
        }
    }


@router.post("/scan/directory")
async def scan_directory_endpoint(req: ScanRequest):
    if not os.path.exists(req.path):
        raise HTTPException(status_code=404, detail="Directory path not found")
    threats = scanner.scan_directory(req.path, max_files=req.max_files or 200)
    return {
        "scanned_path": req.path,
        "threats_found_count": len(threats),
        "threats": [
            {
                "path": t.target_path,
                "threat_name": t.threat_name,
                "severity": t.severity,
                "confidence": t.confidence,
                "sha256": t.sha256,
                "description": t.description,
            }
            for t in threats
        ]
    }
