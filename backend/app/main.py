from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import alerts, predictions, graphs, replay, chat, auth

app = FastAPI(
    title="AIVA-KS API",
    description="AI-Powered Intelligent Kernel Security Visualizer",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router, prefix="/api/auth", tags=["auth"])
app.include_router(alerts.router, prefix="/api/alerts", tags=["alerts"])
app.include_router(predictions.router, prefix="/api/predictions", tags=["predictions"])
app.include_router(graphs.router, prefix="/api/graphs", tags=["graphs"])
app.include_router(replay.router, prefix="/api/replay", tags=["replay"])
app.include_router(chat.router, prefix="/api/chat", tags=["chat"])


@app.get("/api/health")
async def health():
    return {"status": "ok"}
