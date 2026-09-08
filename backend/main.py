"""
MailGuard - Backend API
FastAPI entrypoint with CORS, route registration, and health check.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import os

from config import CORS_ORIGINS, PORT, HOST
from routers.analyze import router as analyze_router
from routers.geolocation import router as geo_router
from routers.cases import router as cases_router
from routers.reports import router as reports_router

app = FastAPI(
    title="MailGuard Forensic Intelligence API",
    description="Backend API for email threat detection, header parsing, NLP analysis, and geolocation intelligence.",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# Enable CORS for frontend communications
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers
app.include_router(analyze_router)
app.include_router(geo_router)
app.include_router(cases_router)
app.include_router(reports_router)

@app.get("/api/health")
@app.get("/")
async def health_check():
    return {
        "status": "online",
        "service": "MailGuard Forensic Intelligence API",
        "version": "1.0.0",
        "docs": "/docs",
    }

if __name__ == "__main__":
    uvicorn.run("main:app", host=HOST, port=PORT, reload=True)
