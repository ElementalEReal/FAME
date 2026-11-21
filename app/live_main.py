"""Isolated FAME LIVE application entry point."""

from fastapi import FastAPI

app = FastAPI(
    title="FAME LIVE",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

@app.get("/healthz", include_in_schema=False)
def healthz():
    return {"status": "ok", "service": "fame-live"}
