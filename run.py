"""
Entry point for the SecureVault API server.

Usage:
    python run.py            # starts the FastAPI app on http://127.0.0.1:8000
    uvicorn backend.main:app --reload
"""
import uvicorn

if __name__ == "__main__":
    uvicorn.run("backend.main:app", host="127.0.0.1", port=8000, reload=True)
