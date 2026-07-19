from fastapi import FastAPI

app = FastAPI(
    title=" Password Manager SentinelVault API",
    description="Cybersecurity Password Manager API",
    version="1.0.0"
)


@app.get("/")
def root():
    return {
        "message": "Welcome to SentinelVault API - Cybersecurity Password Manager API   - KHAWLAH "
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy $$$$$$$"
    }