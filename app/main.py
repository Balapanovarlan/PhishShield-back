from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from app.services.hybrid_detector import HybridDetector
from app.services.data_fetcher import DataFetcher

app = FastAPI(title="PhishShield API", version="1.0.0")

# Initialize detector and fetcher
detector = HybridDetector()

class URLCheckRequest(BaseModel):
    url: str

@app.get("/")
def read_root():
    return {"message": "Welcome to PhishShield Phishing Detection API"}

@app.post("/check")
def check_url(request: URLCheckRequest):
    if not request.url:
        raise HTTPException(status_code=400, detail="URL is required")
    
    result = detector.detect(request.url)
    return result

@app.post("/refresh-data")
def refresh_data():
    fetcher = DataFetcher()
    fetcher.fetch_phishtank()
    fetcher.fetch_tranco()
    detector.load_lists() # Reload into memory
    return {"message": "Threat intelligence databases updated successfully."}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
