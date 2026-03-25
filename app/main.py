from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from app.services.hybrid_detector import HybridDetector
from app.services.data_fetcher import DataFetcher
from typing import Optional

app = FastAPI(title="PhishShield API", version="1.0.0")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins for development
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods
    allow_headers=["*"],  # Allows all headers
)

# Initialize detector and fetcher
detector = HybridDetector()

class URLCheckRequest(BaseModel):
    url: str

@app.get("/")
def read_root():
    return {"message": "Welcome to PhishShield Phishing Detection API"}

@app.post("/check")
def check_url(request: URLCheckRequest, locale: Optional[str] = Header(None)):
    print(f"Incoming scan request: {request.url}")
    # Fallback to English if no locale is provided or if it's not supported
    active_locale = locale if locale in ["en", "ru"] else "en"
    
    if not request.url:
        raise HTTPException(status_code=400, detail="URL is required")
    
    try:
        result = detector.detect(request.url, locale=active_locale)
        print(f"Scan result: {result['is_phishing']}")
        return result
    except Exception as e:
        print(f"Error during scan: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

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
