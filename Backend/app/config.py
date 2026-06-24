import os
from dotenv import load_dotenv

# Load env variables from .env if present
load_dotenv()

class Settings:
    PROJECT_NAME: str = "SISA Sentinel API"
    PROJECT_VERSION: str = "1.0.0"
    
    # Groq API Configurations
    GROQ_API_KEY: str = os.getenv("GROQ_API_KEY", "")
    GROQ_MODEL: str = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
    
    # MongoDB Configuration
    MONGODB_URI: str = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
    MONGODB_DATABASE: str = os.getenv("MONGODB_DATABASE", "sisa_sentinel")
    
    # NVD API Configuration
    NVD_API_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    NVD_API_KEY: str = os.getenv("NVD_API_KEY", "")
    NVD_TIMEOUT_SECONDS: int = 5
    
    # CORS Configurations
    CORS_ORIGINS: list = [
        "http://localhost:5173",  # React/Vite dev port
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "*"
    ]

settings = Settings()
