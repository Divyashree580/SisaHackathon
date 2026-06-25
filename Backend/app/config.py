import os
from dotenv import load_dotenv

# Load env variables from .env if present
env_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), '.env')
load_dotenv(dotenv_path=env_path)


class Settings:
    PROJECT_NAME: str = "SISA Sentinel API"
    PROJECT_VERSION: str = "1.0.0"
    
    # Groq API Configurations
    GROQ_API_KEY: str = os.getenv("GROQ_API_KEY")
    GROQ_MODEL: str = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
    
    # MongoDB Configuration
    MONGODB_URI: str = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
    MONGODB_DATABASE: str = os.getenv("MONGODB_DATABASE", "sisa_sentinel")
    
    # NVD API Configuration
    NVD_API_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    NVD_API_KEY: str = os.getenv("NVD_API_KEY")
    NVD_TIMEOUT_SECONDS: int = 5

    # Server host & port — drives the base URL of this API
    API_HOST: str = os.getenv("API_HOST", "http://localhost")
    API_PORT: int = int(os.getenv("API_PORT", "8000"))

    @property
    def API_BASE_URL(self) -> str:
        """Full base URL composed from API_HOST and API_PORT."""
        return f"{self.API_HOST}:{self.API_PORT}"
    
    # CORS Configurations
    CORS_ORIGINS: list = [
        origin.strip() for origin in os.getenv("CORS_ORIGINS", "*").split(",") if origin.strip()
    ]

settings = Settings()
