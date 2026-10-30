"""
CodeGuard AI - Application Settings
Reads configuration from environment variables with safe defaults.
"""
import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env file if present
env_path = Path(__file__).parent.parent / ".env"
load_dotenv(dotenv_path=env_path)

# ── Gemini / LLM ────────────────────────────────────────────────────────────
GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL: str = os.getenv("GEMINI_MODEL", "gemini-3.8-flash")
LLM_TIMEOUT: int = int(os.getenv("LLM_TIMEOUT", "30"))
LLM_MAX_TOKENS: int = int(os.getenv("LLM_MAX_TOKENS", "4096"))

# ── Application ──────────────────────────────────────────────────────────────
APP_NAME: str = "CodeGuard AI"
APP_TAGLINE: str = "Intelligent Code Review. Safer Software."
APP_VERSION: str = "1.0.0"

# ── Paths ────────────────────────────────────────────────────────────────────
BASE_DIR: Path = Path(__file__).parent.parent
DATA_DIR: Path = BASE_DIR / "data"
OUTPUTS_DIR: Path = BASE_DIR / "outputs"
EDA_DIR: Path = OUTPUTS_DIR / "eda"
REPORTS_DIR: Path = OUTPUTS_DIR / "reports"

# Database
DB_PATH: Path = BASE_DIR / "database" / "codeguard_history.db"

# ── Limits ───────────────────────────────────────────────────────────────────
MAX_FILE_SIZE_KB: int = int(os.getenv("MAX_FILE_SIZE_KB", "500"))
ALLOWED_EXTENSIONS: tuple = (
    ".py", ".java", ".js", ".jsx", ".ts", ".tsx",
    ".cpp", ".cc", ".cxx", ".c", ".h", ".hpp",
    ".cs", ".go", ".rs", ".php", ".rb", ".sql", ".html", ".css"
)

# ── Dataset ──────────────────────────────────────────────────────────────────
DATASET_PATH: Path = DATA_DIR / "dataset.csv"
PROCESSED_DATASET_PATH: Path = DATA_DIR / "processed_dataset.csv"
DATA_DICT_PATH: Path = DATA_DIR / "data_dictionary.csv"

# Ensure output dirs exist
EDA_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)
