from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "Data"
RAW_DIR = DATA_DIR / "Raw"
SAMPLE_DIR = DATA_DIR / "Sample"
PROCESSED_DIR = BASE_DIR / "processed"

SUPPORTED_EXTENSIONS = {".csv", ".txt", ".md", ".json", ".log"}

CORRELATION_WINDOW_MINUTES = 15
BRUTE_FORCE_FAILED_THRESHOLD = 2

SEVERITY_ORDER = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}
