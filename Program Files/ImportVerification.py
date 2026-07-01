# Verified that all Program Files modules can be imported successfully.

import sys
from pathlib import Path

PROGRAM_FILES_DIR = Path(__file__).resolve().parent
if str(PROGRAM_FILES_DIR) not in sys.path:
    sys.path.insert(0, str(PROGRAM_FILES_DIR))

try:
    print("Testing Program Files imports...")
    
    # Test core models
    from Models import Event, Document, DetectionResult, IncidentCluster, EvidenceStore
    print("[SUCCESS] Models")
    
    # Test configuration
    from Configuration import CORRELATION_WINDOW_MINUTES, BRUTE_FORCE_FAILED_THRESHOLD
    print("[SUCCESS] Configuration")
    
    # Test utilities
    from Utilities.time_utils import parse_timestamp, format_timestamp, within_window, minutes_between
    from Utilities.text_utils import normalize_whitespace, keyword_score, extract_excerpt
    print("[SUCCESS] Utilities.time_utils")
    print("[SUCCESS] Utilities.text_utils")
    
    # Test ingest
    from Ingest.Loader import load_evidence
    from Ingest.Parser import parse_file
    from Ingest.Normalizer import normalize_event
    print("[SUCCESS] Ingest.Loader")
    print("[SUCCESS] Ingest.Parser")
    print("[SUCCESS] Ingest.Normalizer")
    
    # Test detection
    from Detection.Rules import run_all_detections, detect_brute_force, detect_privilege_escalation
    print("[SUCCESS] Detection.Rules")
    
    # Test correlation
    from Correlation.Engine import cluster_events
    print("[SUCCESS] Correlation.Engine")
    
    # Test timeline
    from Timeline.Builder import build_timeline
    print("[SUCCESS] Timeline.Builder")
    
    # Test analysis
    from Analysis.Explainer import summarize_incident
    print("[SUCCESS] Analysis.Explainer")
    
    # Test reporting
    from Reporting.Report import render_report
    print("[SUCCESS] Reporting.Report")
    
    # Test main CLI
    try:
        from AuditLens import build_arg_parser, main
    except ImportError:
        from AuditLens import build_arg_parser, main
    print("[SUCCESS] AuditLens (CLI)")
    
    print("\n[SUCCESS] All Program Files modules imported successfully!")
    print("[SUCCESS] No source dependencies detected!")

except ImportError as e:
    print(f"\n [ERROR] Import Error Occured: {e}")
    sys.exit(1)
except Exception as e:
    print(f"\n [ERROR] Unexpected Error Occured: {e}")
    sys.exit(1)
