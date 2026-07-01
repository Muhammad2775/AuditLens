# Technical Project Guide

# 1. Introduction
AuditLens is a modular, offline-first security event correlation engine designed to bridge the gap between fragmented raw log files and actionable incident investigations. The system is built upon the philosophy of **Evidence-First** analysis, ensuring that every detection result and AI-generated summary is strictly grounded in normalized, deterministic log evidence rather than probabilistic inference.

# 2. System Goal
The primary objective of AuditLens is to automate the labor-intensive process of correlating disparate security events.

By ingesting heterogeneous data sources—including CSV, TXT, JSON, and Markdown files—normalizing them into a unified event schema, and executing deterministic detection logic, the platform reconstructs incident timelines and produces high-confidence investigation summaries suitable for Security Operations Center (SOC) analysts.

# 3. Overall System Architecture
AuditLens follows a linear, unidirectional processing pipeline that transforms raw evidence into structured security intelligence.

```text
                Raw Security Logs
        (CSV / TXT / JSON / Markdown)
                      │
                      ▼
           Ingestion & Validation Layer
                      │
                      ▼
          Normalization (Unified Schema)
                      │
                      ▼
             In-Memory Evidence Store
                      │
                      ▼
            Correlation Engine
       (Temporal + Entity-Based Grouping)
                      │
                      ▼
        Deterministic Detection Engine
                      │
                      ▼
       Timeline Reconstruction & Context
                      │
                      ▼
      Human-Readable Investigation Report
```

The architecture is composed of the following layers:
- **Ingestion Layer**
  - Discovers and validates supported input files.
- **Normalization Layer**
  - Converts heterogeneous inputs into the standardized 11-field Unified Event Structure.
- **Evidence Store**
  - Acts as the single in-memory source of truth for all normalized events during execution.
- **Correlation Engine**
  - Groups related events into discrete `IncidentCluster` objects using temporal proximity and shared entities such as user, host, IP address, or session identifiers.
- **Detection Layer**
  - Executes deterministic security heuristics against each incident cluster.
- **Presentation & Reporting Layer**
  - Produces chronological reports enriched with evidence excerpts and contextual recommendations.

# 4. Components & Logic

## 4.1 Ingestion and Normalization (`Ingest/`)
### `Parser.py`
Responsible for extracting information from supported input formats.

Its responsibilities include:
- Parsing CSV audit records
- Processing structured TXT system and application logs using regular expressions
- Reading JSON event records
- Loading Markdown documentation

All parsed information is converted into intermediate Python dictionaries before normalization.

### `Normalizer.py`
This module represents the core design layer of the ingestion pipeline.

Its responsibilities include:
- Enforcing the standardized **11-field Unified Event Structure**
- Inferring missing event categories when sufficient contextual evidence exists
  - Example: Automatically classifying an event as `authentication` when keywords such as *login* are detected.
- Converting timestamps into timezone-aware UTC `datetime` objects
- Standardizing severity levels and event actions

Normalization guarantees that downstream processing remains independent of the original log format.

### `Loader.py`
Acts as the orchestration layer.

Responsibilities include:
- File discovery using filesystem traversal
- Dispatching files to the appropriate parser
- Handling malformed records gracefully
- Preventing ingestion failures caused by individual parsing errors

## 4.2 Correlation Engine (`Correlation/`)

### `Engine.py`
The correlation engine groups normalized events into investigation clusters.

Implementation characteristics include:

- Uses Python's `defaultdict` to organize event buckets.
- Generates composite correlation keys such as:
  - `session_id`
  - `user | ip | host`
  - `host | process`
- Implements a **Sliding Window** algorithm.

The default correlation window is **15 minutes**.

If an incoming event falls outside the temporal boundary of an existing cluster, the engine automatically creates a new `IncidentCluster`.

## 4.3 Detection Layer (`Detection/`)

### `Rules.py`
Implements deterministic detection heuristics.

Rather than evaluating isolated events, detection functions analyze complete incident clusters.

### Detection Logic
Each detection routine searches for predefined behavioral patterns.

Example:

```text
Failed Login
      │
      ▼
Failed Login
      │
      ▼
Failed Login
      │
      ▼
Successful Login
```

This sequence satisfies the brute-force authentication rule when it occurs within the configured correlation window.

### Confidence Scoring
Detection confidence is calculated using manually assigned weighting values ranging from:

```text
0.0 ───────────────────────────► 1.0
Low Confidence             High Confidence
```

Confidence depends on observable evidence rather than statistical prediction.

For example:
- Number of failed login attempts
- Presence of privilege escalation
- Consistency of correlated entities
- Completeness of the attack chain

## 4.4 Reporting and Context (`Analysis/`, `Timeline/`, `Reporting/`)

### `Explainer.py`
This component enhances investigation reports using contextual documentation.

It performs:
- Keyword scoring
- Markdown document ranking
- Policy and playbook matching
- Relevant excerpt extraction

The goal is to provide analysts with procedural guidance related to detected incidents.

### `Builder.py`
Responsible for reconstructing chronological event timelines.

The module transforms internal event objects into human-readable investigative narratives while preserving temporal ordering.

## 4.5 Core Models (`Models.py`)
The project schema is defined using Python **dataclasses**.

Core objects include:

- `Event`
- `Document`
- `IncidentCluster`
- `DetectionResult`

Using dataclasses provides:

- Strong typing
- Cleaner interfaces
- Simplified object construction
- Improved maintainability
- Validation across subsystem boundaries

These models form the contract shared between ingestion, correlation, detection, and reporting.

# 5. Detailed Runtime Control Flow
The runtime execution proceeds through the following sequence.

## Step 1 — Initialization
The application entry point (`auditlens.py`) initializes:

- Command-line argument parsing
- Configuration loading
- Input directory selection

## Step 2 — Evidence Ingestion
`load_evidence()` performs:

1. Directory traversal
2. File parsing
3. Event normalization
4. Event object creation

All resulting `Event` objects are stored inside the in-memory **Evidence Store**.

## Step 3 — Event Clustering
`cluster_events()` executes the correlation phase.

The engine:

1. Sorts events chronologically.
2. Computes correlation keys.
3. Evaluates temporal relationships.
4. Constructs `IncidentCluster` objects.

## Step 4 — Rule Execution
For every incident cluster:

```text
IncidentCluster
       │
       ▼
run_all_detections()
       │
       ▼
DetectionResult
```

Each rule evaluates only the evidence contained within its assigned cluster.

## Step 5 — Contextual Analysis
`summarize_incident()` enriches the detection results.

It cross-references:

- Detection findings
- Markdown policy documents
- Operational playbooks

The highest-scoring contextual excerpts are included in the investigation summary.

## Step 6 — Report Generation
`render_report()` combines:

- Incident clusters
- Detection results
- Generated timelines
- AI-assisted summaries

into a unified investigation report.

## Step 7 — Program Termination
AuditLens performs no persistent side effects.

Specifically:

- No databases are modified.
- No logs are overwritten.
- No external systems are contacted.

The application terminates after returning an appropriate process exit code.

# 6. Limitations and Scope

## In-Memory Architecture
AuditLens intentionally avoids persistent storage technologies such as SQL or NoSQL databases.

Advantages:

- Lightweight
- Fast execution
- Minimal dependencies

Limitations:

- Dataset size is constrained by available system memory.

## Deterministic Detection
AuditLens does **not** employ:

- Machine learning
- Neural networks
- Predictive analytics
- Behavioral anomaly detection

Detection relies entirely on predefined security heuristics.

Consequently, attack patterns that do not match existing rules will not be identified.

## Offline Data Scope
The platform is designed for offline forensic analysis.

It does **not** currently support:

- Real-time event streaming
- Live endpoint monitoring
- SIEM integration
- Continuous event ingestion

## Synthetic Dataset Assumptions
The parser assumes reasonable structural consistency within input data.

Highly inconsistent, severely corrupted, or proprietary log formats may result in events being classified as:

- `raw_log`

with correspondingly low-confidence severity classifications.

# 7. Summary
AuditLens provides a clean, modular, and Pythonic framework for deterministic security event analysis.

By separating ingestion (`Parser.py`, `Normalizer.py`) from correlation (`Engine.py`), detection (`Rules.py`), and presentation (`Explainer.py`, `Report.py`), the platform remains highly extensible while preserving clear architectural boundaries.

Every investigation output remains directly traceable to the originating evidence, reinforcing the project's Evidence-First philosophy and ensuring explainability throughout the analysis pipeline.

These characteristics make AuditLens well suited for:

- Security research
- SOC analyst training
- Detection rule development
- Incident response exercises
- Playbook validation
- Offline forensic investigations