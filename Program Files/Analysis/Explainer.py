from __future__ import annotations

from Models import DetectionResult, Document, IncidentCluster
from Utilities.text_utils import keyword_score, extract_excerpt

def select_relevant_documents(documents: list[Document], keywords: list[str], top_k: int = 2) -> list[tuple[str, str]]:
    scored: list[tuple[int, Document]] = []
    for doc in documents:
        score = keyword_score(doc.title, keywords) + keyword_score(doc.content, keywords)
        if score > 0:
            scored.append((score, doc))

    scored.sort(key=lambda item: item[0], reverse=True)
    selected: list[tuple[str, str]] = []

    for _, doc in scored[:top_k]:
        excerpt = extract_excerpt(doc.content, keywords, window=200)
        selected.append((doc.title, excerpt))
    return selected

def summarize_incident(cluster: IncidentCluster, detections: list[DetectionResult], documents: list[Document]) -> dict:
    triggered = [d for d in detections if d.triggered]
    keywords = [d.name.replace("_", " ") for d in triggered] + [e.action for e in cluster.events] + [e.message for e in cluster.events]

    if triggered:
        issue = ", ".join(d.name for d in triggered)
        incident_summary = f"Cluster {cluster.incident_id} shows signs of: {issue}."
        interpretation = "The event sequence contains security-relevant behavior that warrants analyst review."
        confidence = "medium" if len(triggered) < 3 else "high"
    else:
        incident_summary = f"Cluster {cluster.incident_id} does not match any current detection rule."
        interpretation = "The evidence is not strong enough to label this cluster as suspicious."
        confidence = "low"

    relevant_docs = select_relevant_documents(documents, keywords)
    recommendations = []
    for det in triggered:
        if det.recommendation:
            recommendations.append(det.recommendation)

    if not recommendations:
        recommendations.append("Continue monitoring and compare the activity against expected baseline behavior.")

    return {
        "incident_summary": incident_summary,
        "interpretation": interpretation,
        "confidence": confidence,
        "recommendations": recommendations,
        "relevant_docs": relevant_docs,
    }
