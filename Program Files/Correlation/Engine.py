from __future__ import annotations

from collections import defaultdict
from itertools import count

from Configuration import CORRELATION_WINDOW_MINUTES
from Models import Event, IncidentCluster
from Utilities.time_utils import within_window

def event_key(event: Event) -> str:
    if event.session_id:
        return f"session:{event.session_id}"
    if event.user and event.ip_address and event.host:
        return f"useriphost:{event.user}|{event.ip_address}|{event.host}"
    if event.user and event.host:
        return f"userhost:{event.user}|{event.host}"
    if event.host and event.process_name:
        return f"hostproc:{event.host}|{event.process_name}"
    if event.host:
        return f"host:{event.host}"
    if event.user:
        return f"user:{event.user}"
    return f"source:{event.source_file}"

def cluster_events(events: list[Event], window_minutes: int = CORRELATION_WINDOW_MINUTES) -> list[IncidentCluster]:
    clusters_by_key: dict[str, list[IncidentCluster]] = defaultdict(list)
    incident_counter = count(1)

    for event in sorted(events, key=lambda e: e.timestamp):
        key = event_key(event)
        cluster_list = clusters_by_key[key]

        if not cluster_list:
            cluster = IncidentCluster(
                incident_id=f"INC-{next(incident_counter):03d}",
                key=key,
                events=[event],
            )
            cluster_list.append(cluster)
            continue

        last_cluster = cluster_list[-1]
        last_event = last_cluster.events[-1]

        if within_window(last_event.timestamp, event.timestamp, window_minutes):
            last_cluster.events.append(event)
        else:
            cluster = IncidentCluster(
                incident_id=f"INC-{next(incident_counter):03d}",
                key=key,
                events=[event],
            )
            cluster_list.append(cluster)

    clusters: list[IncidentCluster] = []
    for key in sorted(clusters_by_key.keys()):
        clusters.extend(clusters_by_key[key])

    return sorted(clusters, key=lambda c: c.events[0].timestamp)
