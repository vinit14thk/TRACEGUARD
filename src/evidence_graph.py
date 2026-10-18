import pandas as pd
import networkx as nx


def build_evidence_graph(events: pd.DataFrame) -> nx.Graph:
    """
    Build an evidence graph from security events.

    Nodes represent events, users, source IPs, and devices.
    Edges explain which entities are associated with each event.
    Ground-truth labels are deliberately excluded from the graph.
    """
    graph = nx.Graph()

    for _, event in events.iterrows():
        event_id = str(event["event_id"])
        user = str(event["user"])
        source_ip = str(event["source_ip"])
        device = str(event["device"])

        event_node = f"event:{event_id}"
        user_node = f"user:{user}"
        ip_node = f"ip:{source_ip}"
        device_node = f"device:{device}"

        graph.add_node(
            event_node,
            node_type="event",
            event_id=event_id,
            timestamp=str(event["timestamp"]),
            event_type=str(event["event_type"]),
            status=str(event["status"]),
            process=str(event.get("process", "") or ""),
        )

        entities = [
            (user_node, "user", user),
            (ip_node, "ip", source_ip),
            (device_node, "device", device),
        ]

        for node_id, node_type, value in entities:
            graph.add_node(
                node_id,
                node_type=node_type,
                value=value,
            )

            graph.add_edge(
                event_node,
                node_id,
                relationship=f"event_involves_{node_type}",
                evidence_event_id=event_id,
            )

    return graph


def find_related_events(
    graph: nx.Graph,
    event_id: str,
) -> list[str]:
    """
    Find events connected through at least one shared entity.
    """
    target_node = f"event:{event_id}"

    if target_node not in graph:
        return []

    related = set()

    for entity_node in graph.neighbors(target_node):
        if graph.nodes[entity_node].get("node_type") == "event":
            continue

        for neighbor in graph.neighbors(entity_node):
            if (
                neighbor != target_node
                and graph.nodes[neighbor].get("node_type") == "event"
            ):
                related.add(graph.nodes[neighbor]["event_id"])

    return sorted(related)

def find_related_events_in_time(
    events: pd.DataFrame,
    event_id: str,
    minutes: int = 5,
) -> list[str]:
    """
    Find other events involving the same user or source IP
    within a configurable time window.
    """
    if minutes < 0:
        raise ValueError("minutes must be zero or greater")

    target_rows = events[events["event_id"].astype(str) == str(event_id)]

    if target_rows.empty:
        return []

    target = target_rows.iloc[0]
    target_time = pd.to_datetime(target["timestamp"])
    window = pd.Timedelta(minutes=minutes)

    same_user = events["user"].astype(str) == str(target["user"])
    same_ip = events["source_ip"].astype(str) == str(target["source_ip"])

    timestamps = pd.to_datetime(events["timestamp"])
    within_window = (timestamps - target_time).abs() <= window
    not_target = events["event_id"].astype(str) != str(event_id)

    related = events[same_user | same_ip]
    related = related[within_window.loc[related.index] & not_target.loc[related.index]]

    return sorted(related["event_id"].astype(str).tolist())