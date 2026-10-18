from pathlib import Path

import matplotlib
matplotlib.use("Agg")

import matplotlib.pyplot as plt
import pandas as pd
import networkx as nx

from evidence_graph import build_evidence_graph


def main():
    events = pd.read_csv("data/raw/security_events.csv")
    graph = build_evidence_graph(events)

    # Group nodes by type for a readable layout.
    node_types = nx.get_node_attributes(graph, "node_type")

    positions = {}
    type_x_positions = {
        "event": 0,
        "user": 2,
        "ip": 4,
        "device": 6,
    }

    for node_type, x_position in type_x_positions.items():
        nodes = [
            node for node in graph.nodes
            if node_types.get(node) == node_type
        ]

        for index, node in enumerate(nodes):
            positions[node] = (
                x_position,
                -index * 1.5,
            )

    plt.figure(figsize=(16, 10))

    node_colors = {
        "event": "#8ecae6",
        "user": "#90be6d",
        "ip": "#f9c74f",
        "device": "#f9844a",
    }

    for node_type, color in node_colors.items():
        nodes = [
            node for node in graph.nodes
            if node_types.get(node) == node_type
        ]

        nx.draw_networkx_nodes(
            graph,
            positions,
            nodelist=nodes,
            node_color=color,
            node_size=1300 if node_type == "event" else 1700,
            edgecolors="black",
            linewidths=0.5,
        )

    nx.draw_networkx_edges(
        graph,
        positions,
        alpha=0.45,
        width=1.2,
    )

    labels = {}
    for node, data in graph.nodes(data=True):
        node_type = data.get("node_type")

        if node_type == "event":
            labels[node] = data.get("event_id", node)
        elif node_type == "user":
            labels[node] = data.get("value", node)
        elif node_type == "ip":
            labels[node] = data.get("value", node)
        elif node_type == "device":
            labels[node] = data.get("value", node)

    nx.draw_networkx_labels(
        graph,
        positions,
        labels=labels,
        font_size=7,
    )

    plt.title(
        "TRACEGUARD — Security Evidence Graph",
        fontsize=16,
    )

    plt.text(
        0,
        1.0,
        "Events",
        fontsize=11,
        fontweight="bold",
        ha="center",
    )
    plt.text(
        2,
        1.0,
        "Users",
        fontsize=11,
        fontweight="bold",
        ha="center",
    )
    plt.text(
        4,
        1.0,
        "Source IPs",
        fontsize=11,
        fontweight="bold",
        ha="center",
    )
    plt.text(
        6,
        1.0,
        "Devices",
        fontsize=11,
        fontweight="bold",
        ha="center",
    )

    plt.axis("off")
    plt.tight_layout()

    output_path = Path("reports/evidence_graph.png")
    output_path.parent.mkdir(parents=True, exist_ok=True)

    plt.savefig(
        output_path,
        dpi=200,
        bbox_inches="tight",
    )
    plt.close()

    print(f"Graph image saved to: {output_path}")
    print(f"Nodes: {graph.number_of_nodes()}")
    print(f"Edges: {graph.number_of_edges()}")


if __name__ == "__main__":
    main()