#!/usr/bin/env python3

import argparse
import csv
import pickle
import time
from pathlib import Path

import numpy as np
import pandas as pd
from prettytable import PrettyTable


ROOT = Path(__file__).resolve().parent
TIMEOUT = 15 * 60

MODEL_FILES = {
    "logistic": "models/LogisticRegression",
    "kmeans": "models/KMeans_Clustering",
    "svm": "models/SVC",
    "knearest": "models/KNeighbors",
    "kneighbors": "models/KNeighbors",
    "Randomforest": "models/RandomForestClassifier",
    "randomforest": "models/RandomForestClassifier",
    "gaussiannb": "models/GaussianNB",
}

FEATURE_COLUMNS = [
    "Delta Forward Packets",
    "Delta Forward Bytes",
    "Forward Instantaneous Packets per Second",
    "Forward Average Packets per second",
    "Forward Instantaneous Bytes per Second",
    "Forward Average Bytes per second",
    "Delta Reverse Packets",
    "Delta Reverse Bytes",
    "DeltaReverse Instantaneous Packets per Second",
    "Reverse Average Packets per second",
    "Reverse Instantaneous Bytes per Second",
    "Reverse Average Bytes per second",
]

CLUSTER_LABELS = {
    0: "dns",
    1: "game",
    2: "ping",
    3: "quake",
    4: "telnet",
    5: "voice",
}

flows = {}


class Flow:
    def __init__(self, time_start, datapath, inport, ethsrc, ethdst, outport, packets, bytes_count):
        self.time_start = time_start
        self.datapath = datapath
        self.inport = inport
        self.ethsrc = ethsrc
        self.ethdst = ethdst
        self.outport = outport

        self.forward_packets = packets
        self.forward_bytes = bytes_count
        self.forward_delta_packets = 0
        self.forward_delta_bytes = 0
        self.forward_inst_pps = 0.0
        self.forward_avg_pps = 0.0
        self.forward_inst_bps = 0.0
        self.forward_avg_bps = 0.0
        self.forward_status = "ACTIVE"
        self.forward_last_time = time_start

        self.reverse_packets = 0
        self.reverse_bytes = 0
        self.reverse_delta_packets = 0
        self.reverse_delta_bytes = 0
        self.reverse_inst_pps = 0.0
        self.reverse_avg_pps = 0.0
        self.reverse_inst_bps = 0.0
        self.reverse_avg_bps = 0.0
        self.reverse_status = "INACTIVE"
        self.reverse_last_time = time_start

    def updateforward(self, packets, bytes_count, curr_time):
        self.forward_delta_packets = packets - self.forward_packets
        self.forward_packets = packets
        if curr_time != self.time_start:
            self.forward_avg_pps = packets / float(curr_time - self.time_start)
        if curr_time != self.forward_last_time:
            self.forward_inst_pps = self.forward_delta_packets / float(curr_time - self.forward_last_time)

        self.forward_delta_bytes = bytes_count - self.forward_bytes
        self.forward_bytes = bytes_count
        if curr_time != self.time_start:
            self.forward_avg_bps = bytes_count / float(curr_time - self.time_start)
        if curr_time != self.forward_last_time:
            self.forward_inst_bps = self.forward_delta_bytes / float(curr_time - self.forward_last_time)
        self.forward_last_time = curr_time

        if self.forward_delta_bytes == 0 or self.forward_delta_packets == 0:
            self.forward_status = "INACTIVE"
        else:
            self.forward_status = "ACTIVE"

    def updatereverse(self, packets, bytes_count, curr_time):
        self.reverse_delta_packets = packets - self.reverse_packets
        self.reverse_packets = packets
        if curr_time != self.time_start:
            self.reverse_avg_pps = packets / float(curr_time - self.time_start)
        if curr_time != self.reverse_last_time:
            self.reverse_inst_pps = self.reverse_delta_packets / float(curr_time - self.reverse_last_time)

        self.reverse_delta_bytes = bytes_count - self.reverse_bytes
        self.reverse_bytes = bytes_count
        if curr_time != self.time_start:
            self.reverse_avg_bps = bytes_count / float(curr_time - self.time_start)
        if curr_time != self.reverse_last_time:
            self.reverse_inst_bps = self.reverse_delta_bytes / float(curr_time - self.reverse_last_time)
        self.reverse_last_time = curr_time

        if self.reverse_delta_bytes == 0 or self.reverse_delta_packets == 0:
            self.reverse_status = "INACTIVE"
        else:
            self.reverse_status = "ACTIVE"

    def features(self):
        return np.asarray(
            [
                self.forward_delta_packets,
                self.forward_delta_bytes,
                self.forward_inst_pps,
                self.forward_avg_pps,
                self.forward_inst_bps,
                self.forward_avg_bps,
                self.reverse_delta_packets,
                self.reverse_delta_bytes,
                self.reverse_inst_pps,
                self.reverse_avg_pps,
                self.reverse_inst_bps,
                self.reverse_avg_bps,
            ]
        ).reshape(1, -1)


def load_model(name):
    model_path = ROOT / MODEL_FILES[name]
    with model_path.open("rb") as infile:
        return pickle.load(infile)


def normalize_label(label):
    value = label[0] if hasattr(label, "__len__") and not isinstance(label, str) else label
    if isinstance(value, np.generic):
        value = value.item()
    if isinstance(value, int):
        return CLUSTER_LABELS.get(value, str(value))
    return str(value)


def predict_label(model, features):
    frame = pd.DataFrame(np.asarray(features).reshape(1, -1), columns=FEATURE_COLUMNS)
    return normalize_label(model.predict(frame))


def printclassifier(model):
    table = PrettyTable()
    table.field_names = ["Flow ID", "Source", "Destination", "Traffic Type", "Forward Status", "Reverse Status"]

    for key, flow in flows.items():
        label = predict_label(model, flow.features())
        table.add_row([key, flow.ethsrc, flow.ethdst, label, flow.forward_status, flow.reverse_status])
    print(table)


def detect_delimiter(header_line):
    return "\t" if "\t" in header_line else ","


def iter_dataset_rows():
    for path in sorted((ROOT / "datasets").glob("*.csv")):
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        if not lines:
            continue
        delimiter = detect_delimiter(lines[0])
        with path.open(newline="", encoding="utf-8", errors="replace") as handle:
            reader = csv.DictReader(handle, delimiter=delimiter)
            for row in reader:
                if any(column not in row or row[column] is None for column in FEATURE_COLUMNS):
                    continue
                try:
                    features = [float(row[column]) for column in FEATURE_COLUMNS]
                except ValueError:
                    continue
                yield path.name, row.get("Traffic Type", ""), features


def run_demo(model_name, limit):
    model = load_model(model_name)
    rows = list(iter_dataset_rows())
    table = PrettyTable()
    table.field_names = ["#", "Dataset", "Actual", "Predicted"]

    if not rows:
        print("No valid dataset rows found.")
        return

    feature_frame = pd.DataFrame([features for _, _, features in rows], columns=FEATURE_COLUMNS)
    predictions = [normalize_label([prediction]) for prediction in model.predict(feature_frame)]
    supervised = hasattr(model, "classes_")
    total = len(rows)
    correct = sum(1 for (_, actual, _), predicted in zip(rows, predictions) if actual == predicted)
    step = max(1, total // max(1, limit))
    shown_indexes = list(range(0, total, step))[:limit]

    for display_index, row_index in enumerate(shown_indexes, start=1):
        dataset_name, actual, _ = rows[row_index]
        table.add_row([display_index, dataset_name, actual, predictions[row_index]])

    print(table)
    if supervised:
        print("Demo accuracy on all valid dataset rows: %.2f%%" % ((correct / float(total)) * 100))
    else:
        print("KMeans is unsupervised; shown predictions use the saved cluster mapping.")


def import_scapy():
    try:
        from scapy.all import ICMP, IP, TCP, UDP, conf, sniff
    except ImportError as exc:
        raise SystemExit(
            "Scapy is not installed. Run: pip install -r requirements.txt\n"
            "For live capture on Windows, install Npcap too: https://npcap.com/"
        ) from exc
    return IP, TCP, UDP, ICMP, conf, sniff


def list_interfaces():
    _, _, _, _, conf, _ = import_scapy()
    print("Available capture interfaces:")
    for iface in conf.ifaces.values():
        print(f"- {iface.name}")


def packet_to_flow(packet, layers):
    IP, TCP, UDP, ICMP = layers
    if IP not in packet:
        return None

    ip_layer = packet[IP]
    protocol = str(ip_layer.proto)
    source_port = 0
    destination_port = 0

    if TCP in packet:
        protocol = "tcp"
        source_port = int(packet[TCP].sport)
        destination_port = int(packet[TCP].dport)
    elif UDP in packet:
        protocol = "udp"
        source_port = int(packet[UDP].sport)
        destination_port = int(packet[UDP].dport)
    elif ICMP in packet:
        protocol = "icmp"

    source = str(ip_layer.src)
    destination = str(ip_layer.dst)
    forward_key = (protocol, source, source_port, destination, destination_port)
    reverse_key = (protocol, destination, destination_port, source, source_port)
    return forward_key, reverse_key, source, destination, len(packet)


def update_flow_from_packet(packet, layers):
    parsed = packet_to_flow(packet, layers)
    if parsed is None:
        return False

    forward_key, reverse_key, source, destination, packet_len = parsed
    curr_time = int(time.time())

    if forward_key in flows:
        flow = flows[forward_key]
        flow.updateforward(flow.forward_packets + 1, flow.forward_bytes + packet_len, curr_time)
    elif reverse_key in flows:
        flow = flows[reverse_key]
        flow.updatereverse(flow.reverse_packets + 1, flow.reverse_bytes + packet_len, curr_time)
    else:
        protocol = forward_key[0]
        flows[forward_key] = Flow(curr_time, "windows", protocol, source, destination, protocol, 1, packet_len)
    return True


def run_capture(model_name, interface=None, interval=5, timeout=0, max_flows=20):
    IP, TCP, UDP, ICMP, _, sniff = import_scapy()
    model = load_model(model_name)
    layers = (IP, TCP, UDP, ICMP)
    started = time.monotonic()
    next_print = started + interval
    packet_count = 0
    ip_packet_count = 0

    print("Starting Windows packet capture.")
    print("If no packets appear, use an active interface from: python traffic_classifier.py interfaces")
    print("Npcap must be installed and PowerShell may need to run as Administrator.")
    print("Press Ctrl+C to stop.")

    def handle_packet(packet):
        nonlocal ip_packet_count, next_print, packet_count
        packet_count += 1
        if update_flow_from_packet(packet, layers):
            ip_packet_count += 1
        now = time.monotonic()
        if now >= next_print:
            print_capture_table(model, max_flows, packet_count, ip_packet_count)
            next_print = now + interval

    try:
        while True:
            if timeout > 0 and time.monotonic() - started >= timeout:
                break
            sniff(iface=interface, prn=handle_packet, store=False, timeout=1)
            now = time.monotonic()
            if now >= next_print:
                print_capture_table(model, max_flows, packet_count, ip_packet_count)
                next_print = now + interval
    except PermissionError as exc:
        raise SystemExit("Permission denied. Run PowerShell as Administrator for live packet capture.") from exc
    except RuntimeError as exc:
        raise SystemExit(
            "Live capture is not available yet. Install Npcap from https://npcap.com/ "
            "and run PowerShell as Administrator."
        ) from exc
    except KeyboardInterrupt:
        print("\nStopped capture.")
        return

    print_capture_table(model, max_flows, packet_count, ip_packet_count)
    print("Stopped capture.")


def print_capture_table(model, max_flows, packet_count=None, ip_packet_count=None):
    if not flows:
        if packet_count is None:
            print("No IP flows captured yet.")
        else:
            print(f"No IP flows captured yet. Raw packets: {packet_count}, IP packets: {ip_packet_count}.")
        return

    table = PrettyTable()
    table.field_names = ["#", "Flow", "Source", "Destination", "Predicted", "Fwd Packets", "Rev Packets"]

    recent_flows = list(flows.items())[-max_flows:]
    for index, (key, flow) in enumerate(recent_flows, start=1):
        label = predict_label(model, flow.features())
        table.add_row(
            [
                index,
                key[0],
                flow.ethsrc,
                flow.ethdst,
                label,
                flow.forward_packets,
                flow.reverse_packets,
            ]
        )
    print(table)


def build_parser():
    parser = argparse.ArgumentParser(description="Windows network traffic classifier")
    subparsers = parser.add_subparsers(dest="command")

    demo_parser = subparsers.add_parser("demo", help="run model predictions on existing dataset rows")
    demo_parser.add_argument("model", choices=sorted(MODEL_FILES), nargs="?", default="gaussiannb")
    demo_parser.add_argument("--limit", type=int, default=20, help="number of dataset rows to show")

    capture_parser = subparsers.add_parser("capture", help="capture live Windows packets and classify flows")
    capture_parser.add_argument("model", choices=sorted(MODEL_FILES), nargs="?", default="randomforest")
    capture_parser.add_argument("--iface", help="capture interface name; omit to use Scapy default")
    capture_parser.add_argument("--interval", type=int, default=5, help="seconds between printed tables")
    capture_parser.add_argument("--timeout", type=int, default=0, help="seconds to capture; 0 means run until Ctrl+C")
    capture_parser.add_argument("--max-flows", type=int, default=20, help="maximum flows to show each table")

    subparsers.add_parser("interfaces", help="list Windows packet capture interfaces")

    for model_name in sorted(MODEL_FILES):
        model_parser = subparsers.add_parser(model_name, help=f"capture live Windows traffic with {model_name}")
        model_parser.add_argument("--iface", help="capture interface name; omit to use Scapy default")
        model_parser.add_argument("--interval", type=int, default=5, help="seconds between printed tables")
        model_parser.add_argument("--timeout", type=int, default=0, help="seconds to capture; 0 means run until Ctrl+C")
        model_parser.add_argument("--max-flows", type=int, default=20, help="maximum flows to show each table")

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        return 0
    if args.command == "demo":
        run_demo(args.model, args.limit)
        return 0
    if args.command == "interfaces":
        list_interfaces()
        return 0
    if args.command == "capture":
        run_capture(args.model, args.iface, args.interval, args.timeout, args.max_flows)
        return 0
    if args.command in MODEL_FILES:
        run_capture(args.command, args.iface, args.interval, args.timeout, args.max_flows)
        return 0

    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
