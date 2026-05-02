#!/usr/bin/env python3

import argparse
import csv
import pickle
import time
from collections import Counter, deque
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

EVALUATION_MODEL_NAMES = [
    "Randomforest",
    "gaussiannb",
    "knearest",
    "kneighbors",
    "logistic",
    "randomforest",
    "svm",
]

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
packet_events = deque(maxlen=200)


class Flow:
    def __init__(
        self,
        time_start,
        datapath,
        inport,
        ethsrc,
        ethdst,
        outport,
        packets,
        bytes_count,
        flow_id=None,
        protocol=None,
        source_port=0,
        destination_port=0,
    ):
        self.flow_id = flow_id
        self.time_start = time_start
        self.datapath = datapath
        self.inport = inport
        self.ethsrc = ethsrc
        self.ethdst = ethdst
        self.outport = outport
        self.protocol = protocol or inport
        self.source_port = int(source_port or 0)
        self.destination_port = int(destination_port or 0)

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
        self.forward_report_packets = 0
        self.forward_report_bytes = 0
        self.reverse_report_packets = 0
        self.reverse_report_bytes = 0
        self.last_seen_time = time_start
        self.last_prediction = ""

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

    def addforwardpacket(self, bytes_count, curr_time):
        self.forward_packets += 1
        self.forward_bytes += bytes_count
        self.last_seen_time = curr_time

    def addreversepacket(self, bytes_count, curr_time):
        self.reverse_packets += 1
        self.reverse_bytes += bytes_count
        self.last_seen_time = curr_time

    def refreshmetrics(self, curr_time):
        forward_interval = max(curr_time - self.forward_last_time, 1e-9)
        reverse_interval = max(curr_time - self.reverse_last_time, 1e-9)
        lifetime = max(curr_time - self.time_start, 1e-9)

        self.forward_delta_packets = self.forward_packets - self.forward_report_packets
        self.forward_delta_bytes = self.forward_bytes - self.forward_report_bytes
        self.forward_inst_pps = self.forward_delta_packets / forward_interval
        self.forward_inst_bps = self.forward_delta_bytes / forward_interval
        self.forward_avg_pps = self.forward_packets / lifetime
        self.forward_avg_bps = self.forward_bytes / lifetime
        self.forward_status = "ACTIVE" if self.forward_delta_packets and self.forward_delta_bytes else "INACTIVE"
        self.forward_report_packets = self.forward_packets
        self.forward_report_bytes = self.forward_bytes
        self.forward_last_time = curr_time

        self.reverse_delta_packets = self.reverse_packets - self.reverse_report_packets
        self.reverse_delta_bytes = self.reverse_bytes - self.reverse_report_bytes
        self.reverse_inst_pps = self.reverse_delta_packets / reverse_interval
        self.reverse_inst_bps = self.reverse_delta_bytes / reverse_interval
        self.reverse_avg_pps = self.reverse_packets / lifetime
        self.reverse_avg_bps = self.reverse_bytes / lifetime
        self.reverse_status = "ACTIVE" if self.reverse_delta_packets and self.reverse_delta_bytes else "INACTIVE"
        self.reverse_report_packets = self.reverse_packets
        self.reverse_report_bytes = self.reverse_bytes
        self.reverse_last_time = curr_time

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

    def duration(self, curr_time=None):
        return max((curr_time or time.time()) - self.time_start, 0.0)


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


def load_dataset_frame(drop_zero_rows=False):
    rows = []
    issues = []
    summaries = []

    for path in sorted((ROOT / "datasets").glob("*.csv")):
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        if not lines:
            summaries.append(
                {
                    "dataset": path.name,
                    "total": 0,
                    "valid": 0,
                    "invalid": 0,
                    "labels": {},
                    "missing_columns": ["empty file"],
                }
            )
            continue

        delimiter = detect_delimiter(lines[0])
        total = 0
        valid = 0
        labels = Counter()
        missing_columns = []

        with path.open(newline="", encoding="utf-8", errors="replace") as handle:
            reader = csv.DictReader(handle, delimiter=delimiter)
            fieldnames = reader.fieldnames or []
            missing_columns = [column for column in FEATURE_COLUMNS + ["Traffic Type"] if column not in fieldnames]

            for row_number, row in enumerate(reader, start=2):
                total += 1
                label = row.get("Traffic Type", "")
                if label:
                    labels[label] += 1

                if missing_columns:
                    issues.append((path.name, row_number, "missing columns: %s" % ", ".join(missing_columns)))
                    continue

                if not label:
                    issues.append((path.name, row_number, "missing traffic label"))
                    continue

                if any(row.get(column) in (None, "") for column in FEATURE_COLUMNS):
                    issues.append((path.name, row_number, "missing feature value"))
                    continue

                try:
                    features = [float(row[column]) for column in FEATURE_COLUMNS]
                except ValueError:
                    issues.append((path.name, row_number, "invalid numeric feature"))
                    continue

                if drop_zero_rows and all(value == 0 for value in features):
                    issues.append((path.name, row_number, "dropped all-zero feature row"))
                    continue

                rows.append({"Dataset": path.name, "Traffic Type": label, **dict(zip(FEATURE_COLUMNS, features))})
                valid += 1

        summaries.append(
            {
                "dataset": path.name,
                "total": total,
                "valid": valid,
                "invalid": total - valid,
                "labels": dict(labels),
                "missing_columns": missing_columns,
            }
        )

    return pd.DataFrame(rows), issues, summaries


def run_validate_data():
    frame, issues, summaries = load_dataset_frame()

    summary_table = PrettyTable()
    summary_table.field_names = ["Dataset", "Rows", "Valid", "Invalid", "Labels"]
    for item in summaries:
        labels = ", ".join("%s=%s" % (label, count) for label, count in sorted(item["labels"].items()))
        if item["missing_columns"]:
            labels = "missing columns"
        summary_table.add_row([item["dataset"], item["total"], item["valid"], item["invalid"], labels])

    print("Dataset Summary")
    print(summary_table)

    if frame.empty:
        print("No valid dataset rows found.")
        return

    class_table = PrettyTable()
    class_table.field_names = ["Class", "Rows"]
    for label, count in frame["Traffic Type"].value_counts().sort_index().items():
        class_table.add_row([label, count])
    print("Class Balance")
    print(class_table)

    feature_frame = frame[FEATURE_COLUMNS]
    all_zero_rows = int((feature_frame == 0).all(axis=1).sum())
    duplicate_rows = int(frame.duplicated(subset=FEATURE_COLUMNS, keep=False).sum())
    duplicate_groups = frame[frame.duplicated(subset=FEATURE_COLUMNS, keep=False)].groupby(FEATURE_COLUMNS, dropna=False)
    ambiguous_groups = 0
    for _, group in duplicate_groups:
        if group["Traffic Type"].nunique() > 1:
            ambiguous_groups += 1

    quality_table = PrettyTable()
    quality_table.field_names = ["Check", "Result"]
    quality_table.add_row(["valid rows", len(frame)])
    quality_table.add_row(["missing values in features", int(feature_frame.isna().sum().sum())])
    quality_table.add_row(["non-finite feature values", int((~np.isfinite(feature_frame.to_numpy(dtype=float))).sum())])
    quality_table.add_row(["all-zero feature rows", all_zero_rows])
    quality_table.add_row(["duplicate feature rows", duplicate_rows])
    quality_table.add_row(["ambiguous duplicate groups", ambiguous_groups])
    quality_table.add_row(["recorded issues", len(issues)])
    print("Data Quality Checks")
    print(quality_table)

    model_table = PrettyTable()
    model_table.field_names = ["Model", "Type", "Model Classes", "Classes Missing In Data", "Data Classes Missing In Model"]
    dataset_labels = set(frame["Traffic Type"].unique())
    for model_name, model_path in sorted(MODEL_FILES.items()):
        if model_name == "Randomforest":
            continue
        model = load_model(model_name)
        classes = getattr(model, "classes_", None)
        if classes is None:
            model_table.add_row([model_name, type(model).__name__, "unsupervised", "-", "-"])
            continue
        model_labels = set(str(label) for label in classes)
        model_table.add_row(
            [
                model_name,
                type(model).__name__,
                ", ".join(sorted(model_labels)),
                ", ".join(sorted(model_labels - dataset_labels)) or "-",
                ", ".join(sorted(dataset_labels - model_labels)) or "-",
            ]
        )
    print("Saved Model/Data Contract")
    print(model_table)

    if issues:
        issue_table = PrettyTable()
        issue_table.field_names = ["Dataset", "Row", "Issue"]
        for dataset_name, row_number, issue in issues[:10]:
            issue_table.add_row([dataset_name, row_number, issue])
        print("First Data Issues")
        print(issue_table)


def build_evaluation_model(model_name, random_state):
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.linear_model import LogisticRegression
    from sklearn.naive_bayes import GaussianNB
    from sklearn.neighbors import KNeighborsClassifier
    from sklearn.pipeline import make_pipeline
    from sklearn.preprocessing import StandardScaler
    from sklearn.svm import SVC

    normalized_name = "randomforest" if model_name == "Randomforest" else model_name
    if normalized_name == "randomforest":
        return RandomForestClassifier(n_estimators=100, random_state=random_state)
    if normalized_name in ("knearest", "kneighbors"):
        return make_pipeline(StandardScaler(), KNeighborsClassifier())
    if normalized_name == "gaussiannb":
        return GaussianNB()
    if normalized_name == "svm":
        return make_pipeline(StandardScaler(), SVC())
    if normalized_name == "logistic":
        return LogisticRegression(max_iter=10000)
    raise SystemExit("Evaluation is supported for supervised models only. Use randomforest, knearest, gaussiannb, svm, or logistic.")


def run_evaluate(model_name, test_size, random_state, drop_zero_rows):
    from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
    from sklearn.model_selection import train_test_split

    frame, issues, _ = load_dataset_frame(drop_zero_rows=drop_zero_rows)
    if frame.empty:
        print("No valid dataset rows found.")
        return

    labels = sorted(frame["Traffic Type"].unique())
    if len(labels) < 2:
        print("At least two traffic classes are required for evaluation.")
        return

    x = frame[FEATURE_COLUMNS]
    y = frame["Traffic Type"]
    x_train, x_test, y_train, y_test = train_test_split(
        x,
        y,
        test_size=test_size,
        random_state=random_state,
        stratify=y,
    )

    model = build_evaluation_model(model_name, random_state)
    model.fit(x_train, y_train)
    predictions = model.predict(x_test)
    accuracy = accuracy_score(y_test, predictions)

    result_table = PrettyTable()
    result_table.field_names = ["Metric", "Value"]
    result_table.add_row(["model", model_name])
    result_table.add_row(["valid rows", len(frame)])
    result_table.add_row(["train rows", len(x_train)])
    result_table.add_row(["test rows", len(x_test)])
    result_table.add_row(["test size", test_size])
    result_table.add_row(["random state", random_state])
    result_table.add_row(["dropped all-zero rows", "yes" if drop_zero_rows else "no"])
    result_table.add_row(["data issues ignored", len(issues)])
    result_table.add_row(["accuracy", "%.2f%%" % (accuracy * 100)])
    print("Holdout Evaluation")
    print(result_table)

    confusion = confusion_matrix(y_test, predictions, labels=labels)
    matrix_table = PrettyTable()
    matrix_table.field_names = ["Actual \\ Predicted"] + labels
    for label, row in zip(labels, confusion):
        matrix_table.add_row([label] + list(row))
    print("Confusion Matrix")
    print(matrix_table)

    print("Classification Report")
    print(classification_report(y_test, predictions, labels=labels, zero_division=0))


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
    return {
        "forward_key": forward_key,
        "reverse_key": reverse_key,
        "source": source,
        "destination": destination,
        "source_port": source_port,
        "destination_port": destination_port,
        "protocol": protocol,
        "length": len(packet),
    }


def update_flow_from_packet(packet, layers):
    parsed = packet_to_flow(packet, layers)
    if parsed is None:
        return None

    forward_key = parsed["forward_key"]
    reverse_key = parsed["reverse_key"]
    source = parsed["source"]
    destination = parsed["destination"]
    source_port = parsed["source_port"]
    destination_port = parsed["destination_port"]
    protocol = parsed["protocol"]
    packet_len = parsed["length"]
    curr_time = time.time()

    if forward_key in flows:
        flow = flows[forward_key]
        flow.addforwardpacket(packet_len, curr_time)
        direction = "forward"
    elif reverse_key in flows:
        flow = flows[reverse_key]
        flow.addreversepacket(packet_len, curr_time)
        direction = "reverse"
    else:
        flow = Flow(
            curr_time,
            "windows",
            protocol,
            source,
            destination,
            protocol,
            1,
            packet_len,
            flow_id=len(flows) + 1,
            protocol=protocol,
            source_port=source_port,
            destination_port=destination_port,
        )
        flows[forward_key] = flow
        direction = "new"

    return {
        "time": curr_time,
        "flow_id": flow.flow_id,
        "direction": direction,
        "protocol": protocol,
        "source": source,
        "source_port": source_port,
        "destination": destination,
        "destination_port": destination_port,
        "bytes": packet_len,
        "forward_packets": flow.forward_packets,
        "reverse_packets": flow.reverse_packets,
    }


class IpAnonymizer:
    def __init__(self):
        self._labels = {}

    def label(self, value):
        if value not in self._labels:
            self._labels[value] = "host-%d" % (len(self._labels) + 1)
        return self._labels[value]


def format_endpoint(host, port, anonymizer=None):
    label = anonymizer.label(host) if anonymizer else host
    return "%s:%s" % (label, port) if port else label


def export_capture_rows(output_path, rows):
    if not output_path or not rows:
        return

    path = Path(output_path)
    if not path.is_absolute():
        path = ROOT / path
    path.parent.mkdir(parents=True, exist_ok=True)

    write_header = not path.exists() or path.stat().st_size == 0
    with path.open("a", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        if write_header:
            writer.writeheader()
        writer.writerows(rows)
    print("Exported %d flow snapshot rows to %s" % (len(rows), output_path))


def run_capture(
    model_name,
    interface=None,
    interval=5,
    timeout=0,
    max_flows=20,
    anonymize=False,
    summary=False,
    show_packets=0,
    output=None,
):
    IP, TCP, UDP, ICMP, _, sniff = import_scapy()
    model = load_model(model_name)
    layers = (IP, TCP, UDP, ICMP)
    anonymizer = IpAnonymizer() if anonymize else None
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
        event = update_flow_from_packet(packet, layers)
        if event:
            event["packet_number"] = packet_count
            packet_events.append(event)
            ip_packet_count += 1
        now = time.monotonic()
        if now >= next_print:
            print_capture_table(model, max_flows, packet_count, ip_packet_count, anonymizer, summary, show_packets, output)
            next_print = now + interval

    try:
        while True:
            if timeout > 0 and time.monotonic() - started >= timeout:
                break
            sniff(iface=interface, prn=handle_packet, store=False, timeout=1)
            now = time.monotonic()
            if now >= next_print:
                print_capture_table(model, max_flows, packet_count, ip_packet_count, anonymizer, summary, show_packets, output)
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

    print_capture_table(model, max_flows, packet_count, ip_packet_count, anonymizer, summary, show_packets, output)
    print("Stopped capture.")


def print_recent_packets(max_packets, anonymizer=None):
    if max_packets <= 0:
        return

    if not packet_events:
        print("No recent IP packet events.")
        return

    table = PrettyTable()
    table.field_names = ["Packet", "Flow ID", "Direction", "Proto", "Source", "Destination", "Bytes"]
    for event in list(packet_events)[-max_packets:]:
        table.add_row(
            [
                event["packet_number"],
                event["flow_id"],
                event["direction"],
                event["protocol"],
                format_endpoint(event["source"], event["source_port"], anonymizer),
                format_endpoint(event["destination"], event["destination_port"], anonymizer),
                event["bytes"],
            ]
        )
    print("Recent Packet Events")
    print(table)


def print_capture_table(
    model,
    max_flows,
    packet_count=None,
    ip_packet_count=None,
    anonymizer=None,
    summary=False,
    show_packets=0,
    output=None,
):
    if not flows:
        if packet_count is None:
            print("No IP flows captured yet.")
        else:
            print(f"No IP flows captured yet. Raw packets: {packet_count}, IP packets: {ip_packet_count}.")
        print_recent_packets(show_packets, anonymizer)
        return

    curr_time = time.time()
    for flow in flows.values():
        flow.refreshmetrics(curr_time)

    table = PrettyTable()
    table.field_names = [
        "#",
        "Flow ID",
        "Flow",
        "Source",
        "Destination",
        "Predicted",
        "Status",
        "Fwd Delta",
        "Rev Delta",
        "Fwd Pkts",
        "Rev Pkts",
        "Fwd Bytes",
        "Rev Bytes",
        "Age(s)",
    ]

    recent_flows = sorted(flows.items(), key=lambda item: item[1].last_seen_time)[-max_flows:]
    predictions = []
    export_rows = []
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    for index, (key, flow) in enumerate(recent_flows, start=1):
        active = bool(flow.forward_delta_packets or flow.reverse_delta_packets)
        if active:
            label = predict_label(model, flow.features())
            flow.last_prediction = label
        else:
            label = flow.last_prediction or "idle"
        predictions.append(label)
        source = format_endpoint(flow.ethsrc, flow.source_port, anonymizer)
        destination = format_endpoint(flow.ethdst, flow.destination_port, anonymizer)
        status = "active" if active else "idle"
        duration = round(flow.duration(curr_time), 2)
        table.add_row(
            [
                index,
                flow.flow_id,
                key[0],
                source,
                destination,
                label,
                status,
                flow.forward_delta_packets,
                flow.reverse_delta_packets,
                flow.forward_packets,
                flow.reverse_packets,
                flow.forward_bytes,
                flow.reverse_bytes,
                duration,
            ]
        )
        export_rows.append(
            {
                "timestamp": timestamp,
                "flow_id": flow.flow_id,
                "protocol": key[0],
                "source": source,
                "destination": destination,
                "predicted": label,
                "status": status,
                "forward_delta_packets": flow.forward_delta_packets,
                "reverse_delta_packets": flow.reverse_delta_packets,
                "forward_packets": flow.forward_packets,
                "reverse_packets": flow.reverse_packets,
                "forward_bytes": flow.forward_bytes,
                "reverse_bytes": flow.reverse_bytes,
                "duration_seconds": duration,
            }
        )
    print(table)
    if summary:
        summary_table = PrettyTable()
        summary_table.field_names = ["Predicted", "Shown Flows"]
        for label, count in sorted(Counter(predictions).items()):
            summary_table.add_row([label, count])
        print(summary_table)
    print_recent_packets(show_packets, anonymizer)
    export_capture_rows(output, export_rows)


def build_parser():
    parser = argparse.ArgumentParser(description="Windows network traffic classifier")
    subparsers = parser.add_subparsers(dest="command")

    demo_parser = subparsers.add_parser("demo", help="run model predictions on existing dataset rows")
    demo_parser.add_argument("model", choices=sorted(MODEL_FILES), nargs="?", default="gaussiannb")
    demo_parser.add_argument("--limit", type=int, default=20, help="number of dataset rows to show")

    subparsers.add_parser("validate-data", help="check datasets and saved model/data consistency")

    evaluate_parser = subparsers.add_parser("evaluate", help="run a proper train/test evaluation on the datasets")
    evaluate_parser.add_argument("model", choices=sorted(EVALUATION_MODEL_NAMES), nargs="?", default="randomforest")
    evaluate_parser.add_argument("--test-size", type=float, default=0.3, help="fraction of data to reserve for testing")
    evaluate_parser.add_argument("--random-state", type=int, default=101, help="random seed for reproducible splitting")
    evaluate_parser.add_argument("--drop-zero-rows", action="store_true", help="ignore rows where all model features are zero")

    capture_parser = subparsers.add_parser("capture", help="capture live Windows packets and classify flows")
    capture_parser.add_argument("model", choices=sorted(MODEL_FILES), nargs="?", default="randomforest")
    capture_parser.add_argument("--iface", help="capture interface name; omit to use Scapy default")
    capture_parser.add_argument("--interval", type=int, default=5, help="seconds between printed tables")
    capture_parser.add_argument("--timeout", type=int, default=0, help="seconds to capture; 0 means run until Ctrl+C")
    capture_parser.add_argument("--max-flows", type=int, default=20, help="maximum flows to show each table")
    capture_parser.add_argument("--anonymize", action="store_true", help="replace IP addresses with host labels in output")
    capture_parser.add_argument("--summary", action="store_true", help="show a prediction summary after each capture table")
    capture_parser.add_argument("--show-packets", type=int, default=0, help="show this many recent packet events after each table")
    capture_parser.add_argument("--output", help="append flow snapshot rows to a CSV file")

    subparsers.add_parser("interfaces", help="list Windows packet capture interfaces")

    for model_name in sorted(MODEL_FILES):
        model_parser = subparsers.add_parser(model_name, help=f"capture live Windows traffic with {model_name}")
        model_parser.add_argument("--iface", help="capture interface name; omit to use Scapy default")
        model_parser.add_argument("--interval", type=int, default=5, help="seconds between printed tables")
        model_parser.add_argument("--timeout", type=int, default=0, help="seconds to capture; 0 means run until Ctrl+C")
        model_parser.add_argument("--max-flows", type=int, default=20, help="maximum flows to show each table")
        model_parser.add_argument("--anonymize", action="store_true", help="replace IP addresses with host labels in output")
        model_parser.add_argument("--summary", action="store_true", help="show a prediction summary after each capture table")
        model_parser.add_argument("--show-packets", type=int, default=0, help="show this many recent packet events after each table")
        model_parser.add_argument("--output", help="append flow snapshot rows to a CSV file")

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
    if args.command == "validate-data":
        run_validate_data()
        return 0
    if args.command == "evaluate":
        run_evaluate(args.model, args.test_size, args.random_state, args.drop_zero_rows)
        return 0
    if args.command == "interfaces":
        list_interfaces()
        return 0
    if args.command == "capture":
        run_capture(
            args.model,
            args.iface,
            args.interval,
            args.timeout,
            args.max_flows,
            args.anonymize,
            args.summary,
            args.show_packets,
            args.output,
        )
        return 0
    if args.command in MODEL_FILES:
        run_capture(
            args.command,
            args.iface,
            args.interval,
            args.timeout,
            args.max_flows,
            args.anonymize,
            args.summary,
            args.show_packets,
            args.output,
        )
        return 0

    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
