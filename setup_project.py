#!/usr/bin/env python3
"""Setup and health check helper for the SDN traffic-classifier project."""

from __future__ import annotations

import argparse
import ast
import csv
import importlib
import importlib.metadata
import pickle
import platform
import sys
import warnings
import zipfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


ROOT = Path(__file__).resolve().parent

REQUIRED_DIRS = ("datasets", "models", "D-IGT_scripts")
REQUIRED_FILES = ("README.md", "traffic_classifier.py", "simple_monitor_13.py")

EXPECTED_DATASET_HEADERS = [
    "Forward Packets",
    "Forward Bytes",
    "Delta Forward Packets",
    "Delta Forward Bytes",
    "Forward Instantaneous Packets per Second",
    "Forward Average Packets per second",
    "Forward Instantaneous Bytes per Second",
    "Forward Average Bytes per second",
    "Reverse Packets",
    "Reverse Bytes",
    "Delta Reverse Packets",
    "Delta Reverse Bytes",
    "DeltaReverse Instantaneous Packets per Second",
    "Reverse Average Packets per second",
    "Reverse Instantaneous Bytes per Second",
    "Reverse Average Bytes per second",
    "Traffic Type",
]

EXPECTED_MODELS = (
    "LogisticRegression",
    "KMeans_Clustering",
    "KNeighbors",
    "RandomForestClassifier",
    "SVC",
    "GaussianNB",
)

EXPECTED_DITG_SCRIPTS = (
    "all_script_file",
    "game_script_file",
    "quake_script_file",
    "telnet_script_file",
    "voice_script_file",
)

DEPENDENCIES = {
    "numpy": "numpy",
    "prettytable": "prettytable",
    "sklearn": "scikit-learn",
    "pandas": "pandas",
    "scipy": "scipy",
    "matplotlib": "matplotlib",
    "seaborn": "seaborn",
    "ryu": "ryu",
}


@dataclass
class CheckState:
    ok: int = 0
    warn: int = 0
    error: int = 0

    def add(self, level: str, message: str) -> None:
        if level == "OK":
            self.ok += 1
        elif level == "WARN":
            self.warn += 1
        elif level == "ERROR":
            self.error += 1
        print(f"[{level}] {message}")


def print_section(title: str) -> None:
    print(f"\n== {title} ==")


def package_version(distribution_name: str) -> str | None:
    try:
        return importlib.metadata.version(distribution_name)
    except importlib.metadata.PackageNotFoundError:
        return None


def detect_delimiter(header_line: str) -> str:
    if "\t" in header_line:
        return "\t"
    return ","


def iter_dataset_files() -> Iterable[Path]:
    return sorted((ROOT / "datasets").glob("*.csv"))


def check_environment(state: CheckState) -> None:
    print_section("Environment")
    state.add("OK", f"Python {platform.python_version()} on {platform.system()}")
    if platform.system().lower() == "windows":
        state.add(
            "WARN",
            "Mininet, Open vSwitch, and sudo Ryu commands normally need Linux or a Linux VM.",
        )

    for module_name, dist_name in DEPENDENCIES.items():
        version = package_version(dist_name)
        if version:
            state.add("OK", f"{dist_name} installed ({version})")
            continue
        spec = importlib.util.find_spec(module_name)
        if spec is not None:
            state.add("OK", f"{module_name} importable")
        else:
            state.add("WARN", f"{dist_name} is missing")


def check_project_files(state: CheckState) -> None:
    print_section("Project Files")
    for dirname in REQUIRED_DIRS:
        path = ROOT / dirname
        if path.is_dir():
            state.add("OK", f"folder exists: {dirname}")
        else:
            state.add("ERROR", f"missing folder: {dirname}")

    for filename in REQUIRED_FILES:
        path = ROOT / filename
        if path.is_file():
            try:
                if path.suffix == ".py":
                    ast.parse(path.read_text(encoding="utf-8"))
                state.add("OK", f"file exists and parses: {filename}")
            except SyntaxError as exc:
                state.add("ERROR", f"syntax error in {filename}: {exc}")
        else:
            state.add("ERROR", f"missing file: {filename}")


def check_datasets(state: CheckState) -> None:
    print_section("Datasets")
    dataset_files = list(iter_dataset_files())
    if not dataset_files:
        state.add("ERROR", "no CSV files found in datasets/")
        return

    total_rows = 0
    total_bad_rows = 0
    delimiters = Counter()
    label_counts: Counter[str] = Counter()

    for path in dataset_files:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        if not lines:
            state.add("ERROR", f"{path.name} is empty")
            continue

        delimiter = detect_delimiter(lines[0])
        delimiters["tab" if delimiter == "\t" else "comma"] += 1
        row_count = 0
        bad_rows = 0
        file_labels: Counter[str] = Counter()

        with path.open(newline="", encoding="utf-8", errors="replace") as handle:
            reader = csv.reader(handle, delimiter=delimiter)
            header = next(reader)
            if header != EXPECTED_DATASET_HEADERS:
                state.add("WARN", f"{path.name} has a different header or delimiter format")

            for row_number, row in enumerate(reader, start=2):
                if len(row) != len(EXPECTED_DATASET_HEADERS):
                    bad_rows += 1
                    continue
                try:
                    for value in row[:-1]:
                        float(value)
                except ValueError:
                    bad_rows += 1
                    continue
                row_count += 1
                if row[-1]:
                    file_labels[row[-1]] += 1

        total_rows += row_count
        total_bad_rows += bad_rows
        label_counts.update(file_labels)

        level = "OK" if bad_rows == 0 else "WARN"
        state.add(
            level,
            f"{path.name}: {row_count} valid rows, {bad_rows} bad rows, labels={dict(file_labels)}",
        )

    if len(delimiters) > 1:
        state.add("WARN", f"mixed CSV delimiters found: {dict(delimiters)}")
    else:
        state.add("OK", f"CSV delimiter format is consistent: {dict(delimiters)}")

    state.add("OK", f"dataset total: {total_rows} valid rows, {total_bad_rows} bad rows")
    state.add("OK", f"traffic labels found: {dict(sorted(label_counts.items()))}")

    expected_labels = {"dns", "game", "ping", "telnet", "voice"}
    missing = expected_labels - set(label_counts)
    if missing:
        state.add("WARN", f"missing expected labels: {sorted(missing)}")


def check_ditg_scripts(state: CheckState) -> None:
    print_section("D-ITG Scripts")
    scripts_dir = ROOT / "D-IGT_scripts"
    for filename in EXPECTED_DITG_SCRIPTS:
        path = scripts_dir / filename
        if not path.is_file():
            state.add("ERROR", f"missing script: {filename}")
            continue
        content = path.read_text(encoding="utf-8", errors="replace").strip()
        if content:
            state.add("OK", f"{filename}: {content}")
        else:
            state.add("WARN", f"{filename} is empty")


def check_models(state: CheckState, load_models: bool) -> None:
    print_section("Models")
    models_dir = ROOT / "models"

    for filename in EXPECTED_MODELS:
        path = models_dir / filename
        if path.is_file():
            state.add("OK", f"model file exists: {filename}")
        else:
            state.add("ERROR", f"missing model file: {filename}")

    notebooks = models_dir / "notebooks.zip"
    if notebooks.is_file():
        try:
            with zipfile.ZipFile(notebooks) as archive:
                notebook_count = sum(
                    name.endswith(".ipynb") and not name.startswith("__MACOSX")
                    for name in archive.namelist()
                )
            state.add("OK", f"notebooks.zip exists with {notebook_count} notebooks")
        except zipfile.BadZipFile:
            state.add("ERROR", "models/notebooks.zip is not a valid zip file")
    else:
        state.add("WARN", "models/notebooks.zip is missing")

    if not load_models:
        state.add("WARN", "model loading skipped")
        return

    for filename in EXPECTED_MODELS:
        path = models_dir / filename
        if not path.is_file():
            continue
        try:
            with warnings.catch_warnings(record=True) as caught_warnings:
                warnings.simplefilter("always")
                with path.open("rb") as handle:
                    model = pickle.load(handle)
            model_type = f"{type(model).__module__}.{type(model).__name__}"
            n_features = getattr(model, "n_features_in_", "unknown")
            classes = getattr(model, "classes_", None)
            if classes is not None:
                class_text = ", classes=" + ",".join(str(item) for item in classes)
            else:
                class_text = ""
            state.add("OK", f"{filename} loads as {model_type}, features={n_features}{class_text}")
            for warning in caught_warnings[:1]:
                state.add("WARN", f"{filename} load warning: {warning.category.__name__}: {warning.message}")
        except Exception as exc:
            state.add("WARN", f"{filename} could not be loaded: {type(exc).__name__}: {exc}")


def check_known_code_issues(state: CheckState) -> None:
    print_section("Known Code Checks")
    classifier = ROOT / "traffic_classifier.py"
    if not classifier.is_file():
        return

    source = classifier.read_text(encoding="utf-8", errors="replace")
    if "'knearest': 'models/KNeighbors'" in source and "'kneighbors': 'models/KNeighbors'" in source:
        state.add("OK", "KNN command supports both knearest and kneighbors")
    elif "knearest" in source and "kneighbors" in source:
        state.add("WARN", "KNN command names are inconsistent: knearest vs kneighbors")
    else:
        state.add("OK", "KNN command naming looks consistent")

    if "hash(''.join" in source:
        state.add("WARN", "flow IDs use Python hash(); a stable tuple key is safer")
    else:
        state.add("OK", "flow IDs do not use Python hash()")

    readme = ROOT / "README.md"
    if readme.is_file() and "traffic_classifier_python3.py" in readme.read_text(encoding="utf-8", errors="replace"):
        state.add("WARN", "README references missing file traffic_classifier_python3.py")
    else:
        state.add("OK", "README run command does not reference the old missing script")


def main() -> int:
    parser = argparse.ArgumentParser(description="Check project setup, datasets, models, and SDN files.")
    parser.add_argument(
        "--skip-model-load",
        action="store_true",
        help="Only check model files exist; do not unpickle them.",
    )
    args = parser.parse_args()

    state = CheckState()
    print("Traffic Classifier SDN setup check")
    print(f"Project root: {ROOT}")

    check_environment(state)
    check_project_files(state)
    check_datasets(state)
    check_ditg_scripts(state)
    check_models(state, load_models=not args.skip_model_load)
    check_known_code_issues(state)

    print_section("Summary")
    print(f"OK: {state.ok} | WARN: {state.warn} | ERROR: {state.error}")
    if state.error:
        print("Result: fix ERROR items first.")
        return 1
    if state.warn:
        print("Result: setup is usable, but WARN items should be reviewed.")
        return 0
    print("Result: setup looks good.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
