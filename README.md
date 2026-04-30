# Traffic Classifier SDN

This project classifies SDN network traffic such as DNS, Telnet, Ping, Voice, Game, and Quake traffic.

It uses:

- Mininet for the network topology
- Open vSwitch for SDN switching
- Ryu as the controller
- D-ITG for traffic generation
- Machine learning models for traffic classification

## Project Folders

- `traffic_classifier.py` - reads Ryu flow stats and predicts the traffic type
- `simple_monitor_13.py` - Ryu app that prints OpenFlow flow statistics
- `datasets/` - training traffic datasets
- `models/` - trained ML models and notebooks
- `D-IGT_scripts/` - D-ITG traffic generation scripts
- `setup_project.py` - checks the project setup, folders, datasets, models, and dependencies

## Local Setup Check

From the project folder:

```bash
python -m venv .venv
```

On Windows PowerShell, activate the environment with:

```powershell
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python setup_project.py
```

On Linux/macOS, activate it with:

```bash
source .venv/bin/activate
pip install -r requirements.txt
python setup_project.py
```

## SDN Tools

Install these in a Linux VM or Linux machine:

- D-ITG: https://github.com/jbucar/ditg
- Mininet: http://mininet.org/download/
- Open vSwitch: https://www.openvswitch.org/download/
- Ryu: `pip install -r requirements-sdn.txt`

## Run Mininet

```bash
sudo mn --topo single,3 --mac --switch ovsk --controller remote
```

## Run Real-Time Classification

In another terminal:

```bash
sudo python3 traffic_classifier.py gaussiannb
```

Available model commands:

```text
logistic
kmeans
svm
knearest
kneighbors
Randomforest
randomforest
gaussiannb
```

## Collect Training Data

Example:

```bash
sudo python3 traffic_classifier.py train dns
```

The script collects flow statistics for 15 minutes and writes a new training CSV file.
