# ICS343 Traffic Classification Project

This project classifies network traffic with saved machine learning models.

It can run in two modes:

- **Dataset demo mode**: reads the CSV files in `datasets/` and shows model predictions.
- **Live Windows capture mode**: captures real packets from your Windows network interface using Scapy + Npcap, groups them into flows, and predicts the traffic class.

This Windows setup does **not** require Mininet, Open vSwitch, Ubuntu, or Ryu.

## Project Structure

```text
.
|-- traffic_classifier.py      Main program for demo and live capture
|-- requirements.txt           Python packages needed by the project
|-- datasets/                  Training CSV datasets
|-- models/                    Saved ML models and notebooks
|-- D-IGT_scripts/             Old traffic-generation scripts from the original SDN version
|-- simple_monitor_13.py       Old Ryu monitor from the original SDN version
`-- .gitignore                 Ignores venv/cache/generated files
```

For the normal Windows project, use `traffic_classifier.py`, `datasets/`, `models/`, and `requirements.txt`.

## What You Need To Install

Install these before running the project.

### 1. Python 3.9

Install Python 3.9 from the official Python website:

```text
https://www.python.org/downloads/windows/
```

Recommended direct version:

```text
https://www.python.org/downloads/release/python-3913/
```

During installation, check this option:

```text
Add Python to PATH
```

You can also install Python 3.9 from PowerShell using `winget`:

```powershell
winget install -e --id Python.Python.3.9
```

After installing, close PowerShell and open it again.

Check Python 3.9:

```powershell
py -3.9 --version
```

Expected result:

```text
Python 3.9.x
```

### 2. Npcap

Npcap is required for live packet capture on Windows.

Install it from the official website:

```text
https://npcap.com/#download
```

Download and run the **Npcap installer**. Do not use the GitHub source code for normal setup.

During Npcap installation:

- Keep **Install Npcap in WinPcap API-compatible Mode** checked.
- Leave **Support raw 802.11 traffic** unchecked unless you specifically need monitor mode.
- Leave **Restrict Npcap driver's access to Administrators only** unchecked unless your instructor or system policy requires it.

After installing Npcap, restart PowerShell. If capture does not work, open PowerShell as Administrator.

### 3. Git

Git is optional, but useful if you want to clone or share the project.

Install Git for Windows:

```text
https://git-scm.com/download/win
```

## Important: Do Not Share The Virtual Environment Folder

The project uses a virtual environment folder named:

```text
.venv39/
```

Do **not** upload or share this folder.

Reason:

- It is large.
- It contains machine-specific files.
- It may not work on another computer.
- It is already ignored by `.gitignore`.

The correct way to share the environment is:

```text
requirements.txt
```

Each person should create their own `.venv39` locally using the setup commands below.

## Full Windows PowerShell Setup

Open PowerShell and go to the project folder:

```powershell
cd C:\Path\To\ICS343-Project-Traffic-Classification
```

Replace `C:\Path\To\ICS343-Project-Traffic-Classification` with the real folder path on your computer.

Create a Python 3.9 virtual environment:

```powershell
py -3.9 -m venv .venv39
```

Activate it:

```powershell
.\.venv39\Scripts\Activate.ps1
```

After activation, your prompt should start with:

```text
(.venv39)
```

Upgrade basic install tools:

```powershell
python -m pip install --upgrade pip setuptools wheel
```

Install project packages:

```powershell
pip install -r requirements.txt
```

Check that packages are installed correctly:

```powershell
pip check
```

Expected result:

```text
No broken requirements found.
```

Check Python version:

```powershell
python --version
```

Expected result:

```text
Python 3.9.x
```

## If PowerShell Blocks Activation

If this command fails:

```powershell
.\.venv39\Scripts\Activate.ps1
```

Run:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

Then activate again:

```powershell
.\.venv39\Scripts\Activate.ps1
```

## Verify Npcap

Check that the Npcap service exists:

```powershell
sc.exe query npcap
```

Good result usually includes:

```text
STATE              : 4  RUNNING
```

If it is not running, restart Windows or reinstall Npcap from:

```text
https://npcap.com/#download
```

## List Capture Interfaces

Activate the virtual environment first:

```powershell
.\.venv39\Scripts\Activate.ps1
```

Then list available interfaces:

```powershell
python traffic_classifier.py interfaces
```

You should see names like:

```text
Wi-Fi
Ethernet
Loopback Adapter
```

Use the active internet interface. On this project setup, use `"Wi-Fi"` when the computer is connected to the internet through Wi-Fi.

Only use `"Ethernet"` if the computer is actually connected to the internet through a cable.

You can also check Windows adapters:

```powershell
Get-NetAdapter
```

## Run Dataset Demo

This mode does not capture live packets. It only tests the saved models using the CSV files in `datasets/`.

Recommended command:

```powershell
python traffic_classifier.py demo randomforest --limit 10
```

Other model examples:

```powershell
python traffic_classifier.py demo gaussiannb --limit 10
python traffic_classifier.py demo knearest --limit 10
python traffic_classifier.py demo svm --limit 10
python traffic_classifier.py demo logistic --limit 10
```

The output shows:

- Dataset name
- Actual class
- Predicted class
- Demo accuracy

## Validate The Dataset

Before reporting results, check that the datasets and saved models match:

```powershell
python traffic_classifier.py validate-data
```

This shows:

- row counts for each CSV file
- class balance
- missing or invalid rows
- duplicate feature rows
- saved model classes compared with dataset classes

Current expected notes:

- `ping_training_data.csv` has one invalid row at the end.
- The datasets currently contain `dns`, `game`, `ping`, `telnet`, and `voice`.
- Some saved models also know `quake`, but there is no `quake_training_data.csv` in the current `datasets/` folder.
- The saved `logistic` model does not know the `game` class, so it should not be the main recommended saved model.

## Run A Correct Train/Test Evaluation

Use `evaluate` when you want a better test than the dataset demo.

```powershell
python traffic_classifier.py evaluate randomforest --test-size 0.3
```

This trains a fresh model on 70% of the valid dataset rows and tests on the remaining 30%.

It shows:

- train row count
- test row count
- accuracy
- confusion matrix
- precision / recall / F1-score

Recommended evaluation:

```powershell
python traffic_classifier.py evaluate randomforest --test-size 0.3 --drop-zero-rows
```

`--drop-zero-rows` ignores rows where all model features are zero. This is useful because those startup rows can appear in multiple classes and confuse the model.

Other supervised models:

```powershell
python traffic_classifier.py evaluate knearest --test-size 0.3
python traffic_classifier.py evaluate gaussiannb --test-size 0.3
python traffic_classifier.py evaluate svm --test-size 0.3
python traffic_classifier.py evaluate logistic --test-size 0.3
```

## Run Live Windows Capture

First, open PowerShell. Administrator mode is recommended for packet capture.

Go to the project folder:

```powershell
cd C:\Path\To\ICS343-Project-Traffic-Classification
```

Activate the virtual environment:

```powershell
.\.venv39\Scripts\Activate.ps1
```

List interfaces:

```powershell
python traffic_classifier.py interfaces
```

Run capture on the internet interface, usually Wi-Fi:

```powershell
python traffic_classifier.py capture randomforest --iface "Wi-Fi"
```

You can also run the model name directly:

```powershell
python traffic_classifier.py randomforest --iface "Wi-Fi"
```

For safer output when sharing screenshots, anonymize IP addresses:

```powershell
python traffic_classifier.py capture randomforest --iface "Wi-Fi" --anonymize
```

For a clearer live demo, also show a prediction summary:

```powershell
python traffic_classifier.py capture randomforest --iface "Wi-Fi" --anonymize --summary
```

To show how packets are tracked into flows, print recent packet events too:

```powershell
python traffic_classifier.py capture randomforest --iface "Wi-Fi" --anonymize --summary --show-packets 10
```

To save flow snapshots for your report:

```powershell
python traffic_classifier.py capture randomforest --iface "Wi-Fi" --anonymize --summary --output reports\live_capture.csv
```

Stop live capture with:

```text
Ctrl+C
```

## Useful Capture Options

Print results every 3 seconds:

```powershell
python traffic_classifier.py capture randomforest --iface "Wi-Fi" --interval 3
```

Stop automatically after 30 seconds:

```powershell
python traffic_classifier.py capture randomforest --iface "Wi-Fi" --timeout 30
```

Show only 10 flows per table:

```powershell
python traffic_classifier.py capture randomforest --iface "Wi-Fi" --max-flows 10
```

Use all options together:

```powershell
python traffic_classifier.py capture randomforest --iface "Wi-Fi" --interval 3 --timeout 30 --max-flows 10 --anonymize --summary --show-packets 10 --output reports\live_capture.csv
```

## Generate Traffic For Testing

While capture is running, open another PowerShell window or use your browser.

Simple ping test:

```powershell
ping example.com
```

DNS lookup test:

```powershell
nslookup google.com
```

Browser test:

```text
Open websites like google.com, youtube.com, github.com, or your university portal.
```

The capture table should update when packets are seen.

## What The Live Output Means

Example output:

```text
+----+---------+------+--------------+-------------+-----------+--------+-----------+-----------+----------+----------+-----------+-----------+--------+
| #  | Flow ID | Flow |    Source    | Destination | Predicted | Status | Fwd Delta | Rev Delta | Fwd Pkts | Rev Pkts | Fwd Bytes | Rev Bytes | Age(s) |
+----+---------+------+--------------+-------------+-----------+--------+-----------+-----------+----------+----------+-----------+-----------+--------+
| 1  |    7    | tcp  | host-1:51544 |  host-2:443 |   quake   | active |     6     |     7     |    10    |    12    |    1200   |    1350   |  4.21  |
+----+---------+------+--------------+-------------+-----------+--------+-----------+-----------+----------+----------+-----------+-----------+--------+
```

The `host-1` and `host-2` values appear when `--anonymize` is used. They are placeholders, not real captured IP addresses.

Meaning:

- `Flow`: packet protocol, such as `tcp`, `udp`, or `icmp`.
- `Flow ID`: stable number assigned when the flow is first seen.
- `Source`: source host and port when a port exists.
- `Destination`: destination host and port when a port exists.
- `Predicted`: the class predicted by the ML model.
- `Status`: `active` means the flow had new packets in this print interval; `idle` means no new packets were seen.
- `Fwd Delta`: new forward packets seen during the latest print interval.
- `Rev Delta`: new reverse packets seen during the latest print interval.
- `Fwd Pkts`: total forward packets seen since this flow started.
- `Rev Pkts`: total reverse packets seen since this flow started.
- `Fwd Bytes`: total forward bytes seen since this flow started.
- `Rev Bytes`: total reverse bytes seen since this flow started.
- `Age(s)`: how long the flow has been tracked.

When `--show-packets 10` is used, the program also prints recent packet events:

```text
+--------+---------+-----------+-------+--------------+-------------+-------+
| Packet | Flow ID | Direction | Proto |    Source    | Destination | Bytes |
+--------+---------+-----------+-------+--------------+-------------+-------+
|   31   |    7    |  forward  |  tcp  | host-1:51544 |  host-2:443 |  128  |
+--------+---------+-----------+-------+--------------+-------------+-------+
```

This shows the path from individual packets to a tracked flow.

If you see your local IP, such as `10.x.x.x` or `192.168.x.x`, that is usually your computer or another device on the same network.

Important note: the predicted labels are based on the training datasets. The model only knows the classes it was trained on, such as:

```text
dns
game
ping
quake
telnet
voice
```

So if real Windows traffic is predicted as `quake` or `telnet`, it does not always mean you are actually using Quake or Telnet. It means the flow behavior looks similar to that training class.

## Available Models

You can use these model names:

```text
randomforest
gaussiannb
knearest
kneighbors
svm
logistic
kmeans
Randomforest
```

Recommended model:

```text
randomforest
```

Recommended demo:

```powershell
python traffic_classifier.py demo randomforest --limit 10
```

Recommended live capture:

```powershell
python traffic_classifier.py capture randomforest --iface "Wi-Fi"
```

## Troubleshooting

### `ModuleNotFoundError: No module named 'numpy'`

You are probably not inside the virtual environment, or packages are not installed.

Run:

```powershell
.\.venv39\Scripts\Activate.ps1
pip install -r requirements.txt
```

### `py -3.9` Does Not Work

Python 3.9 is not installed or the Python launcher cannot find it.

Install Python 3.9 from:

```text
https://www.python.org/downloads/windows/
```

Then reopen PowerShell and run:

```powershell
py -0p
```

This lists installed Python versions.

### No Packets Appear

Try these steps:

1. Install Npcap from `https://npcap.com/#download`.
2. Reopen PowerShell as Administrator.
3. Run `python traffic_classifier.py interfaces`.
4. Choose the active interface with `--iface`.
5. Generate traffic using `ping example.com` or open websites.

Example:

```powershell
python traffic_classifier.py capture randomforest --iface "Wi-Fi" --timeout 30
```

### Wrong Interface

List interfaces:

```powershell
python traffic_classifier.py interfaces
```

Then use the active internet interface. For this setup, use Wi-Fi:

```powershell
python traffic_classifier.py capture randomforest --iface "Wi-Fi"
```

Only use Ethernet if the internet connection is actually wired:

```powershell
python traffic_classifier.py capture randomforest --iface "Ethernet"
```

### Cannot Stop Capture

Press:

```text
Ctrl+C
```

If that is hard to stop, use a timeout:

```powershell
python traffic_classifier.py capture randomforest --iface "Wi-Fi" --timeout 10
```

### Ryu Or Mininet Errors

Ryu and Mininet are not needed for this Windows version.

The old SDN files are kept only for reference:

```text
D-IGT_scripts/
simple_monitor_13.py
```

For this project setup, use:

```text
traffic_classifier.py
requirements.txt
datasets/
models/
```

## Cleaning Old Local Folders

If you have an old virtual environment named `.venv`, remove it and keep `.venv39`:

```powershell
Remove-Item -Recurse -Force .venv
```

Do not remove `.venv39` if it is the environment you are using.

Do not commit these folders:

```text
.venv39/
.venv/
npcap/
__pycache__/
```

They are already ignored by `.gitignore`.

## Quick Start Commands

Use this after Python 3.9 and Npcap are installed.

```powershell
cd C:\Path\To\ICS343-Project-Traffic-Classification
py -3.9 -m venv .venv39
.\.venv39\Scripts\Activate.ps1
python -m pip install --upgrade pip setuptools wheel
pip install -r requirements.txt
pip check
python traffic_classifier.py demo randomforest --limit 10
python traffic_classifier.py validate-data
python traffic_classifier.py evaluate randomforest --test-size 0.3 --drop-zero-rows
python traffic_classifier.py interfaces
python traffic_classifier.py capture randomforest --iface "Wi-Fi" --timeout 30 --anonymize --summary --show-packets 10 --output reports\live_capture.csv
```

For another computer, do the same setup again. Do not copy `.venv39` from one machine to another.
