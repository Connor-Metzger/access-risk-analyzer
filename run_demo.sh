#!/usr/bin/env bash
# Run the full pipeline end to end with simulated manager responses.
set -euo pipefail
cd "$(dirname "$0")"
python src/generate_data.py
python src/analyzer.py
python src/generate_packets.py
python src/simulate_decisions.py      # demo only: stands in for real managers
python src/process_decisions.py
python src/create_tickets.py          # dry run; add --live after configuring .env
echo
echo "Dashboard: streamlit run src/dashboard.py   (binds to 127.0.0.1 only)"
