#!/bin/bash

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

DB_FILE="$SCRIPT_DIR/kangaroot.db"

# If the database file doesn't exist, register modules first
if [ ! -f "$DB_FILE" ]; then
    echo "kangaroot.db not found. Running module registration..."
    uv run main.py --register-modules
fi

# Run the main script
uv run main.py
