#!/bin/bash

DIR="${1:-.}"
OUTPUT_FILE="$HOME/zeinaguard_ai_context.txt"

if [ ! -d "$DIR" ]; then
    echo "Error: Directory '$DIR' not found!"
    exit 1
fi

echo "⏳ Extracting core logic from: $DIR"
echo "✂️  Filtering out logs, databases, lock files, Next.js builds, and UI boilerplate..."

{
    echo "========================================"
    echo "📂 PROJECT ARCHITECTURE"
    echo "========================================"
    
    find "$DIR" \
        -not -path '*/\.git/*' \
        -not -path '*/\.next/*' \
        -not -path '*/__pycache__/*' \
        -not -path '*/node_modules/*' \
        -not -path '*/\.venv/*' \
        -not -path '*/logs/*' \
        -not -path '*/instance/*' \
        -not -path '*/dist/*' \
        -not -path '*/build/*' \
        -print | sed -e 's;[^/]*/;|____;g;s;____|; |;g'

    echo -e "\n========================================"
    echo "📜 CORE FILE CONTENTS"
    echo "========================================"

    find "$DIR" -type f \
        -not -path '*/\.git/*' \
        -not -path '*/\.next/*' \
        -not -path '*/__pycache__/*' \
        -not -path '*/node_modules/*' \
        -not -path '*/\.venv/*' \
        -not -path '*/logs/*' \
        -not -path '*/instance/*' \
        -not -path '*/dist/*' \
        -not -path '*/build/*' \
        -not -path '*/sensor/data_logs/*' \
        -not -path '*/components/ui/*' \
        -not -name '*.db' \
        -not -name '*.pyc' \
        -not -name '*.csv' \
        -not -name '*.png' \
        -not -name '*.jpg' \
        -not -name '*.log' \
        -not -name '*.map' \
        -not -name '*.svg' \
        -not -name 'pnpm-lock.yaml' \
        -not -name 'package-lock.json' \
        -not -name 'oui_db.json' \
        -not -name 'trusted.json' | while read -r file; do

        if file "$file" | grep -qE 'text|empty'; then
            echo "$file:"
            cat "$file"
            echo -e "\n______\n"
        fi
    done
} > "$OUTPUT_FILE"

FILE_SIZE=$(du -h "$OUTPUT_FILE" | cut -f1)
echo "✅ Done! Project context saved to: $OUTPUT_FILE"
echo "📊 Final file size: $FILE_SIZE"