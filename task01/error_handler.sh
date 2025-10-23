#!/usr/bin/env bash
# error_handler.sh
# Usage: ./error_handler.sh -i logfile.log
#
# Purpose: Extract and summarize error-like entries from a log file
# and produce a timestamped report. Can read from a file or STDIN.

set -euo pipefail

# -----------------------------
# Help and argument parsing
# -----------------------------
usage() {
  cat <<EOF
Usage: $0 [-i input_file]
  -i FILE   Specify the input log file (default: read from STDIN)
  -h        Show this help
EOF
}

INPUT=""
OUTFILE="error_report.log"
PATTERN='error|fail|unauthorized|denied'

while getopts ":i:h" opt; do
  case ${opt} in
    i ) INPUT="$OPTARG" ;;
    h ) usage; exit 0 ;;
    \? ) echo "Invalid option: -$OPTARG" 1>&2; usage; exit 1 ;;
  esac
done

# If no input file specified, check for piped input
if [[ -z "$INPUT" ]]; then
  # If there's no stdin (no pipe), print usage
  if [[ -t 0 ]]; then
    echo "No input file and no piped stdin. Use -i or pipe input." >&2
    usage
    exit 1
  else
    # Read stdin into a temporary file so we can scan it multiple times
    TMP=$(mktemp)
    cat - > "$TMP"
    INPUT="$TMP"
  fi
fi

# Generate report with timestamp
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
OUTFILE="error_report_${TIMESTAMP}.log"

{
  echo "=== Error Log Report ==="
  echo "Generated: $(date -u)"
  echo ""
  echo "Matches:"
  # Perform case-insensitive grep for configured patterns, then aggregate
  grep -Ein "$PATTERN" "$INPUT" | sort | uniq -c || true
  echo ""
  echo "Summary:"
  grep -Eic "$PATTERN" "$INPUT" || true
} > "$OUTFILE"

echo "Report written to $OUTFILE"

# Cleanup temporary file if created
if [[ -n "${TMP:-}" && -f "$TMP" ]]; then
  rm -f "$TMP"
fi
