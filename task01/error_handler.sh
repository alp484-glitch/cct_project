#!/usr/bin/env bash
set -euo pipefail

# -----------------------------
# 帮助与参数解析
# -----------------------------
print_usage() {
  cat <<'USAGE'
用法:
  ./log_guard.sh -i <logfile>
  cat <logfile> | ./log_guard.sh

可选参数:
  -i FILE    指定日志文件(默认从STDIN读取)
  -h         显示帮助
USAGE
}

INPUT_FILE=""
while getopts ":i:h" opt; do
  case "$opt" in
    i) INPUT_FILE="$OPTARG" ;;
    h) print_usage; exit 0 ;;
    *) print_usage; exit 1 ;;
  esac
done

# 若未指定文件，则从 STDIN 读取
if [[ -n "${INPUT_FILE}" ]]; then
  if [[ ! -f "${INPUT_FILE}" ]]; then
    echo "找不到输入文件: ${INPUT_FILE}" >&2
    exit 1
  fi
  INPUT_SOURCE="${INPUT_FILE}"
else
  # 如果没有管道输入且没给 -i，提示用法
  if [ -t 0 ]; then
    print_usage; exit 1
  fi
 # INPUT_SOURCE="/dev/stdin"
  TMP="$(mktemp)"
  cat > "$TMP"        # 从stdin读一次，写入临时文件
  INPUT_SOURCE="$TMP"
fi


OUTFILE="error_report.log"
PATTERN='error|fail|unauthorized|denied'
echo "=== Error Log Report ===" > $OUTFILE
echo "Generated: $(date)" >> $OUTFILE
echo "" >> $OUTFILE


grep -Ei $PATTERN $INPUT_SOURCE | sort | uniq -c >> $OUTFILE
echo "" >> $OUTFILE
echo "Summary:" >> $OUTFILE
grep -Ei $PATTERN $INPUT_SOURCE | wc -l >> $OUTFILE
echo "Report completed."
