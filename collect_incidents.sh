#!/usr/bin/env bash
set -euo pipefail

ASSIGNED_TO=""
ASSIGNMENT_GROUP="EC Optimization Services"
STATES=("1" "2" "3")
SYCOLS="number,state,cmdb_ci,short_description,assignment_group,assigned_to"
SN_CLI="/nfs/sc/disks/cbitools/ServiceNowCloud/sn_cli.py"
DEBUG=0

usage() {
  cat <<EOF
Usage: $(basename "$0") [-a ASSIGNED_TO] [-g ASSIGNMENT_GROUP] [-s "space-separated states"] [-d]
  -a  Optional value for -at (assigned_to), e.g. 'jdcruzlo'
  -g  Assignment group (default: "EC Optimization Services")
  -s  States to query, space-separated (default: "1 2 3")
  -d  Debug: print the commands being executed (stderr)
Examples:
  $(basename "$0")
  $(basename "$0") -a jdcruzlo
  $(basename "$0") -s "1 3"
EOF
}

while getopts ":a:g:s:dh" opt; do
  case "$opt" in
    a) ASSIGNED_TO="$OPTARG" ;;
    g) ASSIGNMENT_GROUP="$OPTARG" ;;
    s) read -r -a STATES <<<"$OPTARG" ;;
    d) DEBUG=1 ;;
    h) usage; exit 0 ;;
    \?) echo "Unknown option: -$OPTARG" >&2; usage; exit 1 ;;
    :)  echo "Option -$OPTARG requires an argument." >&2; usage; exit 1 ;;
  esac
done

# Basic check
if [[ ! -x "$SN_CLI" && ! -f "$SN_CLI" ]]; then
  echo "Error: sn_cli.py not found at $SN_CLI" >&2
  exit 2
fi

# Run the tool for each state, merge stderr->stdout, feed to awk
{
  for st in "${STATES[@]}"; do
    CMD=( "$SN_CLI" -getall -ag "$ASSIGNMENT_GROUP" -fo json -st "$st" -sysp "$SYCOLS" --sysparamLimit 100 )
    if [[ -n "$ASSIGNED_TO" ]]; then
      CMD+=( -at "$ASSIGNED_TO" )
    fi
    if (( DEBUG )); then
      printf '[DEBUG] ' >&2; printf '%q ' "${CMD[@]}" >&2; printf '\n' >&2
    fi
    "${CMD[@]}" 2>&1 || true
  done
} | awk '
BEGIN {
  first = 1;
  print "{";
}
# Only process lines that look like dicts
/^\{.*\}$/ {
  line = $0;

  # Extract fields using regex matches against the Python-like single-quoted dict
  # Each field is optional; missing ones become empty
  state = cmdbCi = shortDescription = assignedTo = assignmentGroup = number = "";

  if (match(line, /'\''state'\'':[[:space:]]*'\''([^'\'']*)'\''/, m))               state = m[1];
  if (match(line, /'\''cmdbCi'\'':[[:space:]]*'\''([^'\'']*)'\''/, m))              cmdbCi = m[1];
  if (match(line, /'\''shortDescription'\'':[[:space:]]*'\''([^'\'']*)'\''/, m))    shortDescription = m[1];
  if (match(line, /'\''assignedTo'\'':[[:space:]]*'\''([^'\'']*)'\''/, m))          assignedTo = m[1];
  if (match(line, /'\''assignmentGroup'\'':[[:space:]]*'\''([^'\'']*)'\''/, m))     assignmentGroup = m[1];
  if (match(line, /'\''number'\'':[[:space:]]*'\''([^'\'']*)'\''/, m))              number = m[1];

  # Skip if there is no ticket number
  if (number == "") next;

  # JSON escape a field (escape backslashes and double quotes)
  gsub(/\\/, "\\\\", state);              gsub(/"/, "\\\"", state);
  gsub(/\\/, "\\\\", cmdbCi);             gsub(/"/, "\\\"", cmdbCi);
  gsub(/\\/, "\\\\", shortDescription);   gsub(/"/, "\\\"", shortDescription);
  gsub(/\\/, "\\\\", assignedTo);         gsub(/"/, "\\\"", assignedTo);
  gsub(/\\/, "\\\\", assignmentGroup);    gsub(/"/, "\\\"", assignmentGroup);
  gsub(/\\/, "\\\\", number);             gsub(/"/, "\\\"", number);

  # Print comma between entries
  if (!first) {
    print ",";
  }
  first = 0;

  # Emit the JSON entry keyed by ticket number
  printf "  \"%s\": {", number;
  printf "\"state\":\"%s\"", state;
  printf ",\"cmdbCi\":\"%s\"", cmdbCi;
  printf ",\"shortDescription\":\"%s\"", shortDescription;
  printf ",\"assignedTo\":\"%s\"", assignedTo;
  printf ",\"assignmentGroup\":\"%s\"", assignmentGroup;
  printf ",\"number\":\"%s\"", number;
  printf "}";
}
END {
  print first ? "{}" : "\n}";
}
'
