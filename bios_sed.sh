#!/usr/bin/env bash
# ~/work/bios_sed.sh
# usage: bios_sed.sh <auto|xml|txt> <file>
set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "Usage: $0 <auto|xml|txt> <file>" >&2
  exit 2
fi

type_in="$1"
file="$2"

if [[ ! -f "$file" ]]; then
  echo "[bios_sed.sh][ERROR] File not found: $file" >&2
  exit 3
fi

# auto-detect format
type="$type_in"
if [[ "$type_in" == "auto" ]]; then
  if grep -q '<Setting' "$file"; then
    type="xml"
  else
    type="txt"
  fi
fi

echo "[bios_sed.sh] type=$type file=$file"

if [[ "$type" == "xml" ]]; then
  echo "--- BEFORE (matches) ---"
  grep -niE '<Setting name="CSM[[:space:]]*Support"|<Setting name="[^"]*[Bb]oot[[:space:]]*[Mm]ode[[:space:]]*[Ss]elect"' "$file" || true
  echo "------------------------"

  # Always enable CSM Support
  sed -i -E '/<Setting name="CSM[[:space:]]*Support"/ s/selectedOption="[^"]*"/selectedOption="Enabled"/' "$file"

  # Extract Boot mode block
  boot_block="$(awk 'BEGIN{IGNORECASE=1}
    /<Setting name=".*Boot[[:space:]]*mode[[:space:]]*select"/{flag=1}
    flag{print}
    flag && /<\/Setting>/{exit}' "$file")"

  if [[ -z "$boot_block" ]]; then
    echo "[bios_sed.sh] Boot mode block not found → leaving Boot mode unchanged."
  else
    # Determine the exact Legacy spelling (Legacy / LEGACY / legacy)
    legacy_variant="$(echo "$boot_block" | grep -oE '>([[:space:]]*)([Ll][Ee][Gg][Aa][Cc][Yy])<')"
    legacy_variant="$(echo "$legacy_variant" | sed -E 's/[><[:space:]]//g' | head -1)"

    if [[ -n "$legacy_variant" ]]; then
      echo "[bios_sed.sh] Legacy option found as '$legacy_variant' → setting Boot mode to $legacy_variant."
      sed -i -E \
        "/<Setting name=\"[^\"]*[Bb]oot[[:space:]]*[Mm]ode[[:space:]]*[Ss]elect\"/ s/selectedOption=\"[^\"]*\"/selectedOption=\"${legacy_variant//\//\\/}\"/" \
        "$file"
    else
      echo "[bios_sed.sh] Legacy option NOT offered → leaving Boot mode unchanged."
    fi
  fi

  rc=$?
  echo "__SED_RC=$rc"
  echo "--- AFTER (matches) ----"
  grep -niE '<Setting name="CSM[[:space:]]*Support"|<Setting name="[^"]*[Bb]oot[[:space:]]*[Mm]ode[[:space:]]*[Ss]elect"' "$file" || true
  echo "------------------------"
  exit $rc


elif [[ "$type" == "txt" ]]; then
  echo "--- BEFORE (TXT) ---"
  grep -niE '^[[:space:]]*(CSM[[:space:]]*Support|Boot[[:space:]]*Mode[[:space:]]*Select)[[:space:]]*=' "$file" || true
  echo "--------------------"

  # TXT rules:
  # - Force Boot Mode Select to 00 (Legacy) regardless of current value (hex or text), preserve comments/trailing text
  # - Force CSM Support to Enabled (text) and 01 (numeric), preserving trailing text
  sed -i -E \
    -e 's/^([[:space:]]*Boot[[:space:]]*Mode[[:space:]]*Select[[:space:]]*=[[:space:]]*)[^[:space:]]+/\100/I' \
    -e 's/^([[:space:]]*CSM[[:space:]]*Support[[:space:]]*=[[:space:]]*)[0-9A-Fa-f]{2}/\101/I' \
    "$file"

  rc=$?
  echo "__SED_RC=$rc"
  echo "--- AFTER (TXT) ----"
  grep -niE '^[[:space:]]*(CSM[[:space:]]*Support|Boot[[:space:]]*Mode[[:space:]]*Select)[[:space:]]*=' "$file" || true
  echo "--------------------"
  exit $rc

else
  echo "[bios_sed.sh][ERROR] Unknown type: $type" >&2
  exit 4
fi


