#!/usr/bin/env zsh
# snyk-harvest.zsh
#
# runs snyk test with some flagging
# writes a dated archive JSON and symlinks vulns.json > latest
# normalizes for the "vulnMatrix" components to ingest/display.
# snyk folks love us, is all I gotta say. the doc is incredible.
#
# base command w/ params:
#   snyk test . \
#     --json-file-output="<ARCHIVE_DIR>/<proj>_<date>.json" \
#     --show-vulnerable-paths=all \
#     --package-manager="npm" \
#     --print-deps
#
# USAGE
#   ./snyk-harvest.zsh                     # scan cwd, archive in ./snyk-reports/
#   ./snyk-harvest.zsh /path/to/project    # scan specific project root
#
# ENV VARS (set in ~/.zshenv — loads for cron/non-interactive shells)
#   SNYK_TOKEN          required  your Snyk API, .env file is better
#   SNYK_ARCHIVE_DIR    optional  where to keep dated JSON files
#                                 default: <project>/.snyk-reports/
#   SNYK_MATRIX_FILE    optional  path for the normalized vulns.json the
#                                 matrix loader reads. default: <project>/vulns.json
#   SNYK_KEEP_DAYS      optional  how many days of archives to retain (default: 30)
#
# EXIT CODES
#   0   clean — no vulns found
#   1   vulns found (snyk's normal non-zero; expected shit, not my rando script error)
#   2   hard failure — bad token, snyk/jq missing, no package.json, etc.
#
# NEEDS and WANTS
#   snyk  >= 1.1000   (npm i -g snyk or better, local to all build envs)
#   jq    >= 1.6      (apt install jq)

# be strict and catch unset vars and pipe fails
setopt pipefail nounset
# NOT setting errexit — snyk exits 1 on vulns found.
#
# config it up
#
# 

PROJECT_DIR="${1:-$(pwd)}"
PROJECT_NAME="${${PROJECT_DIR:t}//[^a-zA-Z0-9_-]/_}"   # basename, sano.
# I know folks who hate this format timestamp, ha ha.
TODAY=$(date +%Y-%m-%d)                                  # e.g. 2026-05-16
TIMESTAMP=$(date +%Y-%m-%d_%H%M)                         # e.g. 2026-05-16_1432
# have to have a hole to put things, a name for the thing and a lease on life.
ARCHIVE_DIR="${SNYK_ARCHIVE_DIR:-${PROJECT_DIR}/.snyk-reports}"
MATRIX_FILE="${SNYK_MATRIX_FILE:-${PROJECT_DIR}/vulns.json}"
KEEP_DAYS="${SNYK_KEEP_DAYS:-30}"

# dated raw output — matches snyk doc naming pattern
DATED_RAW="${ARCHIVE_DIR}/snykTest_${PROJECT_NAME}_${TIMESTAMP}.json"

# normalized output per run (sits alongside the raw file)
DATED_NORM="${ARCHIVE_DIR}/vulns_${PROJECT_NAME}_${TIMESTAMP}.json"

# sanity checks, run inside venv post actvenv

for cmd in snyk jq; do
  if ! command -v "$cmd" &>/dev/null; then
    print -u2 "ERROR: '$cmd' not found in PATH."
    print -u2 "  snyk: npm i -g snyk"
    print -u2 "  jq:   apt install jq"
    exit 2
  fi
done

if [[ ! -f "${PROJECT_DIR}/package.json" ]]; then
  print -u2 "ERROR: No package.json in '${PROJECT_DIR}'."
  print -u2 "  Pass your project root as the first argument."
  exit 2
fi

mkdir -p "$ARCHIVE_DIR"

# .gitignore the archive dir if we're inside a git repo — raw snyk JSON
# might (has for me) contain internal pathing
GITIGNORE="${PROJECT_DIR}/.gitignore"
if [[ -f "$GITIGNORE" ]] && ! grep -qF '.snyk-reports/' "$GITIGNORE"; then
  print '.snyk-reports/' >> "$GITIGNORE"
  print "→ Added .snyk-reports/ to .gitignore"
fi

# Run Snyk
# parameterized

print "→ Scanning ${PROJECT_DIR} ..."
print "  raw output → ${DATED_RAW}"
print ""

# snyk exits 1 when vulns found — reminder.
# using a || true to prevent pipefail from bailing, then check SNYK_EXIT.
snyk test "${PROJECT_DIR}" \
  --json-file-output="${DATED_RAW}" \
  --show-vulnerable-paths=all \
  --package-manager="npm" \
  --print-deps \
  ; SNYK_EXIT=$?

# 0 = clean, 1 = vulns found (both are fine), 2/3 = fail
if (( SNYK_EXIT >= 2 )); then
  print -u2 "ERROR: snyk failed us, Jim. It's a scanner, \
	  not a miracle worker (exit ${SNYK_EXIT})."
  print -u2 "  Jim, re-run with:  snyk test ${PROJECT_DIR} --debug \
	  to find the Klingon"
  exit 2
fi
# if needed:
# export SNYK_LOG_LEVEL=trace
# snyk test --debug

if [[ ! -s "$DATED_RAW" ]]; then
  print -u2 "ERROR: snyk didn't write to ${DATED_RAW}."
  print -u2 "  Check on that token validity:  snyk auth"
  exit 2
fi

# normalize snyk JSON > vuln matrix format via jq
#
# snyk emits a .vulnerabilities[] entry for EACH vuln *instance*,
# and the same package can appear multiple times, so:
#   1. group by packageName
#   2. within each group, keep the highest-severity entry (lowest rank #)
#   3. map a flat shape the matrix loader expects
#
# --show-vulnerable-paths=all adds a .from[] chain per vuln — capturing
# path depth as, `depth` so the tool can flag transitive hits.

print "→ normalizing to vuln matrix format ..."

jq --arg today "$TODAY" '
  (.vulnerabilities // []) |
  group_by(.packageName) |
  map(
    sort_by(
      .severity |
      if   . == "critical" then 0
      elif . == "high"     then 1
      elif . == "medium"   then 2
      elif . == "low"      then 3
      else 4 end
    ) | first |
    {
      pkg:      .packageName,
      current:  .version,
      patched:  (.fixedIn[0] // "—"),
      eco:      "npm",
      cve:      (
                  if (.identifiers.CVE // [] | length) > 0
                  then .identifiers.CVE[0]
                  else .id
                  end
                ),
      severity: .severity,
      status:   (
                  if .isUpgradable or .isPatchable then "pending"
                  elif (.fixedIn // [] | length) == 0 then "no-fix"
                  else "pending"
                  end
                ),
      # Dependency chain depth from --show-vulnerable-paths
      # .from = ["your-project", "direct-dep@ver", ..., "vuln-pkg@ver"]
      # depth 0 = direct dependency of yours
      # depth 1+ = transitive (npm audit often misses these)
      depth:    ((.from // [] | length) - 1 | if . < 0 then 0 else . end),
      audited:  $today,
      cvss:     (.cvssScore // 0),
      title:    (.title // ""),
      source:   "Snyk"
    }
  )
' "$DATED_RAW" > "$DATED_NORM"

if (( $? != 0 )); then
  print -u2 "ERROR: jq normalization failed. Raw file preserved at:"
  print -u2 "  ${DATED_RAW}"
  exit 2
fi

# Rotate symlinks so I don't touch and fuck up.
#   <archive_dir>/latest_raw.json  → newest dated raw file
#   <MATRIX_FILE> (vulns.json)     → newest normalized file
#
# downstream tooling (rn, matrix loader) can always
# read the current state without parsing filenames.

ln -sfn "$DATED_RAW"  "${ARCHIVE_DIR}/latest_raw.json"
ln -sfn "$DATED_NORM" "$MATRIX_FILE"

print "→ Symlinks updated:"
print "  ${ARCHIVE_DIR}/latest_raw.json  → ${DATED_RAW:t}"
print "  ${MATRIX_FILE}  → ${DATED_NORM:t}"

# Prune the kruft (how many KEEP_DAYS days of history)

PRUNED=0
while IFS= read -r old_file; do
  rm -f "$old_file"
  (( PRUNED++ )) || true
done < <(find "$ARCHIVE_DIR" -maxdepth 1 \
           \( -name 'snykTest_*.json' -o -name 'vulns_*.json' \) \
           -mtime "+${KEEP_DAYS}" 2>/dev/null)

(( PRUNED > 0 )) && print "→ Pruned ${PRUNED} archive(s) older than ${KEEP_DAYS} days."

# cressendo and, the money shot!

TOTAL=$(jq 'length' "$DATED_NORM")
CRITICAL=$(jq '[.[] | select(.severity=="critical")] | length' "$DATED_NORM")
HIGH=$(jq '[.[] | select(.severity=="high")] | length' "$DATED_NORM")
PENDING=$(jq '[.[] | select(.status=="pending")] | length' "$DATED_NORM")
NOFIX=$(jq '[.[] | select(.status=="no-fix")] | length' "$DATED_NORM")
TRANSITIVE=$(jq '[.[] | select(.depth > 0)] | length' "$DATED_NORM")

print ""
print "╔══════════════════════════════════════════╗"
print "║  Snyk Harvest Complete                   ║"
print "╠══════════════════════════════════════════╣"
printf "║  %-14s %3d  (direct: %d, transitive: %d)\n" \
  "vulns found:" "$TOTAL" "$(( TOTAL - TRANSITIVE ))" "$TRANSITIVE"
printf "║  %-14s %3d\n" "critical:"      "$CRITICAL"
printf "║  %-14s %3d\n" "high:"          "$HIGH"
printf "║  %-14s %3d\n" "pending fix:"   "$PENDING"
printf "║  %-14s %3d\n" "no fix avail:"  "$NOFIX"
print "╠══════════════════════════════════════════╣"
print "║  Raw   → ${DATED_RAW:t}"
print "║  Norm  → ${DATED_NORM:t}"
print "╚══════════════════════════════════════════╝"
print ""

# Pare snyk's exit semantics so cron/CI can gate on it
(( TOTAL > 0 )) && exit 1 || exit 0
