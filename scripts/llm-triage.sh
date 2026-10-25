#!/usr/bin/env bash
# First-pass triage of a Splunk CSV export by the lab's local LLM.
#   Usage:  llm-triage.sh <results.csv> <output.md> [max_rows]
#   e.g.    llm-triage.sh cases/<case>/raw/failed-logins.csv cases/<case>/evidence/llm-triage.md
# Export the CSV with enterprise-homelab's scripts/splunk-search.sh. The model runs on
# `llm` (ADR 0010), which only accepts requests from ops, so no log data leaves the lab.
# Its answer is a starting point to check against the data, never a finding on its own.
# Send a summarized search (e.g. stats count min(_time) max(_time) by src_ip user action),
# not raw events: only the first max_rows rows are sent, and in testing the one
# successful login was the row that got cut.
set -euo pipefail

CSV=${1:?usage: $0 <results.csv> <output.md> [max_rows]}
OUT=${2:?usage: $0 <results.csv> <output.md> [max_rows]}
MAX_ROWS=${3:-50}
OLLAMA_URL=${OLLAMA_URL:-http://llm.demarzo.lab:11434}
MODEL=${LLM_MODEL:-qwen3.5:4b}
PROMPT_VERSION=1

# Prompt reading runs at ~55-60 tokens/s, so the row cap keeps a run to a minute or two
total=$(( $(wc -l < "$CSV") - 1 ))
sent=$(( total < MAX_ROWS ? total : MAX_ROWS ))
data=$(head -n $((MAX_ROWS + 1)) "$CSV")
(( sent < total )) && echo "warning: only the first ${sent} of ${total} rows are sent; summarize the search instead" >&2

read -r -d '' PROMPT <<'EOF' || true
You are assisting a SOC analyst with first-pass triage. Below is a CSV export of Splunk
search results from a lab environment. Using only the data provided:

1. Summarize the activity in 2-3 sentences.
2. List each source IP with its event count.
3. List the usernames involved.
4. Give the time range covered (first and last timestamp).
5. Say whether this looks like brute-force or password-guessing activity, and why.

If the data does not answer a question, write "not in the data". Do not guess.
EOF

# temperature 0 so a rerun on the same input gives the same answer; think off per ADR 0010
request=$(jq -n --arg model "$MODEL" --arg content "${PROMPT}"$'\n\nRows sent: '"${sent} of ${total}"$'\n\n```csv\n'"${data}"$'\n```' \
  '{model: $model, stream: false, think: false,
    options: {temperature: 0, num_ctx: 16384},
    messages: [{role: "user", content: $content}]}')

started=$(date -u +%FT%TZ)
response=$(curl -sS -m 900 "${OLLAMA_URL}/api/chat" -d "$request")
answer=$(jq -er '.message.content' <<<"$response") || { echo "error: ${response}" >&2; exit 1; }
seconds=$(jq -r '(.total_duration // 0) / 1e9 | floor' <<<"$response")
digest=$(curl -sS -m 10 "${OLLAMA_URL}/api/tags" | jq -r --arg m "$MODEL" '.models[] | select(.name == $m) | .digest[:12]')

cat > "$OUT" <<EOF
# LLM first-pass triage

| | |
|---|---|
| **Run** | ${started} |
| **Model** | \`${MODEL}\` (digest \`${digest}\`), local Ollama on \`llm\`, temperature 0 |
| **Input** | \`$(basename "$CSV")\` (sha256 \`$(sha256sum "$CSV" | cut -c1-16)…\`), ${sent} of ${total} rows sent |
| **Time** | ${seconds} s |
| **Prompt** | v${PROMPT_VERSION}, from [\`scripts/llm-triage.sh\`](../../../scripts/llm-triage.sh) |

Unverified model output. Each claim is checked against the data in the case's triage section.

## Response

${answer}
EOF

echo "${OUT} (${sent}/${total} rows, ${seconds} s)"
