#!/usr/bin/env bash
# Create a case folder from the template: scripts/new-case.sh <short-name> "<title>"
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <short-name> \"<title>\"" >&2
  exit 1
fi

repo="$(cd "$(dirname "$0")/.." && pwd)"
date="$(date -u +%F)"
year="${date%%-*}"
dir="${repo}/cases/${date}-$1"

if [[ -e "$dir" ]]; then
  echo "error: ${dir} already exists" >&2
  exit 1
fi

# Next case number this year, counting existing case folders
n=$(find "${repo}/cases" -mindepth 1 -maxdepth 1 -type d -name "${year}-*" | wc -l)
id="CASE-${year}-$(printf '%03d' $((n + 1)))"

mkdir -p "${dir}/evidence" "${dir}/raw"
sed -e "s/CASE-YYYY-NNN: <short title>/${id}: $2/" \
    -e "s/| \*\*Date\*\* | YYYY-MM-DD |/| **Date** | ${date} |/" \
    "${repo}/cases/TEMPLATE.md" > "${dir}/README.md"

echo "${id}: ${dir#"$repo"/}/README.md"
