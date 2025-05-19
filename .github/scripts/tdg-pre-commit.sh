#!/usr/bin/env bash

: "${GH_ACTION_OUTPUT:=false}"
: "${TDG_FAIL_ON_ERROR:=true}"

if ! command -v tdg &> /dev/null; then
  echo "tdg not found on PATH; aborting..." >&2
  exit 0
fi

if [ "$#" -eq 0 ]; then
  exit 0
fi

files=()

for argv; do
  argv=$(realpath "$argv")
  argv=${argv//./\\.}
  files+=("-include" "^$argv$")
done

if [ "$GH_ACTION_OUTPUT" = true ]; then

  read -r -d '' jq_filter <<- EOF
    "::warning file=" + .file +
    ",line=" + (.line|tostring) +
    ",endLine=" + (.line|tostring) +
    ",title=" + .type +
    "::" + .title
	EOF
  # N.B. heredoc-EOF should be indented with tabs!
else
  jq_filter='.file + ":" + (.line|tostring) + " " + .type + " found!"'
fi

errors=$(tdg "${files[@]}" -log /dev/null | jq ".comments[]? | $jq_filter")

# The errors may contain "unbalanced" quotes – using -d '\n' disables xargs'
# quote/backslash-processing, which prevents unbalanced quotes from causing
# issues.
# As a result of this, we do need to manually insert newlines _and_ strip the
# superfluous quotes that would've otherwise been removed by xargs.

if [[ -n $errors ]]; then
  echo "$errors" | xargs -d '\n' printf "%s\n" | tr -d '"'
fi

if [[ -n $errors && ${TDG_FAIL_ON_ERROR,,} == 'true' ]]; then
  exit 1
fi
