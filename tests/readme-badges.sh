#!/bin/sh
# SPDX-License-Identifier: MPL-2.0
#
# Regression tests for the badges displayed in the project README.
#
# The badge block is everything before the first blank line of README.adoc.
#
#   sh tests/readme-badges.sh
#
# Exit 0 = all checks pass, 1 = at least one failed.

set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
README="${README:-$HERE/../README.adoc}"

if [ ! -r "$README" ]; then
  echo "ERROR: cannot read $README" >&2
  exit 1
fi

failures=0
pass() { echo "ok    $1"; }
fail() { echo "FAIL  $1"; failures=$((failures + 1)); }

# Lines before the first blank line.
badge_block="$(awk '$0 == "" { exit } { print }' "$README")"

# 1. The unrelated OpenSSF Best Practices badge is absent.
name="unrelated OpenSSF Best Practices badge is absent"
if printf '%s\n' "$badge_block" | grep -qF -e 'bestpractices.dev' -e 'OpenSSF Best Practices'; then
  fail "$name"
else
  pass "$name"
fi

# 2. The unrelated OpenSSF project id is absent from the whole README.
name="unrelated OpenSSF project id is absent from README"
if grep -qF '8509' "$README"; then
  fail "$name"
else
  pass "$name"
fi

# 3. Exactly one repository-scoped OpenSSF Scorecard badge remains.
name="repository-scoped OpenSSF Scorecard badge remains"
scorecard="$(printf '%s\n' "$badge_block" | grep -F 'OpenSSF Scorecard')"
count="$(printf '%s\n' "$badge_block" | grep -cF 'OpenSSF Scorecard')"
if [ "$count" -eq 1 ] &&
   printf '%s\n' "$scorecard" | grep -qF 'api.scorecard.dev/projects/github.com/metadatastician/vordr/badge' &&
   printf '%s\n' "$scorecard" | grep -qF 'scorecard.dev/viewer/?uri=github.com/metadatastician/vordr'; then
  pass "$name"
else
  fail "$name (found $count scorecard badge line(s))"
fi

# 4. The badge block stays separated from the document metadata: the text
#    before the first "// SPDX-License-Identifier" ends in two or more
#    newlines, i.e. that marker starts a line and the line before it is blank.
name="badge block remains separated from document metadata"
if awk '
  { i = index($0, "// SPDX-License-Identifier") }
  i > 0 { found = 1; ok = (i == 1 && NR > 1 && prev == ""); exit }
  { prev = $0 }
  END { exit (found && ok) ? 0 : 1 }
' "$README"; then
  pass "$name"
else
  fail "$name"
fi

if [ "$failures" -eq 0 ]; then
  echo "all README badge checks passed"
  exit 0
fi
echo "$failures README badge check(s) failed"
exit 1
