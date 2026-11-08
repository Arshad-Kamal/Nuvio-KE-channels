#!/bin/sh
# Commits a monitor run's state files and pushes them to main (Nuvio-Project Spec 71 Design 3).
# Usage: [TOKEN=<token>] sh harvest/commit_state.sh <repo>
#
# Nothing to commit: exit 0. Only the state files are committed, onto the checked-out origin/main (any other checkout:
# exit 1, so no other branch's commits reach main). A rejected push fetches main and rebases onto it, at most three
# tries, never forcing. When pool/ or monitor/ changed between the commit the run read and the fetched tip, nothing is
# pushed (exit 1): the state was judged against the old pool (a URL a harvest push removed, a takedown say, must not
# come back in state.tsv) or the old state (another run's results would merge into a state no run produced).
# TOKEN reaches git as an Authorization header for https://github.com/ through GIT_CONFIG_* variables, never argv or
# .git/config (the workflows check out with persist-credentials: false). RETRY_PAUSE (seconds, default 5) is for tests.
set -eu
cd "$1"
if [ -n "${TOKEN:-}" ]; then
  GIT_CONFIG_COUNT=1
  GIT_CONFIG_KEY_0=http.https://github.com/.extraheader
  GIT_CONFIG_VALUE_0="AUTHORIZATION: basic $(printf 'x-access-token:%s' "$TOKEN" | base64 | tr -d '\n')"
  export GIT_CONFIG_COUNT GIT_CONFIG_KEY_0 GIT_CONFIG_VALUE_0
fi
# the commit and any rebase need an identity; a runner has none configured
GIT_AUTHOR_NAME='github-actions[bot]'
GIT_AUTHOR_EMAIL='41898282+github-actions[bot]@users.noreply.github.com'
GIT_COMMITTER_NAME=$GIT_AUTHOR_NAME
GIT_COMMITTER_EMAIL=$GIT_AUTHOR_EMAIL
export GIT_AUTHOR_NAME GIT_AUTHOR_EMAIL GIT_COMMITTER_NAME GIT_COMMITTER_EMAIL

for file in monitor/state.tsv monitor/cursor; do
  if [ -e "$file" ]; then git add -- "$file"; fi
done
if git diff --cached --quiet; then
  echo "monitor: no change to commit"
  exit 0
fi
read_from=$(git rev-parse HEAD)
if [ "$read_from" != "$(git rev-parse --verify --quiet refs/remotes/origin/main || true)" ]; then
  echo "monitor: the checkout is not origin/main; nothing pushed" >&2
  exit 1
fi
git commit --quiet -m "Monitor run $(date -u '+%Y-%m-%d %H:%M') UTC"
try=1
while ! git push --quiet origin HEAD:main; do
  if [ "$try" -ge 3 ]; then
    echo "monitor: the push failed $try times; nothing pushed" >&2
    exit 1
  fi
  try=$((try + 1))
  sleep "${RETRY_PAUSE:-5}"
  git fetch --quiet origin main || continue  # the next try pushes again (refused while main is ahead) and refetches
  if ! git diff --quiet "$read_from" FETCH_HEAD -- pool monitor; then
    echo "monitor: the pool or the state changed during the run (or could not be compared); nothing pushed" >&2
    exit 1
  fi
  if ! git rebase --quiet FETCH_HEAD; then
    git rebase --abort 2>/dev/null || true  # a rebase refused before it started has nothing to abort
    echo "monitor: the state does not rebase onto main; nothing pushed" >&2
    exit 1
  fi
done
echo "monitor: state pushed"
