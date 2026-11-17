#!/bin/sh
# Run the Atheris harnesses. Requires an environment with atheris installed (the fuzz image, or
# Linux x86-64 with `uv sync --all-packages --group fuzz`). Run from the repository root:
#
#     fuzz/run.sh [SECONDS_PER_TARGET] [TARGET ...]
#
# TARGET is a corpus name such as `jwks` or `verify_signed`; default is every harness. The
# committed seeds in fuzz/corpus/<target>/ are read only: new inputs go to $FUZZ_WORK_DIR
# (default /tmp/pytrat-fuzz), crash reproducers to $FUZZ_WORK_DIR/<target>/artifacts/.
# Exits non-zero if any harness found a crash.
set -eu

seconds="${1:-60}"
[ "$#" -gt 0 ] && shift
work="${FUZZ_WORK_DIR:-/tmp/pytrat-fuzz}"

if [ "$#" -eq 0 ]; then
    set -- $(cd fuzz && ls fuzz_*.py | sed -e 's/^fuzz_//' -e 's/\.py$//')
fi

failed=""
for target in "$@"; do
    mkdir -p "$work/$target/corpus" "$work/$target/artifacts"
    echo "=== $target (${seconds}s)"
    if ! python -m "fuzz.fuzz_$target" \
        "$work/$target/corpus" "fuzz/corpus/$target" \
        -max_total_time="$seconds" \
        -timeout=10 \
        -rss_limit_mb=2048 \
        -max_len=8192 \
        -print_final_stats=1 \
        -artifact_prefix="$work/$target/artifacts/" \
        >"$work/$target/log.txt" 2>&1; then
        failed="$failed $target"
    fi
    grep -E "INITED|DONE|^Done|^stat::(number_of_executed_units|average_exec_per_sec|new_units_added|peak_rss_mb)|Uncaught Python exception|^[A-Za-z]*(Error|Exception):|^==[0-9]+== ERROR|artifact_prefix|Test unit written" \
        "$work/$target/log.txt" || true
done

if [ -n "$failed" ]; then
    echo "harnesses with findings:$failed (see $work/<target>/log.txt and artifacts/)" >&2
    exit 1
fi
echo "all harnesses ran clean"
