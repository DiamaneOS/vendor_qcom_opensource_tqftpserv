#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause
#
# Builds and runs the fuzz targets, all at once, one process each.
#   fuzz/run.sh [seconds]   fuzz each target this long (default 600)
#   fuzz/run.sh replay      run every corpus, seed and regression input once
# Corpora go to fuzz/corpus/<target>, crashes to fuzz/artifacts/<target>,
# logs to fuzz/logs. None of them is committed.
# regress.tar.gz is committed: earlier corpora merged to a minimal set
# (./fuzz_<target> -merge=1 regress/<target> corpus/<target> seeds/<target>,
# then tar -czf regress.tar.gz regress). It is unpacked to regress/ and used
# by both modes.
set -eu

cd "$(dirname "$0")"
TARGETS="request session transfer translate"
make -s

python3 gen_seeds.py seeds
rm -rf regress
tar -xzf regress.tar.gz
for t in $TARGETS; do
	mkdir -p corpus/$t artifacts/$t logs
done

max_len() {
	case $1 in
	session|transfer) echo 16384 ;;
	*) echo 4200 ;;
	esac
}

if [ "${1:-}" = replay ]; then
	status=0
	for t in $TARGETS; do
		if ./fuzz_$t -runs=0 -close_fd_mask=3 -max_len=$(max_len $t) \
				corpus/$t seeds/$t regress/$t > logs/replay-$t.log 2>&1; then
			echo "replay $t: $(find corpus/$t seeds/$t regress/$t -type f | wc -l) inputs, ok"
		else
			echo "replay $t: FAILED, see fuzz/logs/replay-$t.log"
			status=1
		fi
	done
	exit $status
fi

secs=${1:-600}
for t in $TARGETS; do
	./fuzz_$t corpus/$t seeds/$t regress/$t -dict=tqftpserv.dict \
		-max_total_time=$secs -max_len=$(max_len $t) -timeout=10 \
		-rss_limit_mb=4096 -close_fd_mask=3 -print_final_stats=1 -use_value_profile=1 \
		-artifact_prefix=artifacts/$t/ > logs/$t.log 2>&1 &
done
wait || true
for t in $TARGETS; do
	echo "$t: $(grep -E '^stat::number_of_executed_units' logs/$t.log || true)" \
	     "crashes: $(ls artifacts/$t | wc -l)"
done
