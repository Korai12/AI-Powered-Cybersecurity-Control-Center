#!/usr/bin/env bash
set -euo pipefail

./validate_phase4_1.sh
./validate_phase4_2.sh
./validate_phase4_3.sh

if [ -f ./validate_phase3.sh ]; then
  ./validate_phase3.sh
fi
if [ -f ./validate_phase2_4.sh ]; then
  ./validate_phase2_4.sh
fi

echo 'ALL PHASE 4 CHECKS PASSED'
