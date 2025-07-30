#!/bin/bash

set -e

./extract_sign_info
python3 find_ref_sigs.py
./extract_faulted_sign_info
cat "extracted/extracted_unfaulted_results.txt" >> "extracted/extracted_faulted_results.txt"
python3 extract_min_sk.py
python3 experiment2b_helper.py
echo "All steps completed successfully."
