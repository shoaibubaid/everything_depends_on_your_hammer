#!/usr/bin/env python3
import os
import sys
import random
import subprocess
from configs import liboqs

# Hardcoded executable
OUT_DIR = "bash_script_results/in/"
OUT_FILE = "collected_faulty_sig.txt"
CPY_FILE = "signature.txt"

if liboqs == 1:
    BASE_ADDRESS = int("5555555e1420", 16)
    EXECUTABLE = "liboqs_signature_gen/bin/sign_heap_v2"
else:
    BASE_ADDRESS = int("555555556e70", 16)
    EXECUTABLE = "sphincsplus-standard/ref/sign_sha2_256f_v2"

csv_file = "bash_script_results/useful_addresses.csv"

# Argument check
if len(sys.argv) != 2:
    print(f"Usage: {sys.argv[0]} <number_of_signs_to_collect>")
    sys.exit(1)

N = int(sys.argv[1])

# Clear OUT_FILE
open(os.path.join(OUT_DIR, OUT_FILE), "w").close()

# Check if CSV file exists
if not os.path.isfile(csv_file):
    print(f"Error: File '{csv_file}' not found!")
    sys.exit(1)

# Check if executable exists
if not os.path.isfile(EXECUTABLE):
    print(f"Error: Executable '{EXECUTABLE}' not found!")
    sys.exit(1)

# Count total lines in the CSV (excluding header)
with open(csv_file, "r") as f:
    total_lines = sum(1 for _ in f)

if total_lines <= 1:
    print("Error: The CSV file contains no data rows!")
    sys.exit(1)

# Repeat the GDB modification N times
for i in range(1, N + 1):
    print(f"Iteration {i}/{N}")

    # Select a random row (excluding header)
    random_line = random.randint(2, total_lines)
    print(f"random line = {random_line}")

    # Read the random row and extract first and second columns
    with open(csv_file, "r") as f:
        for idx, line in enumerate(f, start=1):
            if idx == random_line:
                parts = line.strip().split(",")
                offset = parts[0]
                toByte = parts[1]
                break

    final_address = f"0x{BASE_ADDRESS + int(offset):X}"
    print(f"offset = {offset}")
    print(f"final_address = {final_address}")

    # Create a temporary GDB script
    gdb_script_name = f"gdb_commands_{i}.txt"
    with open(gdb_script_name, "w") as gdb_script:
        gdb_script.write(
            "set pagination off\n"
            "handle SIGSEGV nostop noprint pass\n"
            "handle SIGILL nostop noprint pass\n"
            "handle SIGBUS nostop noprint pass\n"
            "handle SIGFPE nostop noprint pass\n"
            # "# add-symbol-file /usr/local/lib/liboqs.so\n"
            "start\n"
            f"set *(char*){final_address} = {toByte}\n"
            "c\n"
            "quit\n"
        )

    # Run GDB with the script
    subprocess.run(
        ["timeout", "3", "gdb", "-q", "--batch", "-x", gdb_script_name, EXECUTABLE],
        check=False
    )

    # Clean up
    os.remove(gdb_script_name)
    if not os.path.isfile(CPY_FILE) or os.path.getsize(CPY_FILE) == 0:
        print(f"The iteration {i} is empty!")
    else:
        with open(os.path.join(OUT_DIR, OUT_FILE), "a") as out_file, open(CPY_FILE, "r") as cpy_file:
            out_file.write(cpy_file.read())

