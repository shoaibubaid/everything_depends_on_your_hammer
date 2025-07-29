# collect both correct and faulty signatures and finally gives the min_sk values 
import subprocess
import os
import platform
import csv
import sys
import shlex
import random
import shutil
import re
import time
from configs import liboqs

def run_command(cmd, cwd=None):
    # If the command starts with 'python3', replace it with the current Python interpreter
    if cmd.startswith("python3"):
        cmd = cmd.replace("python3", sys.executable, 1)

    # Handle executables on Windows
    if platform.system() == "Windows":
        parts = shlex.split(cmd)
        exe = parts[0]
        # Remove './' prefix if present
        if exe.startswith("./"):
            exe = exe[2:]
        # Add .exe only if it's not a Python script or already has an extension
        if not exe.endswith((".exe", ".py")) and os.path.isfile(os.path.join(cwd or ".", exe + ".exe")):
            exe += ".exe"
        parts[0] = exe
        cmd = parts

    else:
        cmd = shlex.split(cmd)

    subprocess.run(cmd, cwd=cwd, check=True)



if len(sys.argv) != 2:
    print(f"Usage: {sys.argv[0]} <number_of_signs_to_collect>")
    sys.exit(1)

# Get the first argument
N = int(sys.argv[1])

if liboqs == 1:
    BASE_ADDRESS = int("5555555e13d0", 16)
# BASE_ADDRESS = int("5555555e1420", 16) #for liboqs
else:
    BASE_ADDRESS = int("555555556f10", 16)
source = "signature.txt"
unfaulted_signature = "bash_script_results/in/collected_unfaulted_sig.txt"
faulty_signature = "bash_script_results/in/collected_faulty_sig.txt"
csv_file="bash_script_results/useful_addresses.csv"


# EXECUTABLE = "liboqs_signature_gen/bin/sign_heap_v2"
if(liboqs == 1):
    EXECUTABLE = "liboqs_signature_gen/bin/sign_heap_v2"
else:
    EXECUTABLE = "sphincsplus-standard/ref/sign_sha2_256f_v2"


# with open(faulty_signature, "w") as f:
#     pass  # Just open with 'w' mode to truncate

# Check if the CSV file exists
if not os.path.isfile(csv_file):
    print(f"Error: File '{csv_file}' not found!")
    sys.exit(1)

# Count total lines in the CSV (excluding header)
with open(csv_file, "r") as f:
    # total_lines = sum(1 for _ in f)
    reader = csv.reader(f)
    next(reader)  # skip header
    rows = [row for row in reader]

total_lines = len(rows)

if total_lines == 0:
    print("Error: The CSV file contains no valid data rows!")
    sys.exit(1)


for i in range(1, N+1):
    print(f"Iteration {i}/{N}")
    random_row = random.choice(rows)
    offset = random_row[1].strip()
    toByte = random_row[2].strip()
    final_address = hex(BASE_ADDRESS + int(offset, 16))
    print(f"offset = {offset}, final_address = {final_address}")

    # Create a temporary GDB script
    GDB_SCRIPT = f"gdb_commands_{i}.txt"
    with open(GDB_SCRIPT, "w") as gdb_file:
        gdb_file.write(f"""set pagination off
handle SIGSEGV nostop noprint pass
handle SIGILL nostop noprint pass
handle SIGBUS nostop noprint pass
handle SIGFPE nostop noprint pass
start
set *(char*){final_address} = {toByte}
c
quit
""")

    # Run GDB with the script (with 3s timeout)
    try:
        subprocess.run(
            ["gdb", "-q", "--batch", "-x", GDB_SCRIPT, EXECUTABLE],
            check=True,
            timeout=3
        )

    except subprocess.CalledProcessError as e:
        print(f"Error running GDB in iteration {i}: {e}")
    except subprocess.TimeoutExpired:
        print(f"GDB timeout on iteration {i}")

    # Clean up
    os.remove(GDB_SCRIPT)

    # Check CPY_FILE content
    if not os.path.isfile(source) or os.path.getsize(source) == 0:
        print(f"The iteration {i} is empty!")
    else:
        with open(source, "r") as src, open(faulty_signature, "a") as dst:
            dst.write(src.read())


