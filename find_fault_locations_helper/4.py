import csv
import os
import sys
import subprocess

# --- Argument Parsing ---
if len(sys.argv) != 2:
    print(f"Usage: python3 {sys.argv[0]} <base_address>")
    print(f"Example: python3 {sys.argv[0]} 0x0000555555557410")
    sys.exit(1)

input_addr = sys.argv[1]
if not input_addr.startswith("0x"):
    print("Error: Base address must start with 0x")
    sys.exit(1)

# Convert base address to decimal
BASE_ADDRESS = int(input_addr, 16)

# --- File and Directory Setup ---
INPUT_FILE = "bash_script_results/possible_faults.csv"
EXEC_FILE = "./liboqs_signature_gen/bin/sign_heap"
RESULT_DIR1 = "bash_script_results/results"
RESULT_LOG1 = "signature.txt"
ERROR_LOG = "error_log.txt"

# Ensure required files exist
if not os.path.isfile(INPUT_FILE):
    print(f"Error: Input CSV file '{INPUT_FILE}' not found!")
    sys.exit(1)

if not os.path.isfile(EXEC_FILE):
    print(f"Error: Executable file '{EXEC_FILE}' not found!")
    sys.exit(1)

# Create results directory
os.makedirs(RESULT_DIR1, exist_ok=True)

# Clear previous logs
open(RESULT_LOG1, "w").close()
open(ERROR_LOG, "w").close()

# --- Processing CSV ---
with open(INPUT_FILE, "r") as csvfile:
    reader = csv.reader(csvfile)

    for row in reader:
        if len(row) < 3:
            with open(ERROR_LOG, "a") as errlog:
                errlog.write(f"Skipping invalid row: {row}\n")
            continue

        address, value, value2 = row[:3]
        address, value, value2 = address.strip(), value.strip(), value2.strip()

        # Validate data
        if not address or not value or not value2:
            with open(ERROR_LOG, "a") as errlog:
                errlog.write(f"Skipping invalid entry: Address={address}, Value={value}, Value2={value2}\n")
            continue

        # Compute final address
        try:
            final_address = f"0x{BASE_ADDRESS + int(address):X}"
        except ValueError:
            with open(ERROR_LOG, "a") as errlog:
                errlog.write(f"Invalid address offset: {address}\n")
            continue

        print(f"Processing Address={final_address}, Value={value}")

        # Run GDB
        try:
            subprocess.run(
                [
                    "gdb", "-batch",
                    "-ex", f"file {EXEC_FILE}",
                    "-ex", "start",
                    "-ex", f"set *(char *){final_address} = {value}",
                    "-ex", "continue"
                ],
                stdout=open(RESULT_LOG1, "a"),
                stderr=subprocess.STDOUT,
                check=False
            )
        except Exception as e:
            with open(ERROR_LOG, "a") as errlog:
                errlog.write(f"GDB failed for Address={address}, Value={value}, Value2={value2}: {e}\n")
            continue

        # Copy result
        output_file1 = os.path.join(RESULT_DIR1, f"{address}_{value}_{value2}.txt")
        try:
            os.system(f"cp {RESULT_LOG1} {output_file1}")
        except Exception as e:
            with open(ERROR_LOG, "a") as errlog:
                errlog.write(f"Failed to save result for {address},{value}: {e}\n")

print(f"Processing complete. Errors (if any) logged in {ERROR_LOG}.")
