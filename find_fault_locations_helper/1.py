import os
import subprocess
import tempfile
import sys
import csv


EXECUTABLE = "liboqs_signature_gen/bin/sign_heap"

# Check if executable exists
if not os.path.isfile(f"./{EXECUTABLE}"):
    print(f"Error: ./{EXECUTABLE} does not exist. Please compile your code first.")
    sys.exit(1)

# Validate arguments
if len(sys.argv) != 3:
    print(f"Usage: python3 {sys.argv[0]} <base_address> <max_address_value>")
    print(f"Example: python3 {sys.argv[0]} 0x0000555555557410 610")
    sys.exit(1)

input_addr = sys.argv[1]
if not input_addr.startswith("0x"):
    print("Error: base address must start with 0x")
    sys.exit(1)


# Get base address and max value
BASE_ADDRESS = int(sys.argv[1], 16)  # Convert hex to int
MAX_ADDRESS_VALUE = int(sys.argv[2])

# Prepare output file and directory
OUTPUT_DIR = "bash_script_results"
os.makedirs(OUTPUT_DIR, exist_ok=True)
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "initial_results.txt")

# Disable debuginfod globally
with open(os.path.expanduser("~/.gdbinit"), "w") as gdbinit:
    gdbinit.write("set debuginfod enabled off\n")

# Run bit flips
for i in range(MAX_ADDRESS_VALUE + 1):
    CURRENT_DEC = BASE_ADDRESS + i
    CURRENT_HEX = f"0x{CURRENT_DEC:016x}"

    with open(OUTPUT_FILE, "a") as f:
        f.write(f"\n===============================\n")
        f.write(f"[FLIPPING BITS AT ADDRESS: {CURRENT_HEX}]\n")
        f.write(f"===============================\n")

    for bit in range(8):
        BIT_MASK = 1 << bit
        with open(OUTPUT_FILE, "a") as f:
            f.write(f"\n ------ doing for bit {bit} ------\n")

        # Create temporary GDB script
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as gdb_script:
            gdb_script.write("set pagination off\n")
            gdb_script.write("handle SIGSEGV nostop noprint pass\n")
            gdb_script.write("handle SIGILL nostop noprint pass\n")
            gdb_script.write("handle SIGBUS nostop noprint pass\n")
            gdb_script.write("handle SIGFPE nostop noprint pass\n")
            gdb_script.write(f"set $addr = {CURRENT_HEX}\n")
            gdb_script.write("start\n")
            gdb_script.write("x/1i $addr\n")
            gdb_script.write("x/1bx $addr\n")
            gdb_script.write(f"set *(char*) $addr = *(char*) $addr ^ {BIT_MASK}\n")
            gdb_script.write("x/1bx $addr\n")
            gdb_script.write("x/1i $addr\n")
            gdb_script.write("continue\n")
            gdb_script.write("quit\n")

            gdb_script_name = gdb_script.name

        # Run gdb with timeout (3s)
        try:
            subprocess.run(
                ["timeout", "3", "gdb", "-q", "-x", gdb_script_name, f"./{EXECUTABLE}"],
                stdout=open(OUTPUT_FILE, "a"),
                stderr=subprocess.STDOUT,
                check=False
            )
        except subprocess.TimeoutExpired:
            with open(OUTPUT_FILE, "a") as f:
                f.write(f"Warning: GDB process timed out for address {CURRENT_HEX} (bit {bit}).\n")

        # Clean up temporary GDB script
        os.remove(gdb_script_name)

        with open(OUTPUT_FILE, "a") as f:
            f.write("\n")

print("Bit-flip testing completed.")




# <------2-------->
INPUT_FILE = "bash_script_results/initial_results.txt"
OUTPUT_FILE = "bash_script_results/possible_bitflips.txt"

# Ensure the output directory exists
os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)

# Clear the output file
open(OUTPUT_FILE, "w").close()

buffer = []

with open(INPUT_FILE, "r") as infile, open(OUTPUT_FILE, "a") as outfile:
    for line in infile:
        line = line.rstrip("\n")

        # Maintain rolling buffer of last 5 lines
        buffer.append(line)
        if len(buffer) > 5:
            buffer.pop(0)

        # If target phrase is found, write buffer
        if "crypto_sign_open returned <-1>" in line:
            outfile.write("\n".join(buffer) + "\n")
            outfile.write("---\n")  # Separator

print(f"Extraction complete. Results saved in {OUTPUT_FILE}")





# <------3 and 4 -------->
base_dec = int(input_addr, 16)


# --- Input/Output Files ---
INPUT_FILE = "bash_script_results/possible_bitflips.txt"
OUTPUT_FILE = "bash_script_results/possible_faults.csv"

os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)

# Clear output file
open(OUTPUT_FILE, "w").close()

# --- Read File and Process ---
lines = []

with open(INPUT_FILE, "r") as infile, open(OUTPUT_FILE, "a") as outfile:
    for line in infile:
        line = line.strip()

        if "crypto_sign_open returned <-1>" in line:
            if len(lines) >= 3:
                # Extract values
                addr = lines[1].split()[0]
                byte1 = lines[1].split()[2]
                byte2 = lines[0].split()[2]

                # Convert address to decimal and calculate offset
                addr_dec = int(addr, 16)
                offset = addr_dec - base_dec

                # Write CSV line
                outfile.write(f"{offset},{byte1},{byte2}\n")

            lines = []  # Reset buffer
        else:
            lines.append(line)
            if len(lines) > 3:
                lines.pop(0)  # Keep last 3 lines only

print(f"Processing complete. Output saved to {OUTPUT_FILE}.")




# # --- Argument Parsing ---
# if len(sys.argv) != 2:
#     print(f"Usage: python3 {sys.argv[0]} <base_address>")
#     print(f"Example: python3 {sys.argv[0]} 0x0000555555557410")
#     sys.exit(1)

# input_addr = sys.argv[1]
# if not input_addr.startswith("0x"):
#     print("Error: Base address must start with 0x")
#     sys.exit(1)

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





# <-------5 and 6------->
# Hardcoded folder path
folder = "bash_script_results/results"

# Check if the folder exists
if not os.path.isdir(folder):
    print(f"Error: '{folder}' is not a directory.")
    sys.exit(1)

# Walk through the directory and remove empty files
deleted_files = []
for root, _, files in os.walk(folder):
    for file in files:
        file_path = os.path.join(root, file)
        if os.path.isfile(file_path) and os.path.getsize(file_path) == 0:
            deleted_files.append(file_path)
            os.remove(file_path)

# Print deleted files
if deleted_files:
    print("Deleted empty files:")
    for f in deleted_files:
        print(f)
else:
    print("No empty files found.")


# Hardcoded input and output paths
input_folder = "bash_script_results/results"
output_file = "bash_script_results/in/collected_faulty_sig.txt"

# Ensure output directory exists
os.makedirs(os.path.dirname(output_file), exist_ok=True)

# Clear the output file
with open(output_file, "w") as outfile:
    pass

# Loop through all files in the folder (non-recursive)
with open(output_file, "a") as outfile:
    for file_name in sorted(os.listdir(input_folder)):
        file_path = os.path.join(input_folder, file_name)
        if os.path.isfile(file_path):
            outfile.write(f"address = {file_name}\n")
            with open(file_path, "r") as infile:
                outfile.write(infile.read())
            outfile.write("\n\n")  # Add two newlines after each file's content

print(f"All files combined into {output_file}.")

