import os
import subprocess
import tempfile
import time
import sys

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
