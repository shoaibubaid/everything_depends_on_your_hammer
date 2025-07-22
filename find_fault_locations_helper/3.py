import sys
import os

# --- Check Arguments ---
if len(sys.argv) != 2:
    print(f"Usage: python3 {sys.argv[0]} <base_address>")
    print(f"Example: python3 {sys.argv[0]} 0x0000555555557410")
    sys.exit(1)

# --- Base Address ---
input_addr = sys.argv[1]
if not input_addr.startswith("0x"):
    print("Error: base address must start with 0x")
    sys.exit(1)

# Convert to decimal
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
