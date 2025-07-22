import os

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
