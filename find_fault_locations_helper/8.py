import os
import re

# Input and output files
input_file = "bash_script_results/useful_addresses.txt"
output_csv = "bash_script_results/useful_addresses.csv"

# Ensure output directory exists
os.makedirs(os.path.dirname(output_csv), exist_ok=True)

# Clear output file and add header
with open(output_csv, "w") as out:
    out.write("ID,Value1,Value2\n")

# Read input file line by line
pattern = re.compile(r"^([^_]+)_([^_]+)_([^.]+)\.txt$")
with open(input_file, "r") as infile, open(output_csv, "a") as outfile:
    for line in infile:
        line = line.strip()
        parts = line.split()
        if len(parts) >= 3:
            word = parts[2]  # Third word
            match = pattern.match(word)
            if match:
                id_, val1, val2 = match.groups()
                outfile.write(f"{id_},{val1},{val2}\n")

print(f"Processing complete. Output saved to {output_csv}.")
