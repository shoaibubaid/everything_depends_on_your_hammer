import os
import re

# Input files
unfaulted_file = "bash_script_results/extracted/extracted_unfaulted_results.txt"
faulted_file = "bash_script_results/extracted/extracted_faulted_results.txt"
output_file = "bash_script_results/useful_addresses.txt"
fifty_string = "[50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50 ]"
# Regex to find "lengths = [ ... ]" lines
lengths_pattern = re.compile(r'^lengths = (\[.*\])')
def collect_correct_lengths():
    """
    Collects all unique 'lengths = [...]' entries from the unfaulted file.
    Returns a list of strings.
    """
    if not os.path.isfile(unfaulted_file):
        print(f"Error: {unfaulted_file} not found.")
        return []

    seen = set()
    correct_lengths = []
    correct_lengths.append(fifty_string)

    with open(unfaulted_file, "r") as infile:
        for line in infile:
            line = line.strip()
            match = lengths_pattern.match(line)
            if match:
                entry = match.group(1)
                if entry not in seen:
                    seen.add(entry)
                    correct_lengths.append(entry)

    print(f"Collected {len(correct_lengths)} unique 'lengths' entries.")
    # for element in correct_lengths:
    #     print(element)
    return correct_lengths

def process_faulted(correct_lengths):
    """
    Processes the faulted file, comparing its 'lengths' lines with correct_lengths.
    Writes results to output_file.
    """
    if not os.path.isfile(faulted_file):
        print(f"Error: {faulted_file} not found.")
        return

    with open(faulted_file, "r") as infile:
        lines = infile.readlines()

    # Clear output file
    open(output_file, "w").close()

    for i, line in enumerate(lines):
        if line.startswith("lengths = "):
            found = any(valid == line.strip().split(" = ")[1] for valid in correct_lengths)
            if not found and i >= 7:
                with open(output_file, "a") as outfile:
                    outfile.write(lines[i - 7])  # Write 7 lines above the current 'lengths = ...'

    print(f"Processing complete. Results saved to {output_file}.")

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

if __name__ == "__main__":
    correct_lengths = collect_correct_lengths()
    process_faulted(correct_lengths)
