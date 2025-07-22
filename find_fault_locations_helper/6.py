import os

# Hardcoded input and output paths
input_folder = "bash_script_results/results"
output_file = "bash_script_results/outs_with_address.txt"

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
