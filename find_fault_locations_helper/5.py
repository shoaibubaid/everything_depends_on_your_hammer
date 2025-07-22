import os
import sys

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
