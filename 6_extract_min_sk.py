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


ATTACK_CODE = "sphincsplus-attack-code-main/ref"
attack_path = os.path.abspath(ATTACK_CODE)
run_command("./extract_sign_info", cwd=attack_path)
run_command("./extract_faulted_sign_info", cwd=attack_path)




#!/usr/bin/env python3

def chunk_file_by_address(input_file_path):
    """
    Divides an input file into chunks based on the 'address' parameter.
    
    Args:
        input_file_path (str): Path to the input file
    
    Returns:
        list: List of tuples (address_value, chunk_content)
    """
    # Read the input file
    with open(input_file_path, 'r') as file:
        content = file.read()
    
    # Find all occurrences of "address = "
    address_indices = []
    for i, line in enumerate(content.split('\n')):
        if line.startswith("address = "):
            # Get character index of the start of the line
            char_index = len('\n'.join(content.split('\n')[:i]))
            if i > 0:  # Add newline character length except for the first line
                char_index += 1
            address_indices.append((char_index, line))
    
    # Create chunks based on address positions
    chunks = []
    for i, (index, address_line) in enumerate(address_indices):
        # Extract address value
        address_value = address_line.split("=")[1].strip()
        
        # Determine chunk start and end indices
        start_index = index
        if i < len(address_indices) - 1:
            end_index = address_indices[i + 1][0]
        else:
            end_index = len(content)
        
        # Extract chunk content
        chunk_content = content[start_index:end_index].strip()
        chunks.append((address_value, chunk_content))
    
    # print(f"Total chunks identified: {len(chunks)}")
    return chunks

def extract_signature_fields(chunks):
    """
    Extracts leaf, lengths, and wots_sign from each chunk.
    
    Args:
        chunks (list): List of (address, content) tuples
    
    Returns:
        list: List of dictionaries containing the extracted fields
    """
    extracted_data = []
    
    for address, content in chunks:
        # Initialize with default values
        data = {
            'address': address,
            'leaf': None,
            'lengths': None,
            'wots_sign': None
        }
        
        # Process the content line by line
        for line in content.split('\n'):
            line = line.strip()
            
            # Extract leaf value
            if line.startswith("leaf = "):
                data['leaf'] = line.split("=")[1].strip()
            
            # Extract lengths array
            elif line.startswith("lengths = "):
                # Extract the array part
                array_str = line[line.find("["):line.find("]")+1]
                # Convert string representation of array to actual list
                try:
                    data['lengths'] = eval(array_str)
                except:
                    data['lengths'] = array_str  # Keep as string if eval fails
            
            # Extract wots_sign value
            elif line.startswith("wots_sign = "):
                data['wots_sign'] = line.split("=")[1].strip()
        
        extracted_data.append(data)
    
    # print(f"Extracted signature fields from {len(extracted_data)} chunks")
    return extracted_data

# def main():
#     import argparse
#     import json
    
#     parser = argparse.ArgumentParser(description="Process XMSS signature file")
#     parser.add_argument("input_file", help="Path to the input file")
#     parser.add_argument("--output-json", help="Optional path to save extracted data as JSON")
    
#     args = parser.parse_args()
    
#     # Get chunks based on address
source_file_name = "bash_script_results/extracted/extracted_faulted_results.txt"
chunks = chunk_file_by_address(source_file_name)

# Extract specific fields
extracted_data = extract_signature_fields(chunks)

# Print summary of extracted data
# for i, data in enumerate(extracted_data):
#     print(f"\nChunk {i+1}:")
#     print(f"  Address: {data['address']}")
#     print(f"  Leaf: {data['leaf']}")
#     print(f"  Lengths: {data['lengths'][:5]}... (total {len(data['lengths']) if isinstance(data['lengths'], list) else 'N/A'} values)")
#     wots_sign = data['wots_sign']
#     if wots_sign:
#         print(f"  WOTS Sign: {wots_sign[:10]}... (length: {len(wots_sign)})")


def organize_by_leaf(extracted_data):
    """
    Organizes the extracted data by leaf value.
    
    Args:
        extracted_data (list): List of dictionaries with signature fields
    
    Returns:
        dict: Dictionary with leaf values as keys and lists of matching records as values
    """
    leaf_organized = {}
    
    for data in extracted_data:
        leaf = data.get('leaf')
        if leaf is not None:
            # If this leaf doesn't exist yet in our dictionary, create a new list
            if leaf not in leaf_organized:
                leaf_organized[leaf] = []
            
            # Add this data record to the appropriate leaf list
            leaf_organized[leaf].append(data)
    
    print(f"Organized data by {len(leaf_organized)} unique leaf values")
    return leaf_organized


def compute_minimum_lengths_by_leaf(leaf_organized):
    """
    For each leaf group, compares all lengths arrays and produces a new array 
    with the minimum value at each index.
    
    Args:
        leaf_organized (dict): Dictionary with leaf values as keys and lists of data as values
    
    Returns:
        dict: Dictionary with leaf values as keys and minimum lengths arrays as values
    """
    min_lengths_by_leaf = {}
    
    for leaf, data_list in leaf_organized.items():
        # Skip if there's no data for this leaf
        if not data_list:
            continue
            
        # Skip if first item has no lengths array or it's not a list
        if 'lengths' not in data_list[0] or not isinstance(data_list[0]['lengths'], list):
            min_lengths_by_leaf[leaf] = None
            continue
            
        # Get all lengths arrays for this leaf
        all_lengths = [data['lengths'] for data in data_list if isinstance(data['lengths'], list)]
        
        # Skip if no valid lengths arrays
        if not all_lengths:
            min_lengths_by_leaf[leaf] = None
            continue
            
        # Find the maximum length of all arrays
        max_length = max(len(arr) for arr in all_lengths)
        
        # Initialize result array with max values
        min_lengths = [float('inf')] * max_length
        
        # Find minimum value for each index
        for lengths in all_lengths:
            for i, val in enumerate(lengths):
                if i < max_length and val < min_lengths[i]:
                    min_lengths[i] = val
        
        # Replace any remaining infinity values with 0 (or another appropriate default)
        min_lengths = [val if val != float('inf') else 0 for val in min_lengths]
        
        # Store the result
        min_lengths_by_leaf[leaf] = min_lengths
    
    print(f"Computed minimum lengths arrays for {len(min_lengths_by_leaf)} leaf values")
    return min_lengths_by_leaf


def compute_minimum_lengths_and_wots_sign(leaf_organized):
    """
    For each leaf group, compares all lengths arrays and produces:
    1. A new array with the minimum value at each index
    2. The corresponding wots_sign parts based on the minimum lengths
    
    Args:
        leaf_organized (dict): Dictionary with leaf values as keys and lists of data as values
    
    Returns:
        dict: Dictionary with leaf values as keys and dictionaries containing min_lengths and 
              corresponding wots_sign as values
    """
    results_by_leaf = {}
    
    for leaf, data_list in leaf_organized.items():
        # Skip if there's no data for this leaf
        if not data_list:
            continue
            
        # Skip if first item has no lengths array or it's not a list
        if 'lengths' not in data_list[0] or not isinstance(data_list[0]['lengths'], list):
            results_by_leaf[leaf] = {"min_lengths": None, "wots_sign": None}
            continue
        
        # Filter out entries with invalid data
        valid_data = []
        for data in data_list:
            if (isinstance(data.get('lengths'), list) and 
                data.get('wots_sign') and 
                len(data['wots_sign']) >= len(data['lengths']) * 64):
                valid_data.append(data)
        
        if not valid_data:
            results_by_leaf[leaf] = {"min_lengths": None, "wots_sign": None}
            continue
            
        # Find maximum length of all lengths arrays
        max_length = max(len(data['lengths']) for data in valid_data)
        
        # Initialize result arrays
        min_lengths = [float('inf')] * max_length
        min_indices = [-1] * max_length  # Store which chunk has the minimum value
        
        # Find minimum value for each index and store which chunk it came from
        for chunk_idx, data in enumerate(valid_data):
            lengths = data['lengths']
            for i, val in enumerate(lengths):
                if i < max_length and val < min_lengths[i]:
                    min_lengths[i] = val
                    min_indices[i] = chunk_idx
        
        # Replace any remaining infinity values with 0
        min_lengths = [val if val != float('inf') else 0 for val in min_lengths]
        
        # Construct the corresponding wots_sign
        wots_sign = ""
        for i, chunk_idx in enumerate(min_indices):
            if chunk_idx >= 0:
                # Get the wots_sign from the chunk with the minimum length at this position
                chunk_wots_sign = valid_data[chunk_idx]['wots_sign']
                # Calculate the start and end indices for this section of the wots_sign
                start_idx = i * 64
                end_idx = start_idx + 64
                # Extract this section if it exists
                if end_idx <= len(chunk_wots_sign):
                    wots_sign += chunk_wots_sign[start_idx:end_idx]
                else:
                    # If out of range, append zeros or another placeholder
                    wots_sign += "0" * 64
            else:
                # For positions without a valid chunk, append zeros or another placeholder
                wots_sign += "0" * 64
        
        # Store the results
        results_by_leaf[leaf] = {
            "min_lengths": min_lengths,
            "wots_sign": wots_sign
        }
    
    print(f"Computed minimum lengths and corresponding wots_sign for {len(results_by_leaf)} leaf values")
    return results_by_leaf


extracted_data_by_leaf = organize_by_leaf(extracted_data)
minimum_array = compute_minimum_lengths_by_leaf(extracted_data_by_leaf)
minimum_array_wots_sign = compute_minimum_lengths_and_wots_sign(extracted_data_by_leaf)

def save_results_to_txt(results_by_leaf, output_file_path):
    """
    Saves the final results to a text file with the specified format.
    
    Args:
        results_by_leaf (dict): Dictionary with leaf values as keys and dictionaries 
                               containing min_lengths and wots_sign as values
        output_file_path (str): Path to save the output file
    """
    with open(output_file_path, 'w') as f:
        for leaf, result in results_by_leaf.items():
            min_lengths = result.get("min_lengths")
            wots_sign = result.get("wots_sign")
            
            if min_lengths and wots_sign:
                f.write(f"leaf{leaf}_bi_values = {min_lengths}\n")
                f.write(f"leaf{leaf}_most_secret_value = {wots_sign}\n")
                # f.write(f"leaf = {leaf}\n")
                # f.write(f"lengths = {min_lengths}\n")
                f.write(f"wots_sign = {wots_sign}\n\n")
    
    print(f"Results saved to {output_file_path}")



save_results_to_txt(minimum_array_wots_sign,"bash_script_results/extracted/minimum_wots_sign.txt")



def extract_blocks(lines, key_filter):
    """Extracts blocks following each 'count =' line, filtered by key_filter list."""
    blocks = []
    current_block = []
    recording = False

    for line in lines:
        if line.strip().startswith("count = "):
            if recording:
                blocks.append(current_block)
                current_block = []
            recording = True
        elif recording and any(k in line for k in key_filter):
            current_block.append(line)

    if recording and current_block:
        blocks.append(current_block)

    return blocks

def extract_leaf_value(block):
    """Extracts the value from a 'leaf = v' line."""
    for line in block:
        if line.strip().startswith("leaf ="):
            return line.strip().split('=')[1].strip()
    return None

# Read input files
with open("bash_script_results/in/collected_unfaulted_sig.txt", "r") as f1, open("bash_script_results/extracted/extracted_unfaulted_results.txt", "r") as f2:
    sig_lines = f1.readlines()
    meta_lines = f2.readlines()

# Extract blocks by order
sig_blocks = extract_blocks(sig_lines, ["signature = "])
meta_blocks = extract_blocks(meta_lines, ["layer = ", "tree = ", "leaf = "])

# Ensure output directory exists
output_dir = "bash_script_results/in/all_ref_signatures"
os.makedirs(output_dir, exist_ok=True)

# Match blocks by order
for idx, (meta_block, sig_block) in enumerate(zip(meta_blocks, sig_blocks), 1):
    leaf_val = extract_leaf_value(meta_block)
    if not leaf_val:
        print(f"[Warning] Skipping count #{idx}: no 'leaf =' found.")
        continue

    out_path = os.path.join(output_dir, f"ref_signature_{leaf_val}.txt")

    with open(out_path, "w") as out_file:
        out_file.write(f"count = {idx}\n")
        out_file.writelines(meta_block)
        out_file.writelines(sig_block)

print("All reference signature files written successfully.")




def parse_and_find_lowest_avg(filename):
    pattern = re.compile(r"leaf(\d+)_bi_values\s*=\s*\[(.*?)\]")
    averages = {}

    with open(filename, 'r') as file:
        contents = file.read()

    matches = pattern.findall(contents)
    
    for leaf_id_str, value_str in matches:
        leaf_id = int(leaf_id_str)
        if 0 <= leaf_id <= 15:
            try:
                numbers = list(map(int, value_str.strip().split(',')))
                if numbers:
                    avg = sum(numbers) / len(numbers)
                    averages[leaf_id] = avg
            except ValueError:
                print(f"Warning: Could not parse numbers for leaf{leaf_id}")

    if not averages:
        print("No valid leaf{i}_bi_values found in the file.")
        return

    for leaf_id in sorted(averages):
        print(f"leaf{leaf_id}: average = {averages[leaf_id]:.4f}")

    lowest_leaf = min(averages, key=averages.get)
    print(f"\nLeaf with lowest average: leaf{lowest_leaf}")
    print(f"Average value: {averages[lowest_leaf]:.4f}")

    # Copy the reference signature file
    src = f"bash_script_results/in/all_ref_signatures/ref_signature_{lowest_leaf}.txt"
    dst = "bash_script_results/in/ref_signature.txt"
    try:
        shutil.copyfile(src, dst)
        print(f"\nCopied {src} to {dst}")
    except FileNotFoundError:
        print(f"Error: File {src} not found.")
    except Exception as e:
        print(f"Error copying file: {e}")

# Run the script with the hardcoded filename
parse_and_find_lowest_avg("bash_script_results/extracted/minimum_wots_sign.txt")