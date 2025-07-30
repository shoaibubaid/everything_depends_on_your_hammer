import os

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
with open("in/collected_unfaulted_sig.txt", "r") as f1, open("extracted/extracted_unfaulted_results.txt", "r") as f2:
    sig_lines = f1.readlines()
    meta_lines = f2.readlines()

# Extract blocks by order
sig_blocks = extract_blocks(sig_lines, ["signature = "])
meta_blocks = extract_blocks(meta_lines, ["layer = ", "tree = ", "leaf = "])

# Ensure output directory exists
output_dir = "in/all_ref_signatures"
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
