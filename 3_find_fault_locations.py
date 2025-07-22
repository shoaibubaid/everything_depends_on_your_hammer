import subprocess
import os

def run_command(cmd, cwd=None):
    """Run a shell command and print output in real-time."""
    print(f"Running: {cmd} (in {cwd or os.getcwd()})")
    subprocess.run(cmd, shell=True, check=True, cwd=cwd)

source = "signature.txt"
destination = "sphincsplus-attack-code-main/ref/in/collected_unfaulted_sig.txt"

open(destination, "w").close()

for i in range(1):
    run_command(f"python3 2_sign_generate.py")
    with open(source, "r") as src, open(destination, "a") as dst:
        dst.write(src.read())

# Directories
SPHINCSPLUS = ""
ATTACK_CODE = "sphincsplus-attack-code-main/ref"
HELPER = "find_fault_locations_helper"

# Arrays
# FUNC_NAME = [
#     "u32_to_bytes", "treehashx1", "prf_addr", "ull_to_bytes",
#     "wots_gen_leafx1", "merkle_sign", "hash_message", "thash"
# ]
# BASE_ADDRESS = [
#     "0x0000555555556f70", "0x0000555555557410", "0x0000555555562670", "0x0000555555556f30",
#     "0x0000555555556d80", "0x00005555555567b0", "0x0000555555562950", "0x0000555555562b50"
# ]
# MAX_ADDRESS_VALUE = [24, 610, 175, 47, 416, 260, 506, 341]

FUNC_NAME = ["treehashx8"]
BASE_ADDRESS = ["0x00005555555e13d0"]
MAX_ADDRESS_VALUE = [400]

# FUNC_NAME = ["u32_to_bytes"]
# BASE_ADDRESS = ["0x000055555555bdd0"]
# MAX_ADDRESS_VALUE = [8]

# MAX_ADDRESS_VALUE = [1115]



for i, func in enumerate(FUNC_NAME):
    print(f"\n===== Running for function: {func} =====")
    
    # Go to SPHINCSPLUS directory
    sphincsplus_path = os.path.abspath(SPHINCSPLUS)

    # run_command(f"python3 {HELPER}/1.py {BASE_ADDRESS[i]} {MAX_ADDRESS_VALUE[i]}", cwd=sphincsplus_path)
    # run_command(f"python3 {HELPER}/2.py", cwd=sphincsplus_path)
    # run_command(f"python3 {HELPER}/3.py {BASE_ADDRESS[i]}", cwd=sphincsplus_path)
    # run_command(f"python3 {HELPER}/4.py {BASE_ADDRESS[i]}", cwd=sphincsplus_path)
    # run_command(f"python3 {HELPER}/5.py", cwd=sphincsplus_path)
    # run_command(f"python3 {HELPER}/6.py", cwd=sphincsplus_path)

    # Copy results
    out_file = os.path.join(sphincsplus_path, "bash_script_results/outs_with_address.txt")
    attack_in = os.path.abspath(f"{ATTACK_CODE}/in/collected_faulty_sig.txt")
    run_command(f"cp {out_file} {attack_in}")

    # Run extract_faulted_sign_info
    attack_path = os.path.abspath(ATTACK_CODE)
    run_command("./extract_sign_info", cwd=attack_path)
    run_command("./extract_faulted_sign_info", cwd=attack_path)

    # Copy extracted results back
    extracted_file = os.path.join(attack_path, "extracted/extracted_faulted_results.txt")
    results_dir = os.path.join(sphincsplus_path, "bash_script_results")
    run_command(f"cp {extracted_file} {results_dir}")

    # Back to SPHINCSPLUS
    run_command(f"python3 {HELPER}/7.py", cwd=sphincsplus_path)
    run_command(f"python3 {HELPER}/8.py", cwd=sphincsplus_path)
    # run_command(f"mv bash_script_results bash_script_results_{func}", cwd=sphincsplus_path)
