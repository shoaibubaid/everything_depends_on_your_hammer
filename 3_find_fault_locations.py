import subprocess
import os
import platform
import shutil
import sys
import shlex
from configs import liboqs

in_folder = "bash_script_results/in"
extracted_folder = "bash_script_results/extracted"
out_folder = "bash_script_results/out"
# Create the folder if it doesn't exist
def create_folder(folder_path):
    if not os.path.exists(folder_path):
        os.makedirs(folder_path)
        print(f"Folder '{folder_path}' created.")
    else:
        print(f"Folder '{folder_path}' already exists.")

create_folder(in_folder)
create_folder(extracted_folder)
create_folder(out_folder)



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


source = "signature.txt"
# destination = "sphincsplus-attack-code-main/ref/in/collected_unfaulted_sig.txt"
unfaulted_signature = "bash_script_results/in/collected_unfaulted_sig.txt"
open(unfaulted_signature, "w").close()


for i in range(2):
    run_command(f"python3 2_sign_generate.py")
    with open(source, "r") as src, open(unfaulted_signature, "a") as dst:
        dst.write(src.read())

shutil.copy(source, unfaulted_signature)

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

# FUNC_NAME = ["treehashx8"]
# BASE_ADDRESS = ["0x00005555555e13d0+150"]
# BASE_ADDRESS = ["0x00005555555e1420"]
# MAX_ADDRESS_VALUE = [25]

# FUNC_NAME = ["u32_to_bytes"]
# BASE_ADDRESS = ["0x000055555555bdd0"]
# MAX_ADDRESS_VALUE = [8]


if liboqs == 1:
    FUNC_NAME = ["treehashx8"]
    BASE_ADDRESS = ["0x00005555555e13d0"]
# PQCLEAN_SPHINCSSHA2256FSIMPLE_AVX2_treehashx8
    # MAX_ADDRESS_VALUE = [30]
    MAX_ADDRESS_VALUE = [1115]
else:
    FUNC_NAME = ["treehashx1"]
    BASE_ADDRESS = ["0x0000555555556e20"]
    # MAX_ADDRESS_VALUE = [30]
    MAX_ADDRESS_VALUE = [633]


print(BASE_ADDRESS[0])
for i, func in enumerate(FUNC_NAME):
    print(f"\n===== Running for function: {func} =====")
    
    # Go to SPHINCSPLUS directory
    sphincsplus_path = os.path.abspath(SPHINCSPLUS)

    run_command(f"python3 {HELPER}/1.py {BASE_ADDRESS[i]} {MAX_ADDRESS_VALUE[i]} {liboqs}", cwd=sphincsplus_path)
    # run_command(f"python3 {HELPER}/2.py", cwd=sphincsplus_path)
    # run_command(f"python3 {HELPER}/3.py {BASE_ADDRESS[i]}", cwd=sphincsplus_path)
    # run_command(f"python3 {HELPER}/4.py {BASE_ADDRESS[i]}", cwd=sphincsplus_path)
    # run_command(f"python3 {HELPER}/5.py", cwd=sphincsplus_path)
    # run_command(f"python3 {HELPER}/6.py", cwd=sphincsplus_path)

    # Run extract_faulted_sign_info
    attack_path = os.path.abspath(ATTACK_CODE)
    run_command("./extract_sign_info", cwd=attack_path)
    run_command("./extract_faulted_sign_info", cwd=attack_path)

    # # Copy extracted results back
    # extracted_file = os.path.join(attack_path, "extracted/extracted_faulted_results.txt")
    # results_dir = os.path.join(sphincsplus_path, "bash_script_results")
    # # run_command(f"cp {extracted_file} {results_dir}")
    # shutil.copy(extracted_file, results_dir)


    # Back to SPHINCSPLUS
    run_command(f"python3 {HELPER}/2.py", cwd=sphincsplus_path)
    # run_command(f"python3 {HELPER}/8.py", cwd=sphincsplus_path)
    # run_command(f"mv bash_script_results bash_script_results_{func}", cwd=sphincsplus_path)
