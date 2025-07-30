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

source = "signature.txt"
unfaulted_signature = "bash_script_results/in/collected_unfaulted_sig.txt"
faulty_signature = "bash_script_results/in/collected_faulty_sig.txt"
open(unfaulted_signature, "w").close()
open(faulty_signature, "w").close()
for i in range(2):
    # Ensure directory exists
    print(f"Writing to {os.path.abspath(unfaulted_signature)}")
    run_command(f"python3 2_sign_generate.py")
    time.sleep(0.1)
    with open(source, "r") as src, open(unfaulted_signature, "a") as dst:
        dst.write(src.read())
