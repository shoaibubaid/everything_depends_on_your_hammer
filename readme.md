# Everything Depends on Your Hammer
This repo contains the artifact of the paper "Everything Depends on Your Hammer: A Systematic Rowhammer Attack Exploration on SPHINCS+".
In this repo, we generate simulate the process of generating both valid and faulty signatures and extract values such that a signature can be forged.
## System Requirements
- **liboqs library** (must be installed and configured)
- **GDB** (GNU Debugger)
- **Python 3.x**


## SPHINCS+ Implementations
This repository contains **two implementations of SPHINCS+:**
1. **liboqs library implementation** located in `liboqs_signature_gen`
2. **Standard SPHINCS+ repository** located in `sphincsplus-standard`

- This implementation consists of SHA2 hash function with SPHINCS+-256f configuration. However, it works for all the variants of SPHINCS+
- reference valid and faulty signatures are given in `bash_script_results_liboqs` and `bash_script_results_standard`. Just copy the contents into the `bash_script_results` and copy the keys into `key.txt` and `collected_pubkey.txt`
---

## Compilation
To compile the binaries, navigate to the required library directory and run:
```bash
cd liboqs_signature_gen
make all
```
and

```bash
cd sphincsplus-standard/ref
make all
```
and

```bash
cd sphincsplus-attack-code-main/ref
make all
```

## Pre-requisites

Before proceeding further:

1. **Select the Implementation**  
   Set which SPHINCS+ implementation you want to use in **`configs.py`**:
   - Use `liboqs=1` for the **liboqs implementation**.
   - Use `liboqs=0` for the **standard SPHINCS+ implementation**.

2. **Function Disassembly using GDB**  
   Disassemble the following functions using **GDB** :
   - `PQCLEAN_SPHINCSSHA2256FSIMPLE_AVX2_treehashx8`  
     (from **liboqs library – `bin/sign_heap`**)
   - `SPX_treehashx1`  
     (from **standard SPHINCS+ – `sphincsplus-standard/ref/sign_sha2_256f`**)

    **Paste the Base Address and Offset** in **`3_find_fault_locations.py`**,   
   Paste the **initial address location** of the respective function into `BASE_ADDRESS`  
   and set the **maximum offset value** in `MAX_ADDRESS_VALUE`.  

   **Note:** Run **GDB** while being in the **root directory** of this repository.
3. Disassemble the another set of following functions using **GDB**  :
   - `PQCLEAN_SPHINCSSHA2256FSIMPLE_AVX2_treehashx8`  
     (from **liboqs library – `bin/sign_heap_v2`**)
   - `SPX_treehashx1`  
     (from **standard SPHINCS+ – `sphincsplus-standard/ref/sign_sha2_256f_v2`**)

    **Paste the Base Address and Offset** in **`5_collect_fault_sigs.py`**,   
   Paste the **initial address location** of the respective function into `BASE_ADDRESS`  
   and set the **maximum offset value** in `MAX_ADDRESS_VALUE`.  

   **Note:** These are the _v2 functions which have slight changes

- I have pasted the address and offset as per my device, change if necassary

---
## Running the code

1. **Generate the key**
    - Generate a key using 
    ```bash
    python3 1_key_generate.py
    ```
5. **Generate the signature**
    - Generate a signature using 
    ```bash
    python3 2_sign_generate.py
    ```
6. **Find the locations that give exploitable faults**
    - In this step, we find the locations that can generate exploitable fault locations
    ```bash
    python3 3_find_fault_locations.py
    ```
    - This generates `useful_addresses.csv` that consists of all exploitable offsets. 
    - Basically, it flips each of the 8 bits one at a time for all the address locations. First, we check if the process continues till the end. If yes, we check if the generated signature is invalid or not. If the signature is invalid, which is what we want, we check if we can exploit the signature from that location. 

6. **Collect valid signatures**
    - In this step, we collect valid signatures for extraction purposes
    ```bash
    python3 4_collect_valid_sigs.py
    ```
6. **Collect faulty signatures**
    - In this step, we collect the actual faulty signatures
    ```bash
    python3 5_collect_fault_sigs.py <no.of fault locations required>
    ```
    - Try to collect more for easy and faster attack
6. **Extract_min_sk**
    - Here we extract the minimum WOTS+ that we can get
    ```bash
    python3 6_extract_min_sk.py
    ```
    - This extracts the most secret values into the file `bash_script_results/extracted/minimum_wots_sign.txt`
6. **Forge**
    - As a final step, we forge the message. enter the message details in `message_to_forge.txt` and run 
    ```bash
    python3 7_forge.py
    ```
    - This generates a forged signature and stores it into `bash_script_results out/forged_signature.txt`
