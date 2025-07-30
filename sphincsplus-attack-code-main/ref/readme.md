# Attack Code

## steps to follow
--------
0. before going to do anything "make all" on the terminal
1. collect the public key and paste it into the file "in/collected_pubkey.txt".
2. put the unfaulted signatures into the file "in/collected_unfaulted_sig.txt"
3. put the faulted signatures into the file "in/collected_faulted_sig.txt" 
4. while in the ref folder run "./extract_sign_info"
5. then run "python3 extract_min_sk.py"
6. paste any unfaulted signature with its tree and leaf into the file "in/ref_signature.txt"
7. now run the command "./forge"
8. just for extra verification, run "./sign_verify"

-----

# Info about all the files

the files which are of our contributions is
1. <b> wots_forge.c, wots_forge.h </b> -  this has all the functions that helps in extracting bi values, doing hashes and signing the forged signature
2. extract_sign_info.c - this is the function that takes the collected signs ans processes them to find out the bi values
3. extras.c, extras.h - the functions in these files are designed with inly purpose to find the randomness that helps in finding bi values more than the bi values we have extracted.
4. fprintbstr.c, fprintbstr.h - the functions in these files are already provided by the SPHINCSPLUS team. I am just using it for every file. These were just functions for a single file.
5. forge.c - the final forging file that forges the messages.
6. sign_verify - just created to verify the sign one more time. depreicated.
7. extract_min_sk.py, divide_sign_to_layers.py are python helper scripts to find min bi values.

some info about folders:
1. in - has all the input files
2. extracted - has all the extracted data files
3. out - not processed yet. need some processing
