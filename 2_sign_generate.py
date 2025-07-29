import subprocess
from configs import liboqs

# Command to run
if(liboqs == 1):
    print("running liboqs implementation")
    command = "./liboqs_signature_gen/bin/sign_heap_v2"
else:
    command = "./sphincsplus-standard/ref/sign_sha2_256f_v2"
# Run the command
subprocess.run(command, shell=True)
