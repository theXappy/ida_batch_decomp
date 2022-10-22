import os
import subprocess
import sys
from utils.merge import merge

IDA_TERMINAL_EXE = "C:\\Program Files\\IDA 7.7\\idat64.exe"

def delete_if_exists(file):
    if os.path.exists(file):
        os.remove(file)

def main():
    argv = sys.argv
    if len(argv) < 2:
        print("Usage: batch_decompile.py <file_to_decompile>")
        return
    file_path = argv[1]
    file_name = os.path.basename(file_path)
    
    vanilla_decomp_file_name = f"{file_name}_vanilla_decomp.c"
    exports_decomp_file_name = f"{file_name}_exports.c"
    final_decomp_file_name = f"{file_name}_final_decomp.c"
    
    delete_if_exists(vanilla_decomp_file_name)
    delete_if_exists(exports_decomp_file_name)
    delete_if_exists(final_decomp_file_name)
    
    print("STAGE 1: Vanilla decompile")
    o_flag = f"-Ohexrays:{vanilla_decomp_file_name[:-2]}:ALL"
    subprocess.run([IDA_TERMINAL_EXE, o_flag, "-A", file_path])

    print("STAGE 2: Exports decompile")
    s_flag = f"-Sutils\dump_exports.py"
    l_flag = f"-L{exports_decomp_file_name}"
    subprocess.run([IDA_TERMINAL_EXE, "-A", s_flag, l_flag, file_path])

    print("STAGE 3: Merge decompilations")
    merge(vanilla_decomp_file_name, exports_decomp_file_name, final_decomp_file_name)
    

if __name__ == "__main__":
    main()