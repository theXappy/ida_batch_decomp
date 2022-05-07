import sys

def merge(main_decomp_path, exports_decomp_path, out_file_path):
    main_decomp = open(main_decomp_path, "r")
    exports_decomp = open(exports_decomp_path, "r")
    out_file = open(out_file_path, "w")

    while True:
        line = exports_decomp.readline()
        if not line or "// Waiting for autoanalysis..." in line:
            break

    while True:
        line = main_decomp.readline()
        out_file.write(line)
        if "#include <defs.h>" in line:
            # Insert exports into the file
            while True:
                line = exports_decomp.readline()
                if "// All done, exiting." in line:
                    break
                if not line:
                    print(f"ERROR: Reached end of {exports_decomp_path} but didn't find end indictor from the python plugin script")
                    return
                out_file.write(line)
            
            # Add the rest of the file
            out_file.writelines(main_decomp)
            break
        # if line is empty
        # end of file is reached
        if not line:
            print(f"ERROR: Reached end of {main_decomp_path} but didn't find '#include <defs.h>' where we wanted to insert the exported decomp data")
            break

    print("Flushing & closing")
    out_file.flush()
    out_file.close()
    print(f"Done. Output path: {out_file_path}")


def main():
    argv = sys.argv
    if len(argv) < 4:
        print("Usage: merge.py <main_decomp.c> <exports_decomp.c> <output.c>")
        return
    main_decomp_path = argv[1]
    exports_decomp_path = argv[2]
    out_file_path = argv[3]
    merge(main_decomp_path, exports_decomp_path, out_file_path)


if __name__ == "__main__":
    main()