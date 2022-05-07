from __future__ import print_function

#
# Run instructions:
#   idat -Ldecompile.log -Sdecompile_entry_points.py -c file
# from
# https://hex-rays.com/blog/igor-tip-of-the-week-08-batch-mode-under-the-hood/
#

import ida_ida
import ida_auto
import ida_loader
import ida_hexrays
import ida_idp
import ida_entry
from idautils import *
from idaapi import *

# SHAI: Read address reference by a pointer
# Good reference:
# https://gist.github.com/icecr4ck/7a7af3277787c794c66965517199fc9c
def read_ptr(ea):
  if get_inf_structure().is_64bit():
    return get_qword(ea)
  return get_dword(ea)

def my_pointer_size():
    return 8 if  get_inf_structure().is_64bit() else 4

def main():
    print("// Waiting for autoanalysis...") 
    ida_auto.auto_wait()

    # SHAI: "Names" iterates over everything(?) that IDA gave a name to. Most importantly
    # for use - string constants.
    # Also lucky for us, IDA prefixes the names of Apple's CFString it resolves to start with "cfstr_".
    resolved_strings = {}
    for ea, name in Names():
        # Looking specificly for CFString
        if name[:6] == "cfstr_":
            # Parse the CFString stracture (get the character array's index + the length)
            string_content = idc.get_strlit_contents(read_ptr(ea + (my_pointer_size() * 2)), -1, idc.STRTYPE_C)
            
            # DUMP String's internal IDA variable name
            # print(nstr)

            # Saving IDA's string var name and content
            resolved_strings[ea] = (name, string_content)

    #
    # @@@ DUMP STRINGS
    #
    print("//-------------------------------------------------------------------------")
    print("// Strings")
    print("char **all_strings = {")
    for s in Strings():
        string_content = ida_bytes.get_strlit_contents(s.ea, s.length, s.strtype)
        escaped = string_content.replace("\\","\\\\").replace("\"","\\\"")
        if escaped == string_content:
            print('\t"%s", // Address = %x , Length = %d , Type = %d' % (string_content, s.ea, s.length, s.strtype))
        else:
            print('\t"%s", // Unescaped = %s Address = %x , Length = %d , Type = %d' % (escaped, string_content, s.ea, s.length, s.strtype))
    print("};")
    print("")

    print("//-------------------------------------------------------------------------")
    print("// Exports")
    #
    # SHAI: Listing exports
    #
    # Good reference:
    # https://github.com/EiNSTeiN-/idapython/blob/a03c7a511715ad63a2df068b82fe82eafe175fa2/Scripts/ImportExportViewer.py
    for exp_i, exp_ord, exp_ea, exp_name in list(Entries()):
        # EXPORTED VAR's address ---->>> exp_ea
        #print(exp_ea, exp_name)
        content_ea = read_ptr(exp_ea)
        found = content_ea in resolved_strings
        if found:
            value = resolved_strings[content_ea]
            ida_variable = value[0]
            string_content = value[1]
            print('char* %s = "%s"; // IDA Variable: %s' % (exp_name, string_content, ida_variable))
        else:
            print('void* %s;' % exp_name)
        
    if idaapi.cvar.batch:
        print("// All done, exiting.")
        ida_pro.qexit(0)


main()
