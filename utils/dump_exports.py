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
import ida_pro
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


def init_hexrays():
    ALL_DECOMPILERS = {
        ida_idp.PLFM_386: "hexrays",
        ida_idp.PLFM_ARM: "hexarm",
        ida_idp.PLFM_PPC: "hexppc",
        ida_idp.PLFM_MIPS: "hexmips",
    }
    cpu = ida_idp.ph.id
    decompiler = ALL_DECOMPILERS.get(cpu, None)
    if not decompiler:
        print("No known decompilers for architecture with ID: %d" % ida_idp.ph.id)
        return False
    if ida_ida.inf_is_64bit():
        if cpu == ida_idp.PLFM_386:
            decompiler = "hexx64"
        else:
            decompiler += "64"
    if ida_loader.load_plugin(decompiler) and ida_hexrays.init_hexrays_plugin():
        return True
    else:
        print('Couldn\'t load or initialize decompiler: "%s"' % decompiler)
        return False


def main():
    print("// Initializing...") 
    init_hexrays()
    
    print("// Waiting for autoanalysis...") 
    if hasattr(idaapi, "auto_wait"): # IDA 7.4+
        idaapi.auto_wait()
    else:
        idaapi.autoWait() # Old IDA

    # SHAI: "Names" iterates over everything(?) that IDA gave a name to. Most importantly
    # for us - string constants.
    # Also, lucky for us, IDA prefixes the names of Apple's CFString it resolves to start with "cfstr_".
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
        escaped = string_content.decode().replace("\\","\\\\").replace("\"","\\\"")
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
    
    
    
    
    '''
    print("//-------------------------------------------------------------------------")
    print("// Methods"
    # Reference:
    # https://github.com/Cerberus-bytes/DragonBreath/blob/030650c2b4ad69b35df34008ed7f2c53e5a35776/src/Decompilers/IDA/DragonBreath-WriteFile.py
    
    
    ida_path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
    c_path = "%s.c" % ida_path
    
    
    print("Decompile Many...")
    decompile_many(
        "poop.c",
        None,
        ida_hexrays.VDRUN_NEWFILE|
        ida_hexrays.VDRUN_SILENT|
        ida_hexrays.VDRUN_MAYSTOP)
    print("Decompile Many... -- DONE")
    '''
    
    
    

    # Old code to print methods names/ method bodies into current file
    '''
    for ea in Functions():
        functionName = get_func_name(ea)
        print(functionName)
        try:
            decomp = decompile(ea)
            print(decomp)
        except Exception as ex:
            print(ex)
    '''    
    
    if idaapi.cvar.batch:
        print("// All done, exiting.")
        ida_pro.qexit(0)


main()
