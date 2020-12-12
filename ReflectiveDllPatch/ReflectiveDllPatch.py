import sys
import pefile
from struct import pack

def help():
    print("usage: python3 <DllPath> <FuncName>\n")

def get_func_offset(pe_file,func_name):
    if hasattr(pe_file,'DIRECTORY_ENTRY_EXPORT'):
        for export in pe_file.DIRECTORY_ENTRY_EXPORT.symbols:
            if func_name in str(export.name):
                func_rva = export.address
                break

    if func_rva == 0:
        help()
        print("[-] not found function offset in file")
        sys.exit(0)

    offset_va = func_rva - pe_file.get_section_by_rva(func_rva).VirtualAddress
    func_file_offset = offset_va + pe_file.get_section_by_rva(func_rva).PointerToRawData
    func_file_offset -= 9 
    
    return bytes(pack("<I",func_file_offset))

def get_patch_stub(pe_file,func_offset):

    if pe_file.FILE_HEADER.Machine == 0x014c:
        is64 = False
    elif pe_file.FILE_HEADER.Machine ==0x0200 or pe_file.FILE_HEADER.Machine == 0x8664:
        is64 =True
    else:
        print("[-]unknow the format of this pe file")
        sys.exit()

    if is64:
                stub =(
                b"\x4D\x5A"
                b"\x41\x52"
                b"\xe8\x00\x00\x00\x00"
                b"\x5b"
                b"\x48\x81\xC3" + func_offset +
                b"\x55"
                b"\x48\x89\xE5"
                b"\xFF\xD3"
                );

    else:
                stub = (
                b"\x4D"
                b"\x5A"
                b"\x45"
                b"\x52"
                b"\xE8\x00\x00\x00\x00"
                b"\x5A"
                b"\x81\xC2" + func_offset +
                b"\x55"
                b"\x8B\xEC"
                b"\xFF\xD2"
                );
    return stub;

def patch_dll(pe_path,func_name):
    try:
        pe_file =pefile.PE(pe_path)
    except e:
        print(str(e))
        help()
        sys.exit()

    
    func_offset = get_func_offset(pe_file,func_name)
    patch_stub = get_patch_stub(pe_file,func_offset)
    

    filearray = open(pe_path,'rb').read()
    print("[+] loaded nameof %s"% (pe_path))

    patch_pe_file = patch_stub + filearray[len(patch_stub):]
    print("[+] patched offset %s" % (func_offset.hex()))

    patch_pe_name = "patch-" +pe_path
    open(patch_pe_name,'wb').write(patch_pe_file)
    print("[+] wrote nameof %s"% (patch_pe_name))

if __name__ == '__main__':
    a = len(sys.argv)
    if len(sys.argv) != 3:
        help()
        sys.exit(0);
    pe_path = sys.argv[1]
    func_name =  sys.argv[2]
    patch_dll(pe_path,func_name)
