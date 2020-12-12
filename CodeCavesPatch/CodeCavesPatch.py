import sys
import pefile
from struct import pack


def help():
    print("usage: python3 <PePath>")

def get_pe_bit(pe_file):
    if pe_file.FILE_HEADER.Machine == 0x014c:
        is64 = False
    elif pe_file.FILE_HEADER.Machine ==0x0200 or pe_file.FILE_HEADER.Machine == 0x8664:
        is64 =True
    else:
        print("[-]unknow the format of this pe file")
        sys.exit()

    return is64

def get_patch_stub(pe_file,func_offset):


    stub = (
        b"\x4d"+
		b"\x5A" +#pop edx
		b"\x45" +#inc ebp
		b"\x52" +#push edx
		b"\xE8\x00\x00\x00\x00" +#call <next_line>
		b"\x5B" +# pop ebx
		b"\x48\x83\xEB\x09" +# sub ebx,9
		b"\x53" +# push ebx (Image Base)
		b"\x48\x81\xC3" +# add ebx,
		pack("<I",func_offset) +# value
		b"\xFF\xD3" +# call ebp
		b"\xc3" # ret
                );
    return stub;

def patch_pe(pe_path):
    try:
        pe_file =pefile.PE(pe_path)
    except e:
        print(str(e))
        help()
        sys.exit()

    patch_size = 0
    patch_location = 0

    if get_pe_bit(pe_file):
        reflective_stub = open('stub64.bin','rb').read()
    else:
        reflective_stub = open('stub32.bin','rb').read()
    
    cave_size=len(reflective_stub);

    for section in pe_file.sections:
        section_cave_size = section.SizeOfRawData - section.Misc_VirtualSize
        section_cave_location  =section.Misc_VirtualSize + section.PointerToRawData
        print("[+] looking for a codecave in %s sizeof %d  offset of %x" % (section.Name,section_cave_size,section_cave_location))
        if section_cave_size > cave_size:
            patch_size=section_cave_size
            patch_location = section_cave_location
            break

        if patch_size ==0:
            print("[-] not enough size code cvae found ")
            help()
            sys.exit()

    patch_stub = get_patch_stub(pe_file,patch_location)

    filearray = open(pe_path,'rb').read()
    print("[+] loaded nameof %s"% (pe_path))

    patch_pe_file = patch_stub + filearray[len(patch_stub):patch_location] + reflective_stub +filearray[patch_location+len(reflective_stub):]
    print("[+] patched offset %x" % (section_cave_location))

    patch_pe_name = "patch-" +pe_path
    open(patch_pe_name,'wb').write(patch_pe_file)
    print("[+] wrote nameof %s"% (patch_pe_name))
            
if __name__ == '__main__':
    a = len(sys.argv)
    if len(sys.argv) != 2:
        help()
        sys.exit(0);
    pe_path = sys.argv[1]
    pe_path= "runshc32.exe"
    patch_pe(pe_path)
