from keystone import *
from capstone import *
from git import Repo, Commit
from io import BytesIO
from typing import BinaryIO
from elftools.elf.elffile import ELFFile
import struct, os


base = 0x81000000

def to_c_array(b: bytes):
    return "{"+", ".join([f"0x{a:02x}" for a in b])+"}"

class Patch:
    def __init__(self, addr: int, module_nid: int, syms: dict[str,int]):
        self.addr = addr
        self.module_nid = module_nid
        self.syms = syms
        self.versions = []
        self.ks = Ks(KS_ARCH_ARM, KS_MODE_THUMB)
        self.ks.sym_resolver = self.sym_resolver
    
    def patch_name(self):
        return f"patch_0x{self.addr:08x}_0x{self.syms['sceAppMgrIsNonGameProgram']:08x}"

    def sym_resolver(self, name: bytes, value):
        name: str = name.decode("utf8")
        addr = self.syms.get(name)
        if addr is None:
            print("missing symbol", name)
            return False
        if addr < base:
            addr += base
        value[0] = addr
        return True

    def make(self):
        return to_c_array(self.ks.asm(
            "ldr.w r4, [sp, #0xbc]\n" # load serverNameBuf from stack
            
            # get length
            "mov r0, r4\n"
            "movs r1, #0xff\n"
            "blx sceClibStrnlen\n"
            "mov r3, r0\n"
            
            # check if need to rewrite, how long
            "movw r0, #0x0\n" # out buf is 0 because only want length
            "mov r1, r4\n" # serverNameBuf
            "movw r2, #0x1234\n" # identifier to the hook
            "blx sceAppMgrIsNonGameProgram\n" # call the hook
            "cmp r0, #0\n" # check if its < 0
            "ble patch_end\n" # if its less than 0 no need to rewrite, skip the patch
 
            # allocate new buffer
            "mov r1, r0\n" # store the returned length in r1
            "ldr.w r0, [r11, #0xb0]\n" # load template->allocator.alloc
            "bl call_alloc\n" # allocate the returned length (r1) with the allocator in r0
            "str.w r0, [sp, #0xbc]\n" # store the new buffer address in the serverNameBuf stack location

            # write the modified domain name to the buffer
            "mov r1, r4\n" # serverNameBuf
            "movw r2, #0x1234\n" # identifier to the hook
            "blx sceAppMgrIsNonGameProgram\n" # call the hook (r0 = buffer, r1 = serverNameBuf, r2 = identifier)

            # free old buffer
            "ldr.w r0, [r11, 0xb4]\n" # load template->allocator.free
            "mov r1, r4\n" # load serverNameBuf to r1
            "bl call_dealloc\n" # deallocate the old server name

            "b patch_end\n", # skip the to the end of the patch
            self.addr, True
        )[0])

    def __hash__(self) -> int:
        return self.addr*hash(frozenset(self.syms.items()))


ks = Ks(KS_ARCH_ARM, KS_MODE_THUMB)
cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB)

def insn_b_to_addr(insn: CsInsn):
    return int(insn.op_str[3:], 16)

# finds the start of where to patch,
# where the end of the if block
# and the alloc, free functions to use on the servername are,
# does this with simple byte offsets from the known string
# this works fine as sony hasnt changed the module basically at all in recent versions  
def find_patch_location(seg: bytes):
    SceLibHttp_str_location = base+seg.find(b"SceLibHttp_%s")
    low = SceLibHttp_str_location & 0xffff

    # find patch_start
    mov = seg.find(ks.asm(f"movw r2, #0x{low:x}", 0, True)[0])
    patch_start = base + (mov-52)

    # find patch_end
    dis = list(cs.disasm(seg[mov-52:mov], mov-52, 3))
    # make sure the offset is correct
    assert dis[0].mnemonic == "blx"
    assert dis[1].mnemonic == "cmp"
    assert dis[2].mnemonic == "bne"
    patch_end = insn_b_to_addr(dis[2])

    # find call_alloc
    call_to_alloc = patch_end + 52
    dis2 = list(cs.disasm(seg[call_to_alloc:call_to_alloc+4], call_to_alloc, 1))
    assert dis2[0].mnemonic == "bl"
    call_alloc = insn_b_to_addr(dis2[0])

    # find call_dealloc
    call_to_dealloc = call_to_alloc + 74
    dis3 = list(cs.disasm(seg[call_to_dealloc:call_to_dealloc+4], call_to_dealloc, 1))
    assert dis3[0].mnemonic == "bl"
    call_dealloc = insn_b_to_addr(dis3[0])

    return patch_start, patch_end, call_alloc, call_dealloc


class Struct:
    def __init__(self, data: bytes):
        format, names = self._format()
        tup = struct.unpack(format, data[:self.size()])
        for name, value in zip(names, tup):
            setattr(self, name, value)

    @classmethod
    def _format(cls):
        format = ""
        names = []
        for key, _ in cls.__annotations__.items():
            fmt = getattr(cls, key)
            format += fmt
            names.append(key)
        return format, names
    
    @classmethod
    def size(cls):
        return struct.calcsize(cls._format()[0])

class SceModuleInfo(Struct):
    attributes: int = "b"
    version: int = "h"
    module_name: str = "27s"
    type: int = "b"
    gp_value: int = "I"
    exportsStart: int = "I"
    exportsEnd: int = "I"
    importsTop: int = "I"
    importsEnd: int = "I"
    module_nid: int = "I"
    tlsStart: int = "I"
    tlsFileSize: int = "I"
    tlsMemSize: int = "I"
    module_start: int = "I"
    module_stop: int = "I"
    exidx_top: int = "I"
    exidx_end: int = "I"
    extab_start: int = "I"
    extab_end: int = "I"

class SceModuleImports(Struct):
    size_: int = "h"
    version: int = "h"
    attribute: int = "h"
    num_functions: int = "h"
    num_vars: int = "h"
    num_tls_vars: int = "h"
    reserved1: int = "h"
    library_nid: int = "I"
    library_name: int = "I"
    reserved2: int = "I"
    func_nid_table: int = "I"
    func_entry_table: int = "I"
    var_nid_table: int = "I"
    var_entry_table: int = "I"
    tls_nid_table: int = "I"
    tls_entry_table: int = "I"

def get_nids(seg_data: bytes, module_info: SceModuleInfo):
    importsData = seg_data[module_info.importsTop:module_info.importsEnd]
    nids = {}
    off = 0
    while off < len(importsData):
        size = int.from_bytes(importsData[off:off+2], "little")
        assert size == 0x34
        
        imports = SceModuleImports(importsData[off:])
        off += size
        
        entry_table_location = imports.func_entry_table-base
        func_entry_table = seg_data[entry_table_location:entry_table_location+imports.num_functions*4]
        nid_table_location = imports.func_nid_table-base
        func_nid_table = seg_data[nid_table_location:nid_table_location+imports.num_functions*4]

        for i in range(imports.num_functions):
            nid = int.from_bytes(func_nid_table[i*4:(i+1)*4], "little")
            func = int.from_bytes(func_entry_table[i*4:(i+1)*4], "little")
            nids[nid] = func
    return nids


# automatically finds the patch location, where the SceIoOpen stub is
def find_patch(elf: ELFFile):
    entry: int = elf.header.e_entry
    segment_num = (entry >> 30) & 0x3
    info_offset = entry & 0x3fffffff
    seg = elf.get_segment(segment_num)
    seg_data: bytes = seg.data()
    
    module_info = SceModuleInfo(seg_data[info_offset:])
    nids = get_nids(seg_data, module_info)

    location, patch_end, call_alloc, call_dealloc = find_patch_location(seg_data)
    return Patch(location, module_info.module_nid, {
        "sceAppMgrIsNonGameProgram": nids[0x5F22E192],
        "sceClibStrnlen": nids[0xAC595E68],
        "patch_end": patch_end,
        "call_alloc": call_alloc,
        "call_dealloc": call_dealloc
    })


# versions to look at
versions = [
    "360-CEX", "360-DEX", "360-QAF", "360-TOOL",
    "361-CEX", "361-DEX", "361-TOOL",
    "363-CEX", "363-DEX", "363-QAF",  "363-TOOL",
    "365-CEX", "365-DEX", "365-TOOL",
    "367-CEX", "367-DEX", "367-TOOL",
    "368-CEX", "368-DEX", "368-TOOL",
    "369-CEX",
    "370-CEX",
    "371-CEX", "371-TOOL",
    "372-CEX", "372-DEX", "372-QAF",
    "373-CEX", "373-TOOL",
    "374-CEX",   
]

def add_all_patches():
    # find patches in every version
    auto_patches: list[Patch] = []
    def add_patch(r: BinaryIO, version: str):
        elf = ELFFile(r)
        patch = find_patch(elf)
        patch.versions.append(version)
        auto_patches.append(patch)

    psvita_elfs = Repo("psvita-elfs")
    for version in versions:
        head = psvita_elfs.heads[version]
        commit: Commit = head.commit
        file_contents = psvita_elfs.git.show('{}:{}'.format(commit.hexsha, "vs0/sys/external/libhttp.suprx.elf")).encode("utf8", "surrogateescape")
        add_patch(BytesIO(file_contents), version)
    psvita_elfs.close()

    libhttp_itls = "lhttp.suprx.elf"
    if os.path.exists(libhttp_itls):
        with open(libhttp_itls, "rb") as f:
            add_patch(f, "itls")
    return auto_patches


def filter_patches(auto_patches: list[Patch]):
    # patches by module_nid
    patches: dict[int, Patch] = {}
    for patch in auto_patches:
        existing = patches.get(patch.module_nid)
        if existing:
            assert hash(patch) == hash(existing)
            existing.versions.append(patch.versions[0])
        else:
            patches[patch.module_nid] = patch

    # patches that are not the same address and sceioopen 
    patches_unique: list[Patch] = []
    for patch in patches.values():
        exists = len([p for p in patches_unique if hash(p) == hash(patch)]) > 0
        if not exists:
            patches_unique.append(patch)

    # put all module_nids that this patch works for in the patch
    for patch in patches_unique:
        matches = [a for a in auto_patches if hash(patch) == hash(a)]
        patch.module_nid = set([match.module_nid for match in matches])

    return patches_unique, patches


# write header with the patch data and switch to select it
def write_inject_h(patches_unique: list[Patch], patches: dict[int, Patch]):
    with open("inject-http.h", "w") as f:
        for patch in patches_unique:
            f.write(f"const char {patch.patch_name()}[] = {patch.make()};\n\n")

        f.write("\nint get_servername_patch(const char** patch, int* offset, int* patch_size, unsigned int module_nid) {\n")
        f.write("\tswitch(module_nid) {\n")

        for patch in patches_unique:
            for module_nid in patch.module_nid:
                p = patches[module_nid]
                f.write(f"\tcase 0x{module_nid:08x}: // {', '.join(p.versions)}\n")

            f.write(f"\t\t*patch = {patch.patch_name()};\n")
            f.write(f"\t\t*patch_size = sizeof({patch.patch_name()});\n")
            f.write(f"\t\t*offset = 0x{patch.addr-base:x};\n")
            f.write("\t\tbreak;\n")
        
        f.write("\tdefault:\n\t\treturn -1;\n")

        f.write("\t}\n\treturn 0;\n")
        f.write("}\n")


def main():
    auto_patches = add_all_patches()
    patches_unique, patches = filter_patches(auto_patches)
    write_inject_h(patches_unique, patches)


main()
