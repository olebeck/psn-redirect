from keystone import *
from capstone import *
import struct
from elftools.elf.elffile import ELFFile
from typing import BinaryIO
from io import BytesIO
from collections import defaultdict
import requests


BASE = 0x81000000
s = requests.Session()

def git_contents(branch, name):
    r = s.get(f"https://github.com/LiEnby/psvita-elfs/raw/refs/heads/{branch}/{name}")
    r.raise_for_status()
    return BytesIO(r.content)

def insn_b_to_addr(insn: CsInsn):
    return int(insn.op_str[3:], 16)

def to_c_array(b: bytes):
    return "{"+", ".join([f"0x{a:02x}" for a in b])+"}"

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

class SceModuleImports2(Struct):
    size_: int = "h"
    version: int = "h"
    attribute: int = "h"
    num_functions: int = "h"
    num_vars: int = "h"
    library_nid: int = "I"
    library_name: int = "I"
    func_nid_table: int = "I"
    func_entry_table: int = "I"
    var_nid_table: int = "I"
    var_entry_table: int = "I"


def get_nids(seg_data: bytes, module_info: SceModuleInfo):
    importsData = seg_data[module_info.importsTop:module_info.importsEnd]
    nids = {}
    off = 0
    while off < len(importsData):
        size = int.from_bytes(importsData[off:off+2], "little")
        if size == 0x24:
            imports = SceModuleImports2(importsData[off:])
        elif size == 0x34:
            imports = SceModuleImports(importsData[off:])
        else:
            raise "imports wrong size"
        off += size
        
        entry_table_location = imports.func_entry_table-BASE
        func_entry_table = seg_data[entry_table_location:entry_table_location+imports.num_functions*4]
        nid_table_location = imports.func_nid_table-BASE
        func_nid_table = seg_data[nid_table_location:nid_table_location+imports.num_functions*4]

        for i in range(imports.num_functions):
            nid = int.from_bytes(func_nid_table[i*4:(i+1)*4], "little")
            func = int.from_bytes(func_entry_table[i*4:(i+1)*4], "little")
            nids[nid] = func
    return nids



class Patch:
    _filename: str = ""
    _extra_files: list[str] = []
    _code: str = ""
    _imports: dict[str, int] = {}

    def patch_name(self) -> str:
        raise "unimplemented"
    
    @staticmethod
    def find(data: bytes) -> tuple[int, dict[str, int]]:
        raise "unimplemented"


    def __init__(self, addr: int, module_info: SceModuleInfo, syms: dict[str,int]):
        self.addr = addr
        self.module_info = module_info
        self.module_nids = set()
        self.syms = syms
        self.versions = []
        self.ks = Ks(KS_ARCH_ARM, KS_MODE_THUMB)
        self.ks.sym_resolver = self._sym_resolver

    @classmethod
    def create(cls, r: BinaryIO):
        elf = ELFFile(r)
        entry: int = elf.header.e_entry
        segment_num = (entry >> 30) & 0x3
        info_offset = entry & 0x3fffffff
        seg = elf.get_segment(segment_num)
        seg_data: bytes = seg.data()
        
        module_info = SceModuleInfo(seg_data[info_offset:])
        nids = get_nids(seg_data, module_info)
        syms = {k: nids[v] for k, v in cls._imports.items()}

        addr, extra_syms = cls.find(seg_data)
        syms.update(extra_syms)

        obj = cls(addr, module_info, syms)
        return obj

    def _sym_resolver(self, name: bytes, value):
        name: str = name.decode("utf8")
        addr = self.syms.get(name)
        if addr is None:
            print("missing symbol", name)
            return False
        if addr < BASE:
            print("wrong base", name)
            return False
        value[0] = addr
        return True

    def make(self):
        data, _ = self.ks.asm(self._code, self.addr, True)
        return to_c_array(data)

    def __hash__(self) -> int:
        return self.addr*hash(frozenset(self.syms.items()))



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

def generate_all_patches(*classes: Patch) -> str:
    all_patches: dict[str, list[Patch]] = defaultdict(list)
    
    # create patches for each firmware version
    for version in versions:
        for cls in classes:
            print(version, cls.__name__)
            data = git_contents(version, cls._filename)
            patch = cls.create(data)
            patch.versions.append(version)
            all_patches[cls.__name__].append(patch)

    # create patches for extra elfs
    for cls in classes:
        for filename in cls._extra_files:
            with open(filename, "rb") as f:
                patch = cls.create(f)
                patch.versions.append(filename.split(".")[0])
                all_patches[cls.__name__].append(patch)

    # filtering

    # patches for the same nid
    # asserts that same module nid can all use the same patch
    patches_by_nid: dict[str, dict[int, Patch]] = defaultdict(dict)
    for name, patches in all_patches.items():
        by_nid = patches_by_nid[name]
        for patch in patches:
            existing = by_nid.get(patch.module_info.module_nid)
            if existing:
                assert hash(patch) == hash(existing)
                existing.versions.append(patch.versions[0])
            else:
                by_nid[patch.module_info.module_nid] = patch

    # filters for patches that are not the same address and symbols
    patches_unique: dict[str,list[Patch]] = defaultdict(list)
    for name, patches in patches_by_nid.items():
        for patch in patches.values():
            exists = len([p for p in patches_unique[name] if hash(p) == hash(patch)]) > 0
            if not exists:
                matches = [a for a in all_patches[name] if hash(patch) == hash(a)]
                patch.module_nids = set([match.module_info.module_nid for match in matches])
                patches_unique[name].append(patch)


    # generate code

    out = ""
    t = 0
    def wo(s: str, i: int = 0):
        nonlocal out
        nonlocal t
        if len(s)>0 and s[-1] == "}":
            t-=1
        out += ("\t"*(t+i)) + s +  "\n"
        if len(s)>0 and s[-1] == "{":
            t+=1

    wo("// AUTO GENERATED DONT EDIT")
    for name, patches in patches_unique.items():
        wo(f"\n\n// {name}")
        created_patches = {}
        for patch in patches:
            if created_patches.get(patch.patch_name()):
                continue
            wo(f"const char {patch.patch_name()}[] = {patch.make()};\n")
            created_patches[patch.patch_name()] = True

        wo(f"int get_{patch.__class__.__name__}(const char** patch, int* offset, int* patch_size, unsigned int module_nid) {{")
        wo("switch(module_nid) {")
        for patch in patches:
            by_nid = patches_by_nid[name]
            for module_nid in patch.module_nids:
                wo(f"case 0x{module_nid:08x}: // {', '.join(by_nid[module_nid].versions)}", -1)
            wo(f"*patch = {patch.patch_name()};")
            wo(f"*patch_size = sizeof({patch.patch_name()});")
            wo(f"*offset = 0x{patch.addr-BASE:x};")
            wo("break;")
        wo("default:", -1)
        wo("return -1;")
        wo("}")
        wo("return 0;")
        wo("}")

    return out
