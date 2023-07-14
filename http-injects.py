from keystone import *
from capstone import *

from patcher import Patch, BASE, insn_b_to_addr, generate_all_patches
cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
ks = Ks(KS_ARCH_ARM, KS_MODE_THUMB)

class PsnRedirectPatch(Patch):
    _filename = "vs0/sys/external/libhttp.suprx.elf"
    _extra_files = ["lhttp.suprx.elf"]
    def patch_name(self):
        return f"psn_redirect_0x{self.addr:08x}_0x{self.syms['sceAppMgrIsNonGameProgram']:08x}"

    _imports = {
        "sceAppMgrIsNonGameProgram": 0x5F22E192,
        "sceClibStrnlen": 0xAC595E68
    }

    _code = (
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

        "b patch_end\n" # skip the to the end of the patch
    )


    # finds the start of where to patch,
    # where the end of the if block
    # and the alloc, free functions to use on the servername are,
    # does this with simple byte offsets from the known string
    # this works fine as sony hasnt changed the module basically at all in recent versions  
    @staticmethod
    def find(seg: bytes) -> tuple[int, dict[str, int]]:
        SceLibHttp_str_location = BASE+seg.find(b"SceLibHttp_%s")
        low = SceLibHttp_str_location & 0xffff

        # find patch_start
        mov = seg.find(ks.asm(f"movw r2, #0x{low:x}", 0, True)[0])
        patch_start = BASE + (mov-52)

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

        return patch_start, {
            "patch_end": BASE+patch_end,
            "call_alloc": BASE+call_alloc,
            "call_dealloc": BASE+call_dealloc
        }



class ShellCACheckPatch(Patch):
    _filename = "vs0/vsh/shell/shell.self.elf"
    def patch_name(self):
        return "shell_ca_check_patch"
    
    _code = (
        "mov r0, 0\n"
        "bx lr\n"
    )

    @staticmethod
    def find(data: bytes) -> tuple[int, dict[str, int]]:
        off = data.find(b'\x01\xeb\x82\x00\x50\xf8\x04\x0c')-22
        dis = list(cs.disasm(data[off:off+6], off, 2))
        assert dis[0].mnemonic == "push.w"
        assert dis[1].mnemonic == "sub"
        return BASE+off, {}



class ShellXMPPRedirect(Patch):
    _filename = "vs0/vsh/shell/shell.self.elf"
    def patch_name(self):
        return f"shell_xmpp_redirect_patch_0x{self.addr:08x}_0x{self.syms['sceAppMgrReleaseBgmPort']:08x}"
    
    _imports = {
        "sceAppMgrReleaseBgmPort": 0xF3717E37,
    }

    _code = (
        "blx sceAppMgrReleaseBgmPort\n"
    )

    @staticmethod
    def find(data: bytes) -> tuple[int, dict[str, int]]:
        off = data.find(b'\xc4\xf8\x2c\x90\xc4\xf8\x30\x90')
        if off < 0:
            raise Exception("not found")
        off -= 20
        dis = list(cs.disasm(data[off:off+32], off, 3))
        assert dis[0].mnemonic == "str.w"
        assert dis[1].mnemonic == "adds.w"
        assert dis[2].mnemonic == "str.w"
        return BASE+off, {}




def main():
    with open("src/inject-http.h", "w") as f:
        f.write(generate_all_patches(PsnRedirectPatch, ShellCACheckPatch, ShellXMPPRedirect))

main()
