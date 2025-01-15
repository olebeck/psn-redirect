#include <taihen.h>
#include <psp2kern/kernel/modulemgr.h>
#include <psp2kern/kernel/debug.h>
#include <psp2kern/kernel/threadmgr.h>
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/io/stat.h>
#include <psp2kern/io/fcntl.h>
#include <psp2/sysmodule.h>

#include "tai.h"
#include "inject-http.h"
#include "http.h"
#include "xmpp.h"


static int hk = 0;
static tai_hook_ref_t lfp_hook;


void print_hex(char* buf, int size) {
    char out[3];
    out[2] = 0;
    for (int z = 0; z < size; z++) {
        unsigned char hi = (buf[z] >> 4) & 0xf; 
        unsigned char lo = buf[z] & 0xf;
        out[0] = hi + (hi < 10 ? '0' : 'a' - 10);
        out[1] = lo + (lo < 10 ? '0' : 'a' - 10);
        ksceKernelPrintf(out);
    }
    ksceKernelPrintf("\n");
}


typedef int (*PatchGet)(const char **patch, int *offset, int *patch_size, unsigned int module_nid);

void apply_patch(int pid, int modid, int module_nid, PatchGet get_func, const char* name) {
    const char* patch;
    ptrdiff_t offset;
    int patch_size;
    int err = get_func(&patch, &offset, &patch_size, module_nid);
    if(err < 0) {
        ksceKernelPrintf("%s not found for %08x module nid\n", name, module_nid);
        return;
    }

    int hnd = taiInjectDataForKernel(pid, modid, 0, offset, patch, patch_size);
    if(hnd < 0) {
        ksceKernelPrintf("%s: %08x\n", name, hnd);
        return;
    }
}


// load module for pid (0 to get), running in kernel context, path is in kernel
static SceUID load_for_pid_patched(int pid, const char *path, uint32_t flags, int *ptr_to_four) {
    char* is_libhttp = strstr(path, "libhttp.suprx");

    int res = TAI_CONTINUE(SceUID, lfp_hook, pid, path, flags, ptr_to_four);

    if(is_libhttp != NULL) {
        if(pid == ksceKernelSysrootGetShellPid()) {
            int modid = ksceKernelGetModuleIdByPid(pid);
            tai_module_info_t info;
            info.size = sizeof(tai_module_info_t);
            int ret2 = get_tai_info(pid, "SceShell", &info);
            if(ret2 < 0) {
                ksceKernelPrintf("get_tai_info SceShell: %08x\n", ret2);
                return res;
            }

            apply_patch(pid, info.modid, info.module_nid, get_ShellCACheckPatch, "ShellCACheckPatch");
            apply_patch(pid, info.modid, info.module_nid, get_ShellXMPPRedirect, "ShellXMPPRedirect");
        }

        tai_module_info_t info;
        info.size = sizeof(tai_module_info_t);
        int ret2 = get_tai_info(pid, "SceLibHttp", &info);
        if(ret2 < 0) {
            ksceKernelPrintf("get_tai_info: %08x\n", ret2);
            return res;
        }

        apply_patch(pid, info.modid, info.module_nid, get_PsnRedirectPatch, "PsnRedirectPatch");
    }

	return res;
}

const replacement_t replacements[] = {
    {
        .original_domain = "playstation.net",
        .replacement_domain = "np.yuv.pink",
    },
    {
        .original_domain = "kzv.online.scee.com",
        .replacement_domain = "mirage.yuv.pink"
    }
};

const char* xmpp_replacement = "xmpp.np.yuv.pink";

#define ARRAY_LEN(x) (sizeof(x)/sizeof(*x))

void _start() __attribute__ ((weak, alias ("module_start")));
int module_start(SceSize argc, const void *args) {
    int modid = ksceKernelSearchModuleByName("SceKernelModulemgr");
    if (modid > 0) {
        hk = taiHookFunctionOffsetForKernel(KERNEL_PID, &lfp_hook, modid, 0, 0x21ec, 1, load_for_pid_patched);
    }
    if (modid < 0 || hk < 0) {
        return SCE_KERNEL_START_FAILED;
    }

    init_http(&replacements, ARRAY_LEN(replacements));
    init_xmpp(xmpp_replacement, 5223);
}


int module_stop(SceSize args, void *argp) {
    if(hk > 0) {
		taiHookReleaseForKernel(hk, lfp_hook);
    }
    release_http();
    release_xmpp();
}
