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

static tai_hook_ref_t sceAppMgrIsNonGameProgram_hook_ref;
static SceUID sceAppMgrIsNonGameProgram_hook_id = -1;

void do_http_servername_patch(int pid, int modid, int module_nid) {
    const char* patch;
    ptrdiff_t offset;
    int patch_size;
    int err = get_PsnRedirectPatch(&patch, &offset, &patch_size, module_nid);
    if(err < 0) {
        ksceKernelPrintf("Failed to find patch for %08x\n", module_nid);
        return;
    }

    int hnd = taiInjectDataForKernel(pid, modid, 0, offset, patch, patch_size);
    if(hnd < 0) {
        ksceKernelPrintf("http_servername_patch: %08x\n", hnd);
        return;
    }
}

void do_shell_ca_check_patch(int pid, int modid, int module_nid) {
    const char* patch;
    ptrdiff_t offset;
    int patch_size;
    int err = get_ShellCACheckPatch(&patch, &offset, &patch_size, module_nid);
    if(err < 0) {
        ksceKernelPrintf("Failed to find patch for %08x\n", module_nid);
        return;
    }

    int hnd = taiInjectDataForKernel(pid, modid, 0, offset, patch, patch_size);
    if(hnd < 0) {
        ksceKernelPrintf("http_servername_patch: %08x\n", hnd);
        return;
    }
}


int replaceDomain(const char* input_user, char* out_user, int input_length, const char* part_to_replace, const char* replacement_domain) {
    char input[0xff];
    char out[0xff];
    ksceKernelMemcpyFromUser(input, input_user, input_length+1);

    const char* found = strstr(input, part_to_replace);
    if (found != NULL) {
        size_t part_len = strlen(part_to_replace);
        size_t replace_len = strlen(replacement_domain);
        size_t tail_len = strlen(found + part_len);
        size_t modified_len = strlen(input) - part_len + replace_len;
        
        if (out_user == NULL) {
            // just Return the length if out is 0
            return modified_len+1;
        }
        
        // Write the modified domain to out
        strncpy(out, input, found - input);
        strncpy(out + (found - input), replacement_domain, replace_len);
        strncpy(out + (found - input) + replace_len, found + part_len, tail_len + 1);
        out[modified_len] = '\0';
        ksceKernelPrintf("modified domain: %s\n", out);
        ksceKernelMemcpyToUser(out_user, out, modified_len+1);
        return modified_len+1;
    }

    return -1;
}

int sceAppMgrIsNonGameProgram_hook(char* out, char* serverName, int flag, int serverNameLength) {
    if(flag == 0x00001234) {
        return replaceDomain(serverName, out, serverNameLength, "playstation.net", "np.yuv.pink");
    }

    return TAI_CONTINUE(int, sceAppMgrIsNonGameProgram_hook_ref);
}

void print_hex(char* buf, char* out, int size) {
    for (int z = 0; z < size; z++) {
        unsigned char hi = (buf[z] >> 4) & 0xf; 
        unsigned char lo = buf[z] & 0xf;        
        *out++ = hi + (hi < 10 ? '0' : 'a' - 10);
        *out++ = lo + (lo < 10 ? '0' : 'a' - 10);
    }
    *out++ = 0;
}

static int hk = 0;
static tai_hook_ref_t lfp_hook;
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

            do_shell_ca_check_patch(pid, info.modid, info.module_nid);
        }

        tai_module_info_t info;
        info.size = sizeof(tai_module_info_t);
        int ret2 = get_tai_info(pid, "SceLibHttp", &info);
        if(ret2 < 0) {
            ksceKernelPrintf("get_tai_info: %08x\n", ret2);
            return res;
        }

        do_http_servername_patch(pid, info.modid, info.module_nid);
    }

	return res;
}




void _start() __attribute__ ((weak, alias ("module_start")));
int module_start(SceSize argc, const void *args) {
    int modid = ksceKernelSearchModuleByName("SceKernelModulemgr");
    if (modid > 0)
        hk = taiHookFunctionOffsetForKernel(KERNEL_PID, &lfp_hook, modid, 0, 0x21ec, 1, load_for_pid_patched);
    if (modid < 0 || hk < 0)
        return SCE_KERNEL_START_FAILED;

    sceAppMgrIsNonGameProgram_hook_id = taiHookFunctionExportForKernel(KERNEL_PID,
        &sceAppMgrIsNonGameProgram_hook_ref,
        "SceAppMgr", TAI_ANY_LIBRARY, 0x5F22E192,
        sceAppMgrIsNonGameProgram_hook
    );
    if(sceAppMgrIsNonGameProgram_hook_id < 0) {
        ksceKernelPrintf("sceAppMgrIsNonGameProgram_hook_id: %08x\n", sceAppMgrIsNonGameProgram_hook_id);
    }
}


int module_stop(SceSize args, void *argp) {
    if(hk > 0) {
		taiHookReleaseForKernel(hk, lfp_hook);
    }
    if(sceAppMgrIsNonGameProgram_hook_id > 0) {
        taiHookReleaseForKernel(sceAppMgrIsNonGameProgram_hook_id, sceAppMgrIsNonGameProgram_hook_ref);
    }
}
