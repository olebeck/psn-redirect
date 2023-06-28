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

static tai_hook_ref_t sceSysmoduleLoadModule_hook_ref;
static SceUID sceSysmoduleLoadModule_hook_id = -1;

void do_http_servername_patch(int pid, int modid, int module_nid) {
    const char* patch;
    ptrdiff_t offset;
    int patch_size;
    int err = get_servername_patch(&patch, &offset, &patch_size, module_nid);
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


int replaceDomain(const char* input_user, char* out_user, int input_length, const char* replacement_domain, const char* part_to_replace) {
    char input[0xff];
    char out[0xff];
    ksceKernelMemcpyFromUser(input, input_user, input_length+1);
    ksceKernelPrintf("replaceDomain: %s\n", input);

    const char* found = strstr(input, part_to_replace);
    if (found != NULL) {
        ksceKernelPrintf("found playstation.net\n");
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
        ksceKernelPrintf("modified: %s\n", out);
        ksceKernelMemcpyToUser(out_user, out, modified_len+1);
        return modified_len+1;
    }

    return -1;
}

int sceAppMgrIsNonGameProgram_hook(char* out, char* serverName, int flag, int serverNameLength) {
    if(flag == 0x00001234) {
        return replaceDomain(serverName, out, serverNameLength, "np.yuv.pink", "playstation.net");
    }

    return TAI_CONTINUE(int, sceAppMgrIsNonGameProgram_hook_ref);
}


SceUID sceSysmoduleLoadModule_hook(SceSysmoduleModuleId id) {
    SceUID ret = TAI_CONTINUE(SceUID, sceSysmoduleLoadModule_hook_ref, id);
    if(id == SCE_SYSMODULE_HTTP) {
        SceUID pid = ksceKernelGetProcessId();
        tai_module_info_t info;
        info.size = sizeof(tai_module_info_t);
        int ret2 = get_tai_info(pid, "SceLibHttp", &info);
        if(ret2 < 0) {
            ksceKernelPrintf("get_tai_info: %08x\n", ret2);
            return ret;
        }

        ksceKernelPrintf("%s %08x %08x\n", info.name, info.module_nid, info.modid);

        do_http_servername_patch(pid, info.modid, info.module_nid);
    }
    return ret;
}


void _start() __attribute__ ((weak, alias ("module_start")));
int module_start(SceSize argc, const void *args) {
    sceSysmoduleLoadModule_hook_id = taiHookFunctionExportForKernel(KERNEL_PID,
        &sceSysmoduleLoadModule_hook_ref,
        "SceSysmodule", 0x03FCF19D, 0x79A0160A,
        sceSysmoduleLoadModule_hook
    );

    sceAppMgrIsNonGameProgram_hook_id = taiHookFunctionExportForKernel(KERNEL_PID,
        &sceAppMgrIsNonGameProgram_hook_ref,
        "SceAppMgr", TAI_ANY_LIBRARY, 0x5F22E192,
        sceAppMgrIsNonGameProgram_hook
    );
    ksceKernelPrintf("sceAppMgrIsNonGameProgram_hook_id: %08x\n", sceAppMgrIsNonGameProgram_hook_id);
}


int module_stop(SceSize args, void *argp) {
    if(sceSysmoduleLoadModule_hook_id > 0) {
        taiHookReleaseForKernel(sceSysmoduleLoadModule_hook_id, sceSysmoduleLoadModule_hook_ref);
    }
    if(sceAppMgrIsNonGameProgram_hook_id > 0) {
        taiHookReleaseForKernel(sceAppMgrIsNonGameProgram_hook_id, sceAppMgrIsNonGameProgram_hook_ref);
    }
}
