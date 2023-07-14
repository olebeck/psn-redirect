#include <psp2kern/kernel/debug.h>
#include <psp2kern/kernel/sysmem.h>
#include <taihen.h>


static tai_hook_ref_t sceAppMgrIsNonGameProgram_hook_ref;
static SceUID sceAppMgrIsNonGameProgram_hook_id = -1;

static char* replacement_domain;

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
        return replaceDomain(serverName, out, serverNameLength, "playstation.net", replacement_domain);
    }

    return TAI_CONTINUE(int, sceAppMgrIsNonGameProgram_hook_ref);
}


void init_http(char* domain) {
    replacement_domain = domain;

    sceAppMgrIsNonGameProgram_hook_id = taiHookFunctionExportForKernel(KERNEL_PID,
        &sceAppMgrIsNonGameProgram_hook_ref,
        "SceAppMgr", TAI_ANY_LIBRARY, 0x5F22E192,
        sceAppMgrIsNonGameProgram_hook
    );
    if(sceAppMgrIsNonGameProgram_hook_id < 0) {
        ksceKernelPrintf("sceAppMgrIsNonGameProgram_hook_id: %08x\n", sceAppMgrIsNonGameProgram_hook_id);
    }
}

void release_http() {
    if(sceAppMgrIsNonGameProgram_hook_id > 0) {
        taiHookReleaseForKernel(sceAppMgrIsNonGameProgram_hook_id, sceAppMgrIsNonGameProgram_hook_ref);
    }
}
