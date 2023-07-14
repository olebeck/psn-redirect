void print_hex(char* buf, char* out, int size);

typedef int (*PatchGet)(const char **patch, int *offset, int *patch_size, unsigned int module_nid);

void apply_patch(int pid, int modid, int module_nid, PatchGet get_func, const char* name);

