typedef struct replacement_t {
    char* original_domain;
    char* replacement_domain;
} replacement_t;

void init_http(const replacement_t* replacements, int replacement_num);
void release_http();
