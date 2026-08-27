#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

typedef int (*smoke_fn)(void);

int main(int argc, char **argv)
{
    void *handle;
    smoke_fn smoke;
    int result;

    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    int flags;

    if (argc != 3)
        return 2;
    if (strcmp(argv[2], "now") == 0)
        flags = RTLD_NOW;
    else if (strcmp(argv[2], "lazy") == 0)
        flags = RTLD_LAZY;
    else
        return 7;
    puts("dlopen-before");
    handle = dlopen(argv[1], flags | RTLD_LOCAL);
    if (handle == NULL) {
        fprintf(stderr, "dlopen: %s\n", dlerror());
        return 3;
    }
    puts("dlopen-after");
    smoke = (smoke_fn)dlsym(handle, "openssl_dlopen_smoke");
    if (smoke == NULL) {
        fprintf(stderr, "dlsym: %s\n", dlerror());
        dlclose(handle);
        return 4;
    }
    puts("dlsym-after");
    result = smoke();
    puts("callback-after");
    puts("dlclose-before");
    if (dlclose(handle) != 0)
        return 5;
    puts("dlclose-after");
    if (result != 42)
        return 6;
    puts("dlopen-smoke=pass");
    return 0;
}
