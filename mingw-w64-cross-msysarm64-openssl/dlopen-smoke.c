#include <dlfcn.h>
#include <stdio.h>

typedef int (*smoke_fn)(void);

int main(int argc, char **argv)
{
    void *handle;
    smoke_fn smoke;
    int result;

    if (argc != 2)
        return 2;
    handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (handle == NULL) {
        fprintf(stderr, "dlopen: %s\n", dlerror());
        return 3;
    }
    smoke = (smoke_fn)dlsym(handle, "openssl_dlopen_smoke");
    if (smoke == NULL) {
        fprintf(stderr, "dlsym: %s\n", dlerror());
        dlclose(handle);
        return 4;
    }
    result = smoke();
    if (dlclose(handle) != 0)
        return 5;
    if (result != 42)
        return 6;
    puts("dlopen-smoke=pass");
    return 0;
}
