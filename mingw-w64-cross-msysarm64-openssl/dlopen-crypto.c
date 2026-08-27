#include <openssl/evp.h>

__declspec(dllexport) int openssl_dlopen_smoke(void)
{
    EVP_MD *digest = EVP_MD_fetch(NULL, "SHA256", NULL);

    if (digest == NULL)
        return 1;
    EVP_MD_free(digest);
    return 42;
}
