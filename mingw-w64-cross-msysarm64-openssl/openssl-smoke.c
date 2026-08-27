#include <openssl/evp.h>
#include <openssl/ssl.h>

int main(void)
{
    EVP_MD *digest = EVP_MD_fetch(NULL, "SHA256", NULL);
    SSL_CTX *context = SSL_CTX_new(TLS_method());

    EVP_MD_free(digest);
    SSL_CTX_free(context);
    return digest == NULL || context == NULL;
}
