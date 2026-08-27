#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/crypto.h>

static void minimal_teardown(void *provctx)
{
    (void)provctx;
}

static const OSSL_DISPATCH minimal_dispatch[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))minimal_teardown },
    OSSL_DISPATCH_END
};

int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
                       const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out,
                       void **provctx)
{
    (void)handle;
    (void)in;
    if (OpenSSL_version_num() == 0)
        return 0;
    *provctx = NULL;
    *out = minimal_dispatch;
    return 1;
}
