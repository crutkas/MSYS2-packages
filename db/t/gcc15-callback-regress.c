/*
 * Regression guard for the Berkeley DB 6.2.32 / GCC 15 (C23) build fix.
 *
 * Berkeley DB stores heterogeneous DB_CONFIG callbacks in a single generic
 * function-pointer slot (src/env/env_config.c: CFG_DESC.func) and dispatches
 * each one after casting back to its exact prototype, chosen by CFG_DESC.type.
 *
 * Under C11/C17 an empty parameter list meant "unspecified arguments", so the
 * table could initialize that slot with differently-typed functions directly.
 * GCC 15 defaults to C23, where an empty parameter list means "(void)", so the
 * bare initializers become -Wincompatible-pointer-types errors (48 of them,
 * first at env_config.c:77).  The fix casts each initializer to the slot's type
 * via CFG_FN(); every call still casts back to the real prototype first, so the
 * round-trip conversion is well defined (C17/C23 6.3.2.3p8).
 *
 * This file mirrors that exact surface.  Built the way the package builds
 * (GCC 15 default standard + -Werror), it:
 *   - COMPILES and passes at runtime with the fix (CFG_FN cast) in place;
 *   - FAILS TO COMPILE when the fix is reverted (build with -DREGRESS_NO_FIX),
 *     reproducing the incompatible-pointer-types error the patch removes.
 *
 * Run: db/t/run-gcc15-regress.sh
 */
#include <stdio.h>
#include <string.h>

typedef enum { CFG_UINT, CFG_STRING, CFG_2UINT } cfg_type;

/* Generic storage slot, exactly like CFG_DESC.func after the fix. */
typedef struct {
	const char *name;
	cfg_type type;
	int (*func)(void);
} desc_t;

/* Exact-prototype typedefs used to cast back before every call. */
typedef int (*fn_uint)(unsigned, unsigned *);
typedef int (*fn_string)(const char *, unsigned *);
typedef int (*fn_2uint)(unsigned, unsigned, unsigned *);

#ifdef REGRESS_NO_FIX
/* Reverted patch: bare initializer -> C23 incompatible-pointer-types error. */
#define CFG_FN(f)	(f)
#else
/* The fix under test. */
#define CFG_FN(f)	((int (*)(void))(f))
#endif

static int take_uint(unsigned a, unsigned *out) { *out = a; return 0; }
static int take_string(const char *s, unsigned *out) { *out = (unsigned)strlen(s); return 0; }
static int take_2uint(unsigned a, unsigned b, unsigned *out) { *out = a + b; return 0; }

static const desc_t table[] = {
	{ "u",  CFG_UINT,   CFG_FN(take_uint)   },
	{ "s",  CFG_STRING, CFG_FN(take_string) },
	{ "uu", CFG_2UINT,  CFG_FN(take_2uint)  },
};

int main(void)
{
	unsigned out = 0;
	int rc = 0;

	/* Dispatch through the exact prototype, proving call compatibility. */
	((fn_uint)table[0].func)(41u, &out);
	if (out != 41u) { fprintf(stderr, "uint dispatch wrong: %u\n", out); rc = 1; }

	((fn_string)table[1].func)("berkeley", &out);
	if (out != 8u) { fprintf(stderr, "string dispatch wrong: %u\n", out); rc = 1; }

	((fn_2uint)table[2].func)(20u, 22u, &out);
	if (out != 42u) { fprintf(stderr, "2uint dispatch wrong: %u\n", out); rc = 1; }

	if (rc == 0)
		printf("gcc15-callback-regress: PASS\n");
	return rc;
}
