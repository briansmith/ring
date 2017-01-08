#include <openssl/cpu.h>

#ifdef __linux__

/* |getauxval| is not available on Android until API level 20. Link it as a weak
 * symbol and use other methods as fallback. As of Rust 1.14 this weak linkage
 * isn't supported, so we do it in C.
 */
unsigned long getauxval(unsigned long type) __attribute__((weak));

/*
 * getauxval() may or may not be available. In addition, it may not find
 * the type requested.
 * - If getauxval() is not available, this returns -1.
 * - If getauxval() is available but the requested type is not found or another
 *   error occurs, this returns 0.
 * - If getauxval() is available but a different error occurs, this returns -2.
 * - If getauxval() is available and the requested type is found, this returns
 *   1 and also writes to the result pointer param.
 */
int32_t getauxval_wrapper(unsigned long type, unsigned long *result);

#include <errno.h>

int32_t getauxval_wrapper(unsigned long type, unsigned long *result) {
    if (getauxval == NULL) {
        return -1;
    }

    unsigned long auxval = getauxval(type);
    if (errno == ENOENT) {
        // as of glibc 2.19, errno is ENOENT if the type is not found.
        errno = 0;
        return 0;
    } else if (errno != 0) {
        // as of glibc 2.23 the only error is enoent, but more errors
        // may be added
        errno = 0;
        return -2;
    }

    *result = auxval;
    return 1;
}
#endif
