#include <openssl/cpu.h>

#ifdef __linux__

/* |getauxval| is not available on Android until API level 20. Link it as a weak
 * symbol and use other methods as fallback. As of Rust 1.14 this weak linkage
 * isn't supported, so we do it in C.
 */
unsigned long getauxval(unsigned long type) __attribute__((weak));

/*
 * If getauxval is not available, or an error occurs, return 0.
 * Otherwise, return the value found.
 */
unsigned long getauxval_wrapper(unsigned long type);

#include <errno.h>

unsigned long getauxval_wrapper(unsigned long type) {
    if (getauxval == NULL) {
        return 0;
    }

    unsigned long auxval = getauxval(type);
    // map errors to a zero value
    if (errno != 0) {
        errno = 0;
        return 0;
    }

    return auxval;
}
#endif
