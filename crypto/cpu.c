#include <openssl/cpu.h>

#ifdef __linux__
unsigned long getauxval_wrapper(unsigned long type, char *success) {
    if (getauxval == NULL) {
        *success = 0;
        return 0;
    }

    unsigned long result = getauxval(type);
    if (errno != 0) {
        *success = 0;
        return 0;
    }

    *success = 1;
    return result;
}
#endif
