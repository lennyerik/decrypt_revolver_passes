#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>
#include <dlfcn.h>

typedef struct {} REALString;

typedef REALString *(*EncryptFn)(void *Data, void *Password, long Offset);
typedef REALString *(*DecryptFn)(void *Data, void *Password, long Offset);

typedef unsigned char *(*GetDecryptOutBufFn)(unsigned long *length);

static bool check_dlerr(void *val) {
    if (val == NULL) {
        printf("DLERROR: %s\n", dlerror());
        return false;
    }
    return true;
}

int main() {
    void *lib = dlopen("./EHEncrypt16141.so", RTLD_LAZY);
    assert(check_dlerr(lib));

    EncryptFn Encrypt = (EncryptFn) dlsym(lib, "_Z7EncryptP16REALstringStructS0_l");
    assert(check_dlerr(Encrypt));

    DecryptFn Decrypt = (DecryptFn) dlsym(lib, "_Z7DecryptP16REALstringStructS0_l");
    assert(check_dlerr(Decrypt));

    Decrypt((void *) 0x1337, (void *) 0x1234, 0);

    GetDecryptOutBufFn GetDecryptOutBuf = (GetDecryptOutBufFn) dlsym(NULL, "GetDecryptOutBuf");
    assert(check_dlerr(GetDecryptOutBuf));

    unsigned long len = 0;
    unsigned char *buf = GetDecryptOutBuf(&len);
    // printf("%lu : %p\n", len, buf);
    for (unsigned long i = 0; i < len; i++) {
        printf("%u ", buf[i]);
    }
    printf(" ::  %s\n", buf);
}
