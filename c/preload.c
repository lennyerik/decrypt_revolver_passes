#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

int i = 0;

char first[] = { 0xff, 0xf8, 0x92, 0x29, 0xe3, 0x1b, 0xb3, 0x51, 0x4a, 0x0b, 0xaa, 0x3d, 0x3f };
// qSmiiLro8m
char *second = "2pAuzgX9Ns";

char *out_buf = NULL;
unsigned long out_buf_len = 0;

char *REALGetStringContents(void *string_struct, unsigned long *length) {
    char *ret = NULL;
    *length = 0;

    switch (i++) {
        case 0:
            ret = first;
            break;
        case 1:
            ret = second;
            break;
        case 2:
            ret = first;
            break;
        default:
            printf("REALGetStringContents called too many times!\n");
            assert(0);
    }

    *length = strlen(ret);
    char *buf = (char *) malloc(*length + 1);
    memcpy(buf, ret, *length + 1);

    if (i == 3) {
        out_buf = buf;
        out_buf_len = *length;
    }

    return buf;
}

void *EBuildStringImpl(char *data, unsigned long length) {
    // printf("EBuildString called\n");
    return NULL;
}

void *EBuildString = EBuildStringImpl;

char *GetDecryptOutBuf(unsigned long *length) {
    i = 0;
    *length = out_buf_len;
    return out_buf;
}
