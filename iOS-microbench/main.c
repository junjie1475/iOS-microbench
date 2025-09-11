#include <keystone/keystone.h>
#include <assert.h>
#include <dlfcn.h>
#include <pthread.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/sysctl.h>
#include <unistd.h>


ks_engine *ks = NULL;
static uint32_t convert(const char *assembly) {
  size_t count;
  size_t size;
  uint32_t *encode;
  uint32_t result;

  if (ks_asm(ks, assembly, 0, &encode, &size, &count)) {
    printf("ERROR: failed on ks_asm() with count = %lu, error code = %u\n",
           count, ks_errno(ks));
  }
  assert(size == 4);
  memcpy(&result, encode, 4);
  ks_free(encode);
  return result;
}

int test_entry() {
    ks_err err;
    
    err = ks_open(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN, &ks);
      if (err != KS_ERR_OK) {
        printf("ERROR: failed on ks_open(), quit\n");
        return -1;
      }
    printf("%x\n", convert("add x1, x2, x3"));
    return 0;
}
