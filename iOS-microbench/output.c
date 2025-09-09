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

#include <libkern/OSCacheControl.h>


struct proc_threadcounts_data {
  uint64_t ptcd_instructions;
  uint64_t ptcd_cycles;
  uint64_t ptcd_user_time_mach;
  uint64_t ptcd_system_time_mach;
  uint64_t ptcd_energy_nj;
};

struct proc_threadcounts {
  uint16_t ptc_len;
  uint16_t ptc_reserved0;
  uint32_t ptc_reserved1;
  struct proc_threadcounts_data ptc_counts[];
};

#define PROC_PIDTHREADCOUNTS 34
#define PROC_PIDTHREADCOUNTS_SIZE (sizeof(struct proc_threadcounts))
int proc_pidinfo(int pid, int flavor, uint64_t arg, void *buffer, int buffersize);

static int its = 8192 * 4;
static int outer_its = 64 * 4;
static int unroll = 1; // TODO
const char *delim = "\t";

#define FILL_INSTR 3000

struct proc_threadcounts *rbuf;
pid_t pid;
static void configure_rdtsc() {
}

static int countsize;
static uint64_t target_tid;
static void init_rdtsc() {
  countsize = sizeof(struct proc_threadcounts) + 2 * sizeof(struct proc_threadcounts_data);
  rbuf = (struct proc_threadcounts*)malloc(countsize);
  pid = getpid();
  pthread_threadid_np(pthread_self(), &target_tid);
}

static unsigned long long int rdtsc() {
  int ret = proc_pidinfo(pid, PROC_PIDTHREADCOUNTS, target_tid, rbuf, countsize);
  
  struct proc_threadcounts_data *p = &(rbuf->ptc_counts[0]);
  uint64_t cycle = p->ptcd_cycles;
  return cycle;
}

static int add_prep2(uint32_t *ibuf) {
  int o = 0;

  // free as much of the prf as possible
  for (int i = 6; i < 31; i++)
    ibuf[o++] = 0xd2800000 | i; // mov xi, #0

  for (int i = 0; i < 32; i++)
    ibuf[o++] = 0x4ea11c20 | i; // mov.16b vi, v1

  return o;
}
#define ADD(s) ibuf[o++] = convert(s)

static int add_filler2(uint32_t *ibuf, int instr_type, int j) {
    int o = 0;
    switch (instr_type) {
        case 0:
            if(j % 2 == 0) ibuf[o++] = 0x4e228420;
            else ibuf[o++] = 0x4e229c23;
            break;
        case 1:
            if(j % 8 < 1) ibuf[o++] = 0x1e21cc02;
            else if(j % 8 < 6) ibuf[o++] = 0xd503201f;
            else ibuf[o++] = 0x4e228420;
            break;
        case 2:
            ibuf[o++] = 0x1e200001;
            break;
        case 3:
            ibuf[o++] = 0x1e221823;
            break;
        case 4:
            ibuf[o++] = 0xf9400045;
            break;
        case 5:
            ibuf[o++] = 0xf9000445;
            break;
        case 6:
            if(j % 8 < 2) ibuf[o++] = 0xf9400045;
            else if(j % 8 < 4) ibuf[o++] = 0xf9000445;
            else ibuf[o++] = 0xd503201f;
            break;
        case 7:
            ibuf[o++] = 0x8b0b0165;
            break;
        case 8:
            ibuf[o++] = 0x9b0b7d65;
            break;
        case 9:
            if(j % 8 < 2) ibuf[o++] = 0x9b0b7d65;
            else ibuf[o++] = 0x8b0b0165;
            break;
        case 10:
            ibuf[o++] = 0x9acb0d65;
            break;
        case 11:
            if(j % 3 < 2) ibuf[o++] = 0x9b0b7d65;
            else ibuf[o++] = 0x9acb0d65;
            break;
        case 12:
            ibuf[o++] = 0x6b0600bf;
            break;
        case 13: // ipc 4
            if(j % 8 < 6) ibuf[o++] = 0x8b0b0165;
            else if(j % 8 < 7) ibuf[o++] = 0x9acb0d65;
            else ibuf[o++] = 0xd503201f;
            break;
        case 14:
            ibuf[o++] = 0x54000020;
            break;
        case 15:
            ibuf[o++] = 0xd503201f;
            break;
    }
    return o;
}

void make_routine2(uint32_t *ibuf, int icount, int instr_type) {
  int o = 0;
  mprotect(ibuf, 0x400000, PROT_WRITE);

  // prologue
  ibuf[o++] = 0xa9b47bfd;
  ibuf[o++] = 0xa9016ffc;
  ibuf[o++] = 0xa90267fa;
  ibuf[o++] = 0xa9035ff8;
  ibuf[o++] = 0xa90457f6;
  ibuf[o++] = 0xa9054ff4;
  ibuf[o++] = 0xa90647f2;
  ibuf[o++] = 0xa9073ff0;
  ibuf[o++] = 0x6d083bef;
  ibuf[o++] = 0x6d0933ed;
  ibuf[o++] = 0x6d0a2beb;
  ibuf[o++] = 0x6d0b23e9;
        

  // next, next, data1, data2, its
  // x0 = offset into data1
  // x1 = offset into data2
  // x2 = data1
  // x3 = data2
  // x4 = its

  o += add_prep2(ibuf + o);

  int start = o;

  for (int j = 0; j < icount; j++) {
    o += add_filler2(ibuf + o, instr_type, j);
  }


  // loop back to top
  ibuf[o++] = 0x71000484;
  int off = start - o;
  assert(off < 0 && off > -0x40000);
  ibuf[o++] = 0x54000001 | ((off & 0x7ffff) << 5); // b.ne

  // epilogue
  ibuf[o++] = 0x6d4b23e9;
  ibuf[o++] = 0x6d4a2beb;
  ibuf[o++] = 0x6d4933ed;
  ibuf[o++] = 0x6d483bef;

  ibuf[o++] = 0xa9473ff0;
  ibuf[o++] = 0xa94647f2;
  ibuf[o++] = 0xa9454ff4;
  ibuf[o++] = 0xa94457f6;
  ibuf[o++] = 0xa9435ff8;
  ibuf[o++] = 0xa94267fa;
  ibuf[o++] = 0xa9416ffc;
  ibuf[o++] = 0xa8cc7bfd;
  ibuf[o++] = 0xd65f03c0;


  mprotect(ibuf, 0x400000, PROT_WRITE);
  sys_icache_invalidate(ibuf, o * 4);
}


static void shuffle(int *array, size_t n) {
  if (n > 1) {
    size_t i;
    for (i = 0; i < n - 1; i++) {
      size_t j = i + rand() / (RAND_MAX / (n - i) + 1);
      int t = array[j];
      array[j] = array[i];
      array[i] = t;
    }
  }
}

static void init_dbufs(uint64_t **out_data1, uint64_t **out_data2) {
  // Initialize two 256MB data buffers, with the same linked-list
  // of offsets.
  size_t size = 256 * 1024 * 1024;
  size_t cache_line_size = 64;
  size_t count = size / cache_line_size;
  size_t stride = cache_line_size / sizeof(void *);
  int *numbers = malloc(count * sizeof(int));
  for (int i = 0; i < count; i++) {
    numbers[i] = i;
  }
  shuffle(numbers, count);

  uint64_t *data1 = calloc(size, 1);
  uint64_t *data2 = (uint64_t *)((char *)calloc(size + 64, 1) + 64);
  int next = numbers[count - 1];
  for (int i = 0; i < count; i++) {
    int n = numbers[i];
    data1[stride * n] = next * stride;
    data2[stride * n] = next * stride;
    next = n;
  }

  *out_data1 = data1;
  *out_data2 = data2;
  free(numbers);
}

int test_entry(int agrc, char **argv) {
  int test_high_perf_cores = 1;
  int instr_type = 1;
  int start_icount = 15;
  int stop_icount = 1000;
  int stride_icount = 1;

  init_rdtsc();
  uint64_t *data1, *data2;
  init_dbufs(&data1, &data2);


  if (test_high_perf_cores) {
    int core = 7;
    pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0);

  } else {
    pthread_set_qos_class_self_np(QOS_CLASS_BACKGROUND, 0);
  }

  void *mapping = mmap(NULL, 0x400000, PROT_WRITE,
                        MAP_ANON | MAP_PRIVATE, -1, 0);
   uint32_t *ibuf = (uint32_t *)mapping;
  uint64_t next = 0;

   for (int icount = start_icount; icount <= stop_icount; icount += stride_icount) {
//     make_routine(ibuf, icount, 16);
     make_routine2(ibuf, FILL_INSTR, 15);

     uint64_t (*routine)(uint64_t, uint64_t, uint64_t *, uint64_t *, uint64_t) = (void *)ibuf;

     uint64_t min_diff = 0x7fffffffffffffffLL;
     uint64_t max_diff = 0x0;
     uint64_t sum_diff = 0;

     mprotect(ibuf, 0x400000, PROT_EXEC);
     next = routine(next, next, data1, data2, its);

     for (int i = 0; i < outer_its; i++) {

       long long start = rdtsc();
       next = routine(next, next, data1, data2, its);
       long long stop = rdtsc();

       uint64_t cycles = stop - start;

       sum_diff += cycles;
       if (min_diff > cycles) {
         min_diff = cycles;
       }
       if (max_diff < cycles) {
         max_diff = cycles;
       }
      }
      printf("%d%s%.2f%s%.2f%s%.2f%s%.2f%s%.2f\n", icount, delim,
        1.0 * min_diff / its / unroll, delim,
        1.0 * sum_diff / its / unroll / outer_its, delim,
        1.0 * max_diff / its / unroll, delim,
        (1.0 * FILL_INSTR) / (1.0 * min_diff / its/ unroll), delim,
        (1.0 * min_diff / its/ unroll) / (FILL_INSTR / 8.0));
    }
    // cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON -DLLVM_TARGETS_TO_BUILD="AArch64;X86" -G "Unix Makefiles" ..

  return 0;
}

