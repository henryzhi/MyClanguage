
#define _GNU_SOURCE
#include <stdlib.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <signal.h>
#include <assert.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdlib.h>

typedef uint64_t cycles_t;
static int pin_cpu(size_t i)
{
  cpu_set_t cpu_set;
  pthread_t thread; 
  thread = pthread_self();

  CPU_ZERO(&cpu_set);
  CPU_SET(i, &cpu_set);

  return pthread_setaffinity_np(thread, sizeof cpu_set, &cpu_set);
}

static inline void code_barrier(void)
{
  asm volatile("cpuid\n" :: "a" (0) : "%rbx", "%rcx", "%rdx");
}

static inline void data_barrier(void)
{
  asm volatile("mfence\n" ::: "memory");
}

static inline cycles_t rdtscp(void)
{
  cycles_t cycles_lo, cycles_hi;

  asm volatile("rdtscp\n" :
    "=a" (cycles_lo), "=d" (cycles_hi) ::
    "%rcx");
  return ((uint64_t)cycles_hi << 32) | cycles_lo;
}


void set_gs(uint16_t value) {
  __asm__ volatile("mov %0, %%gs" : : "r"(value));
}

uint16_t get_gs() {
  uint16_t value;
  __asm__ volatile("mov %%gs, %0" : "=r"(value));
  return value;
}


volatile int shared_lock1 = 0;
volatile int count = 0;
volatile uint64_t sum = 0;
int detect_interrupt() {
  printf("main_thread.\n");
  uint16_t orig_gs = get_gs();
  set_gs(1);
  unsigned int count = 0;
  uint64_t past, now; 
  data_barrier();
  code_barrier();
  past = rdtscp();
  data_barrier();
  /* Loop until %gs gets reset by an interrupt handler. */
  while (get_gs() == 1) {
    ++count;
    
    if (count == 1) 
      shared_lock1 = 1;  
  } 
  data_barrier();
  now = rdtscp();
  code_barrier();
  data_barrier();
  sum = now-past;
  /* Restore register so as not to break TLS on x86-32 Linux.  This is
     not necessary on x86-64 Linux, which uses %fs for TLS. */
  set_gs(orig_gs);
  printf("%%gs was reset after %u iterations, elasped cycles:%zu\n", count, sum);
  return 0;
}

void almost_c99_signal_handler(int sig)
{
  switch(sig)
  {
    case SIGSEGV:
      fputs("Caught SIGSEGV: segfault\n", stderr);
      break;
    default:
      fputs("Caught SIGTERM: a termination request was sent to the program\n",
            stderr);
      break;
  }
  exit(EXIT_SUCCESS);
}
 
void set_signal_handler()
{
  signal(SIGSEGV, almost_c99_signal_handler);
}

void cause_segfault();
 
void *sonfunc(void *arg)
{
  volatile int *ptr = (volatile int *)arg;	

  if(ptr) {
    printf("son thread.\n");
    if (pin_cpu(0) == -1)
      printf("child pin cpu error.\n");
    set_signal_handler();
    cause_segfault(ptr);
  }
  else
    printf("ptr is null.\n");	
  return NULL;	
}

int main(int argc, char * argv[])
{
  pid_t pid; 
  volatile int *ptr = (volatile int *)strtoul(argv[1], NULL, 16); 
  
  if (pin_cpu(1) == -1)
      printf("parent pin cpu error.\n");
  pthread_t son_thread;
  pthread_create(&son_thread, NULL, sonfunc, (void *)ptr);
  detect_interrupt(); 
  assert(pthread_join(son_thread, NULL) == 0); 
  return 0;
}
 
//pid = fork();
//assert (pid >= 0);
 
void cause_segfault(volatile int *ptr)
{
  //volatile int * unmapped_ptr = (int*)0xffffffff80000000;
  //volatile int * mapped_ptr = (int*)0xffffffffbccbb640;
  while (shared_lock1 == 0);
  //*unmapped_ptr;
  *(volatile int *)ptr;

}
 
