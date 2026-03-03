#include <openssl/sha.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct {
  const char *prefix;
  int bits;
  int threads;
  int tid;
  atomic_int *found;
  uint64_t *result;
} worker_args;

static int leading_zero_bits(const unsigned char *digest) {
  int zeros = 0;
  for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
    unsigned char b = digest[i];
    if (b == 0) {
      zeros += 8;
      continue;
    }
    while ((b & 0x80) == 0) {
      zeros++;
      b <<= 1;
    }
    break;
  }
  return zeros;
}

static void *worker(void *argp) {
  worker_args *arg = (worker_args *)argp;
  size_t prefix_len = strlen(arg->prefix);
  char buf[256];
  unsigned char digest[SHA_DIGEST_LENGTH];
  memcpy(buf, arg->prefix, prefix_len);

  for (uint64_t counter = (uint64_t)arg->tid; !atomic_load(arg->found);
       counter += (uint64_t)arg->threads) {
    int n = snprintf(buf + prefix_len, sizeof(buf) - prefix_len, "%llx",
                     (unsigned long long)counter);
    if (n <= 0 || (size_t)n >= sizeof(buf) - prefix_len) {
      continue;
    }
    SHA1((unsigned char *)buf, prefix_len + (size_t)n, digest);
    if (leading_zero_bits(digest) >= arg->bits) {
      if (!atomic_exchange(arg->found, 1)) {
        *arg->result = counter;
      }
      break;
    }
  }
  return NULL;
}

int main(int argc, char **argv) {
  if (argc != 3) {
    fprintf(stderr, "usage: %s <bits> <resource>\n", argv[0]);
    return 1;
  }

  int bits = atoi(argv[1]);
  const char *resource = argv[2];
  long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
  if (ncpu < 1) ncpu = 1;
  int threads = (int)ncpu;

  char prefix[256];
  int n = snprintf(prefix, sizeof(prefix), "1:%d:250228:%s::rnd:", bits, resource);
  if (n <= 0 || (size_t)n >= sizeof(prefix)) {
    fprintf(stderr, "prefix too long\n");
    return 1;
  }

  pthread_t *tids = calloc((size_t)threads, sizeof(pthread_t));
  worker_args *args = calloc((size_t)threads, sizeof(worker_args));
  if (!tids || !args) {
    fprintf(stderr, "alloc failed\n");
    return 1;
  }

  atomic_int found = 0;
  uint64_t result = 0;

  for (int i = 0; i < threads; i++) {
    args[i].prefix = prefix;
    args[i].bits = bits;
    args[i].threads = threads;
    args[i].tid = i;
    args[i].found = &found;
    args[i].result = &result;
    pthread_create(&tids[i], NULL, worker, &args[i]);
  }

  for (int i = 0; i < threads; i++) {
    pthread_join(tids[i], NULL);
  }

  printf("%s%llx\n", prefix, (unsigned long long)result);
  free(tids);
  free(args);
  return 0;
}
