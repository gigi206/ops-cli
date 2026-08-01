// The user namespace turned out to cost nothing, so the remaining candidate for the gap between a
// hot-loop remote read (~1.5 us) and the 11.9 us the shipped exec supervisor measured is which pid
// is being read: an execve notification always names a *freshly created* process, so every
// open("/proc/<pid>/mem") is a first touch — new proc dentry, new inode — while a hot loop against
// one pid reuses all of it.
//
// This matters far beyond bookkeeping: an openat lens would read the same *long-lived* process over
// and over, so if the cost is a per-new-process one, openat does not pay it and execve does.
//
// N children are forked up front. The cold column reads each pid exactly once; the warm column does
// the same number of reads against a single pid. Nothing else differs.

#define _GNU_SOURCE
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static double now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1e9 + (double)ts.tv_nsec;
}

#define KIDS 400

static char target_path[4096];

// One read of `plen` bytes at the known address out of `pid`, by open+pread+close.
static int read_once(pid_t pid, size_t plen, char *out) {
    char mem_path[64];
    snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", (int)pid);
    int fd = open(mem_path, O_RDONLY);
    if (fd < 0) return -1;
    ssize_t n = pread(fd, out, plen, (off_t)(uintptr_t)target_path);
    close(fd);
    return n > 0 ? 0 : -1;
}

int main(void) {
    strcpy(target_path, "/home/user/project/src/some/reasonably/deep/module.rs");
    size_t plen = strlen(target_path) + 1;
    char out[4096];

    static pid_t kids[KIDS];
    for (int i = 0; i < KIDS; i++) {
        pid_t p = fork();
        if (p == 0) { for (;;) pause(); }
        kids[i] = p;
    }
    usleep(300000);

    // Cold: each pid read for the first time.
    double t0 = now_ns();
    int failed = 0;
    for (int i = 0; i < KIDS; i++) {
        if (read_once(kids[i], plen, out) != 0) failed++;
    }
    double cold = (now_ns() - t0) / KIDS / 1000.0;

    // Warm: the same count of reads, all against one pid already touched above.
    t0 = now_ns();
    for (int i = 0; i < KIDS; i++) {
        if (read_once(kids[0], plen, out) != 0) failed++;
    }
    double warm = (now_ns() - t0) / KIDS / 1000.0;

    // And with the fd kept open, the shape a per-pid cache would have.
    char mem_path[64];
    snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", (int)kids[0]);
    int memfd = open(mem_path, O_RDONLY);
    t0 = now_ns();
    for (int i = 0; i < KIDS; i++) {
        if (pread(memfd, out, plen, (off_t)(uintptr_t)target_path) <= 0) failed++;
    }
    double cached = (now_ns() - t0) / KIDS / 1000.0;
    close(memfd);

    printf("cold pid (first touch) : %6.3f us   <- what an execve notification pays\n", cold);
    printf("warm pid (same target) : %6.3f us   <- what an openat notification would pay\n", warm);
    printf("warm pid, cached fd    : %6.3f us\n", cached);
    if (failed) printf("(%d reads failed)\n", failed);

    for (int i = 0; i < KIDS; i++) kill(kids[i], SIGKILL);
    for (int i = 0; i < KIDS; i++) waitpid(kids[i], NULL, 0);
    return 0;
}
