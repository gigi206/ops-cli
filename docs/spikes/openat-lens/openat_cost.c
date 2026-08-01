// Prices the two terms an openat user-notif supervisor would pay, measured in situ rather than by
// a wall-clock diff between two binaries.
//
//   1. the native cost of the syscall the supervisor would intercept (openat of a warm file, both
//      an absolute path and an AT_FDCWD-relative one), so the overhead can be stated as a ratio
//   2. the cost of reading a pathname out of a *remote* process, the supervisor's dominant term,
//      by the two available mechanisms: open+pread+close on /proc/<pid>/mem, and process_vm_readv
//
// The remote pid matters: a self-referential read skips ptrace_may_access and understates the cost.

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

#define REPS 200000
#define PATH_REPS 50000

// A static buffer, so the forked child holds the same path at the same virtual address the parent
// can name — the shape a supervisor faces, which knows the pointer from the notification.
static char target_path[4096];

int main(void) {
    const char *abs_path = "/etc/hostname";
    strcpy(target_path, "/home/user/project/src/some/reasonably/deep/module.rs");
    size_t plen = strlen(target_path) + 1;

    // Warm the dentry cache so this measures the syscall, not the disk.
    for (int i = 0; i < 100; i++) {
        int fd = open(abs_path, O_RDONLY);
        if (fd >= 0) close(fd);
    }

    // --- 1a. openat, absolute path ---
    double t0 = now_ns();
    for (int i = 0; i < REPS; i++) {
        int fd = openat(AT_FDCWD, abs_path, O_RDONLY);
        if (fd >= 0) close(fd);
    }
    double abs_total = now_ns() - t0;

    // The same loop without the open, to subtract the close and the loop overhead.
    int probe = open(abs_path, O_RDONLY);
    t0 = now_ns();
    for (int i = 0; i < REPS; i++) {
        int fd = dup(probe);
        if (fd >= 0) close(fd);
    }
    double dup_total = now_ns() - t0;
    close(probe);

    // --- 1b. openat relative to AT_FDCWD (the form a supervisor cannot resolve from the path alone) ---
    if (chdir("/etc") != 0) { perror("chdir"); return 1; }
    for (int i = 0; i < 100; i++) {
        int fd = open("hostname", O_RDONLY);
        if (fd >= 0) close(fd);
    }
    t0 = now_ns();
    for (int i = 0; i < REPS; i++) {
        int fd = openat(AT_FDCWD, "hostname", O_RDONLY);
        if (fd >= 0) close(fd);
    }
    double rel_total = now_ns() - t0;

    double abs_us = (abs_total - dup_total) / REPS / 1000.0;
    double rel_us = (rel_total - dup_total) / REPS / 1000.0;
    printf("openat absolute        : %6.3f us/call  (raw %.3f, minus dup+close %.3f)\n",
           abs_us, abs_total / REPS / 1000.0, dup_total / REPS / 1000.0);
    printf("openat AT_FDCWD-relative: %6.3f us/call\n", rel_us);

    // --- 2. reading that pathname out of a REMOTE process ---
    pid_t child = fork();
    if (child < 0) { perror("fork"); return 1; }
    if (child == 0) {
        // Keep the buffer live and stay parked; the parent reads it and kills us.
        for (;;) { pause(); }
    }
    usleep(50000);

    char mem_path[64];
    snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", (int)child);
    char out[4096];

    // 2a. open + pread + close, the shape the shipped exec supervisor uses.
    t0 = now_ns();
    for (int i = 0; i < PATH_REPS; i++) {
        int fd = open(mem_path, O_RDONLY);
        if (fd < 0) { perror("open /proc/pid/mem"); kill(child, SIGKILL); return 1; }
        ssize_t n = pread(fd, out, plen, (off_t)(uintptr_t)target_path);
        if (n <= 0) { perror("pread"); close(fd); kill(child, SIGKILL); return 1; }
        close(fd);
    }
    double mem_total = now_ns() - t0;

    // 2b. the same read with the fd opened once and kept.
    int memfd = open(mem_path, O_RDONLY);
    if (memfd < 0) { perror("open /proc/pid/mem"); kill(child, SIGKILL); return 1; }
    t0 = now_ns();
    for (int i = 0; i < PATH_REPS; i++) {
        if (pread(memfd, out, plen, (off_t)(uintptr_t)target_path) <= 0) {
            perror("pread"); close(memfd); kill(child, SIGKILL); return 1;
        }
    }
    double cached_total = now_ns() - t0;
    close(memfd);

    // 2c. process_vm_readv — one syscall, no fd at all.
    struct iovec local = { .iov_base = out, .iov_len = plen };
    struct iovec remote = { .iov_base = target_path, .iov_len = plen };
    t0 = now_ns();
    for (int i = 0; i < PATH_REPS; i++) {
        if (process_vm_readv(child, &local, 1, &remote, 1, 0) <= 0) {
            perror("process_vm_readv"); kill(child, SIGKILL); return 1;
        }
    }
    double pvr_total = now_ns() - t0;

    kill(child, SIGKILL);
    waitpid(child, NULL, 0);

    double mem_us = mem_total / PATH_REPS / 1000.0;
    double cached_us = cached_total / PATH_REPS / 1000.0;
    double pvr_us = pvr_total / PATH_REPS / 1000.0;
    printf("remote path read, open+pread+close : %6.3f us\n", mem_us);
    printf("remote path read, cached fd + pread: %6.3f us\n", cached_us);
    printf("remote path read, process_vm_readv : %6.3f us\n", pvr_us);
    printf("\nread as a multiple of one native absolute openat: %.1fx / %.1fx / %.1fx\n",
           mem_us / abs_us, cached_us / abs_us, pvr_us / abs_us);
    return 0;
}
