// Isolates the one condition that could explain why the shipped exec supervisor measured 11.9 us
// for a remote pathname read while a plain same-namespace read of the same shape costs ~1.5 us:
// the cage target lives in a *descendant user namespace*, so every /proc/<pid>/mem access pays
// ptrace_may_access across that boundary, plus whatever the host LSM mediates.
//
// Two children hold the same static buffer at the same address. One stays in this namespace; the
// other calls unshare(CLONE_NEWUSER|CLONE_NEWNS) first. Everything else about the read is identical,
// so the difference between the two columns is the boundary's price and nothing else.

#define _GNU_SOURCE
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
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

#define REPS 30000

static char target_path[4096];

static pid_t park_child(int unshare_userns) {
    pid_t pid = fork();
    if (pid != 0) return pid;
    if (unshare_userns && unshare(CLONE_NEWUSER | CLONE_NEWNS) != 0) {
        perror("unshare");
        _exit(1);
    }
    for (;;) pause();
}

// Times the three read mechanisms against `pid`, printing one labelled row each.
static void bench(const char *label, pid_t pid, size_t plen) {
    char mem_path[64], out[4096];
    snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", (int)pid);

    double t0 = now_ns();
    for (int i = 0; i < REPS; i++) {
        int fd = open(mem_path, O_RDONLY);
        if (fd < 0) { printf("%-22s open /proc/%d/mem failed\n", label, pid); return; }
        if (pread(fd, out, plen, (off_t)(uintptr_t)target_path) <= 0) {
            printf("%-22s pread failed\n", label);
            close(fd);
            return;
        }
        close(fd);
    }
    double fresh = (now_ns() - t0) / REPS / 1000.0;

    int memfd = open(mem_path, O_RDONLY);
    t0 = now_ns();
    for (int i = 0; i < REPS; i++) {
        if (pread(memfd, out, plen, (off_t)(uintptr_t)target_path) <= 0) break;
    }
    double cached = (now_ns() - t0) / REPS / 1000.0;
    close(memfd);

    struct iovec local = { .iov_base = out, .iov_len = plen };
    struct iovec remote = { .iov_base = target_path, .iov_len = plen };
    t0 = now_ns();
    int pvr_ok = 1;
    for (int i = 0; i < REPS; i++) {
        if (process_vm_readv(pid, &local, 1, &remote, 1, 0) <= 0) { pvr_ok = 0; break; }
    }
    double pvr = (now_ns() - t0) / REPS / 1000.0;

    printf("%-22s open+pread+close %6.3f us | cached fd %6.3f us | process_vm_readv %6.3f us%s\n",
           label, fresh, cached, pvr, pvr_ok ? "" : " (FAILED)");
}

int main(void) {
    strcpy(target_path, "/home/user/project/src/some/reasonably/deep/module.rs");
    size_t plen = strlen(target_path) + 1;

    pid_t same = park_child(0);
    pid_t nested = park_child(1);
    usleep(200000);

    bench("same namespace", same, plen);
    bench("descendant userns", nested, plen);

    kill(same, SIGKILL);
    kill(nested, SIGKILL);
    waitpid(same, NULL, 0);
    waitpid(nested, NULL, 0);
    return 0;
}
