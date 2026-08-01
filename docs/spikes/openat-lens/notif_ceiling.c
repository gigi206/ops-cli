// The aggregate throughput ceiling an openat user-notification lens would impose on a whole cage.
//
// This is the number that matters, and it is not the per-call latency. A seccomp filter is inherited
// across fork and exec, and a second NEW_LISTENER returns EBUSY, so every process in the cage shares
// ONE listener served by ONE receive loop. Per-notification work is therefore a cage-wide ceiling,
// not a per-caller cost: past it, a parallel build does not slow down proportionally — it serializes.
//
// W workers, all descendants of one filtered process, hammer openat for a fixed wall-clock window.
// The supervisor counts what it served. The answer is notifications per second, aggregate.

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef SECCOMP_FILTER_FLAG_NEW_LISTENER
#define SECCOMP_FILTER_FLAG_NEW_LISTENER (1UL << 3)
#endif
#ifndef SECCOMP_USER_NOTIF_FLAG_CONTINUE
#define SECCOMP_USER_NOTIF_FLAG_CONTINUE (1UL << 0)
#endif

#define WINDOW_NS 3000000000.0

static double now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1e9 + (double)ts.tv_nsec;
}

static int send_fd(int sock, int fd) {
    char dummy = 'x';
    struct iovec iov = { .iov_base = &dummy, .iov_len = 1 };
    char cbuf[CMSG_SPACE(sizeof(int))];
    memset(cbuf, 0, sizeof(cbuf));
    struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1,
                          .msg_control = cbuf, .msg_controllen = sizeof(cbuf) };
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));
    return sendmsg(sock, &msg, 0) < 0 ? -1 : 0;
}

static int recv_fd(int sock) {
    char dummy;
    struct iovec iov = { .iov_base = &dummy, .iov_len = 1 };
    char cbuf[CMSG_SPACE(sizeof(int))];
    memset(cbuf, 0, sizeof(cbuf));
    struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1,
                          .msg_control = cbuf, .msg_controllen = sizeof(cbuf) };
    if (recvmsg(sock, &msg, 0) < 0) return -1;
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    if (!cmsg || cmsg->cmsg_type != SCM_RIGHTS) return -1;
    int fd;
    memcpy(&fd, CMSG_DATA(cmsg), sizeof(int));
    return fd;
}

static int install_filter(void) {
    struct sock_filter prog[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 0, 3),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_openat, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog fprog = { .len = sizeof(prog) / sizeof(prog[0]), .filter = prog };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) return -1;
    return (int)syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER,
                        &fprog);
}

int main(int argc, char **argv) {
    int workers = argc > 1 ? atoi(argv[1]) : 4;
    int read_path = argc > 2 ? atoi(argv[2]) : 1;

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { perror("socketpair"); return 1; }

    pid_t root = fork();
    if (root < 0) { perror("fork"); return 1; }
    if (root == 0) {
        close(sv[0]);
        // Own process group, so the whole worker fleet is sweepable in one kill even though the
        // workers are this process's children and would otherwise be orphaned by its death.
        setsid();
        int listener = install_filter();
        if (listener < 0) { perror("seccomp"); _exit(1); }
        if (send_fd(sv[1], listener) != 0) _exit(1);
        close(listener);
        char go;
        if (read(sv[1], &go, 1) != 1) _exit(1);
        // The filter is inherited, so every worker below notifies on the same listener.
        for (int i = 0; i < workers; i++) {
            if (fork() == 0) {
                // A hard deadline as well as the group kill below: a worker that outlived its
                // supervisor would spin a core forever, and this is a throwaway.
                double deadline = now_ns() + WINDOW_NS * 4;
                while (now_ns() < deadline) {
                    for (int k = 0; k < 1000; k++) {
                        int fd = openat(AT_FDCWD, "/etc/hostname", O_RDONLY);
                        if (fd >= 0) close(fd);
                    }
                }
                _exit(0);
            }
        }
        for (;;) pause();
    }

    close(sv[1]);
    int listener = recv_fd(sv[0]);
    if (listener < 0) { perror("recv_fd"); return 1; }
    if (write(sv[0], "g", 1) != 1) return 1;

    struct seccomp_notif *req = calloc(1, sizeof(*req));
    struct seccomp_notif_resp *resp = calloc(1, sizeof(*resp));
    char path[4096];
    // One cached /proc/<pid>/mem fd per worker pid, the shape a real supervisor would keep.
    int memfd[4096];
    for (int i = 0; i < 4096; i++) memfd[i] = -1;

    long served = 0;
    double start = now_ns();
    while (now_ns() - start < WINDOW_NS) {
        memset(req, 0, sizeof(*req));
        if (ioctl(listener, SECCOMP_IOCTL_NOTIF_RECV, req) != 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (read_path) {
            int slot = (int)(req->pid % 4096);
            if (memfd[slot] < 0) {
                char mp[64];
                snprintf(mp, sizeof(mp), "/proc/%d/mem", (int)req->pid);
                memfd[slot] = open(mp, O_RDONLY);
            }
            if (memfd[slot] >= 0) {
                ssize_t n = pread(memfd[slot], path, sizeof(path) - 1, (off_t)req->data.args[1]);
                if (n > 0) path[n - 1] = '\0';
            }
        }
        memset(resp, 0, sizeof(*resp));
        resp->id = req->id;
        resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
        if (ioctl(listener, SECCOMP_IOCTL_NOTIF_SEND, resp) != 0 && errno != ENOENT) break;
        served++;
    }
    double elapsed = (now_ns() - start) / 1e9;

    printf("%2d workers, path read %s : %8.0f notifications/s  (%.2f us of supervisor time each)\n",
           workers, read_path ? "on " : "off", served / elapsed, elapsed * 1e6 / (double)served);

    // `root` called setsid(), so its pid is the group id the workers inherited: one kill sweeps all.
    kill(-root, SIGKILL);
    kill(root, SIGKILL);
    waitpid(root, NULL, 0);
    return 0;
}
