// The end-to-end price of putting `openat` behind a seccomp user-notification, measured rather than
// summed from parts. Summing understates it: the notifying task is *parked* for the whole exchange,
// so what it pays is two context switches plus the supervisor's work, not the supervisor's work
// alone.
//
// A child installs a NEW_LISTENER filter matching only openat, hands the listener fd to the parent
// over a socketpair, then times a loop of openat. The parent serves each notification, in three
// escalating shapes, so the cost of each added step is separable:
//
//   continue-only   RECV -> SEND(CONTINUE)                       the floor: pure round trip
//   +path read      RECV -> read the pathname -> SEND(CONTINUE)  what a policy actually needs
//   +errno          RECV -> read -> SEND(errno)                  the refusal path
//
// The baseline column runs the identical loop with no filter installed at all.

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
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

#define REPS 40000
#define MODE_CONTINUE 0
#define MODE_READ 1
#define MODE_ERRNO 2

static double now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1e9 + (double)ts.tv_nsec;
}

static int seccomp_syscall(unsigned int op, unsigned int flags, void *args) {
    return (int)syscall(SYS_seccomp, op, flags, args);
}

// Send `fd` over `sock` as an SCM_RIGHTS ancillary message.
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

// Match only openat on the native arch; everything else runs unfiltered.
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
    return seccomp_syscall(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER, &fprog);
}

// Serve exactly `count` notifications in the given mode, then return.
static void supervise(int listener, pid_t child, int mode, long count) {
    struct seccomp_notif *req = calloc(1, sizeof(*req));
    struct seccomp_notif_resp *resp = calloc(1, sizeof(*resp));
    char mem_path[64], path[4096];
    snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", (int)child);
    // A per-pid cached fd — the shape a real supervisor would use for a long-lived cage process.
    int memfd = open(mem_path, O_RDONLY);

    for (long i = 0; i < count; i++) {
        memset(req, 0, sizeof(*req));
        if (ioctl(listener, SECCOMP_IOCTL_NOTIF_RECV, req) != 0) {
            if (errno == EINTR) { i--; continue; }
            break;
        }
        if (mode != MODE_CONTINUE && memfd >= 0) {
            // args[1] is openat's pathname pointer.
            ssize_t n = pread(memfd, path, sizeof(path) - 1, (off_t)req->data.args[1]);
            if (n > 0) path[n - 1] = '\0';
        }
        memset(resp, 0, sizeof(*resp));
        resp->id = req->id;
        if (mode == MODE_ERRNO) {
            resp->error = -EPERM;
        } else {
            resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
        }
        if (ioctl(listener, SECCOMP_IOCTL_NOTIF_SEND, resp) != 0 && errno != ENOENT) break;
    }
    if (memfd >= 0) close(memfd);
    free(req);
    free(resp);
}

int main(void) {
    const char *path = "/etc/hostname";

    // --- baseline: the same loop, no filter ---
    for (int i = 0; i < 100; i++) { int fd = open(path, O_RDONLY); if (fd >= 0) close(fd); }
    double t0 = now_ns();
    for (int i = 0; i < REPS; i++) {
        int fd = openat(AT_FDCWD, path, O_RDONLY);
        if (fd >= 0) close(fd);
    }
    double base_us = (now_ns() - t0) / REPS / 1000.0;
    printf("openat, no filter          : %7.3f us/call\n", base_us);

    const char *names[] = { "CONTINUE only", "CONTINUE + path read", "errno EPERM + path read" };
    for (int mode = 0; mode <= MODE_ERRNO; mode++) {
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { perror("socketpair"); return 1; }

        pid_t child = fork();
        if (child < 0) { perror("fork"); return 1; }
        if (child == 0) {
            close(sv[0]);
            int listener = install_filter();
            if (listener < 0) { perror("seccomp"); _exit(1); }
            if (send_fd(sv[1], listener) != 0) { perror("send_fd"); _exit(1); }
            close(listener);
            // Wait for the parent to be ready to serve.
            char go;
            if (read(sv[1], &go, 1) != 1) _exit(1);

            double c0 = now_ns();
            for (int i = 0; i < REPS; i++) {
                int fd = openat(AT_FDCWD, path, O_RDONLY);
                if (fd >= 0) close(fd);
            }
            double per = (now_ns() - c0) / REPS / 1000.0;
            // The write itself is an openat-free syscall, so it does not perturb the loop.
            if (write(sv[1], &per, sizeof(per)) != sizeof(per)) _exit(1);
            _exit(0);
        }

        close(sv[1]);
        int listener = recv_fd(sv[0]);
        if (listener < 0) { perror("recv_fd"); return 1; }
        if (write(sv[0], "g", 1) != 1) { perror("go"); return 1; }
        supervise(listener, child, mode, REPS);

        double per = 0;
        if (read(sv[0], &per, sizeof(per)) != sizeof(per)) {
            printf("%-26s: child did not report\n", names[mode]);
        } else {
            printf("%-26s: %7.3f us/call  (+%.3f us, %.1fx native)\n",
                   names[mode], per, per - base_us, per / base_us);
        }
        close(listener);
        close(sv[0]);
        waitpid(child, NULL, 0);
    }
    return 0;
}
