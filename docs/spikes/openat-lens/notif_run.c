// Runs a real command under an openat user-notification filter and reports what it cost, so the
// verdict rests on a workload rather than on a microbenchmark extrapolated by multiplication.
//
// usage: notif_run <0|1 read the path> -- <command> [args...]
//
// The child installs the filter, hands the listener to this process, and execs the command; the
// filter is inherited by everything the command spawns. The supervisor serves every notification
// with CONTINUE (the allow verdict), keeping one cached /proc/<pid>/mem fd per caller pid.

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <poll.h>
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

#define PID_SLOTS 65536

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
    if (argc < 4 || strcmp(argv[2], "--") != 0) {
        fprintf(stderr, "usage: %s <0|1 read path> -- <command> [args...]\n", argv[0]);
        return 2;
    }
    int read_path = atoi(argv[1]);
    char **cmd = &argv[3];

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { perror("socketpair"); return 1; }

    double start = now_ns();
    pid_t child = fork();
    if (child < 0) { perror("fork"); return 1; }
    if (child == 0) {
        close(sv[0]);
        int listener = install_filter();
        if (listener < 0) { perror("seccomp"); _exit(127); }
        if (send_fd(sv[1], listener) != 0) _exit(127);
        close(listener);
        char go;
        if (read(sv[1], &go, 1) != 1) _exit(127);
        close(sv[1]);
        execvp(cmd[0], cmd);
        perror("execvp");
        _exit(127);
    }

    close(sv[1]);
    int listener = recv_fd(sv[0]);
    if (listener < 0) { perror("recv_fd"); return 1; }
    if (write(sv[0], "g", 1) != 1) return 1;

    struct seccomp_notif *req = calloc(1, sizeof(*req));
    struct seccomp_notif_resp *resp = calloc(1, sizeof(*resp));
    static int memfd[PID_SLOTS];
    static int mempid[PID_SLOTS];
    for (int i = 0; i < PID_SLOTS; i++) { memfd[i] = -1; mempid[i] = -1; }
    char path[4096];

    long served = 0, distinct = 0;
    double supervisor_ns = 0;
    int status = 0, done = 0;
    while (!done) {
        struct pollfd pfd = { .fd = listener, .events = POLLIN };
        int pr = poll(&pfd, 1, 100);
        if (pr < 0 && errno != EINTR) break;
        // When the last filtered process is gone the listener hangs up, and RECV then returns
        // ENOENT on a fd poll() keeps reporting ready — a busy loop if the hangup is not the exit.
        if (pfd.revents & (POLLHUP | POLLERR)) break;
        if (pr == 0) {
            if (waitpid(child, &status, WNOHANG) == child) done = 1;
            continue;
        }
        memset(req, 0, sizeof(*req));
        if (ioctl(listener, SECCOMP_IOCTL_NOTIF_RECV, req) != 0) {
            if (errno == EINTR) continue;
            break;
        }
        double w0 = now_ns();
        if (read_path) {
            int slot = (int)(req->pid % PID_SLOTS);
            if (mempid[slot] != (int)req->pid) {
                if (memfd[slot] >= 0) close(memfd[slot]);
                char mp[64];
                snprintf(mp, sizeof(mp), "/proc/%d/mem", (int)req->pid);
                memfd[slot] = open(mp, O_RDONLY);
                mempid[slot] = (int)req->pid;
                distinct++;
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
        supervisor_ns += now_ns() - w0;
        served++;
    }
    if (!done) waitpid(child, &status, 0);
    double wall = (now_ns() - start) / 1e9;

    fprintf(stderr,
            "\n[notif_run] wall %.2fs | %ld notifications (%ld distinct pids) | %.0f/s | "
            "supervisor %.2f us each, %.2fs total | path read %s | exit %d\n",
            wall, served, distinct, served / wall, supervisor_ns / (double)(served ? served : 1) / 1000.0,
            supervisor_ns / 1e9, read_path ? "on" : "off", WEXITSTATUS(status));
    return 0;
}
