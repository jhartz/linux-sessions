/*
 * Linux Sessions
 *
 * Find the timestamps of recent user sessions by reading wtmp.
 *
 * Much inspired by the implementation of "last" in util-linux:
 * https://github.com/karelzak/util-linux/blob/master/login-utils/last.c
 *
 * Jake Hartz
 */

#define _GNU_SOURCE

#include <errno.h>
#include <getopt.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <utmpx.h>

#ifndef RUN_LVL
# define RUN_LVL 1
#endif
#ifndef SHUTDOWN_TIME
# define SHUTDOWN_TIME 254
#endif

struct utmpx_list {
    struct utmpx ut;
    struct utmpx_list *prev;
    struct utmpx_list *next;
};

char *strftime_format;
bool exclude_active;
bool exclude_inactive;
int num_sessions;
time_t after_time;
time_t before_time;
bool print_extra;

char *username;
struct passwd *pw;

void *xmalloc(const size_t size, const char *msg) {
    void *p = malloc(size);
    if (!p) {
        perror(msg);
        exit(1);
    }
    return p;
}

#define omalloc(type)   ((type *) malloc(sizeof(type)))
#define xomalloc(type)  ((type *) xmalloc(sizeof(type), "Error allocating " #type))

/**
 * struct utmpx's we've found for dead processes.
 * Since we process wtmp in reverse order, these are used to determine if a
 * login is dead yet or not.
 */
struct utmpx_list *dead_uts;

/**
 * Determine if the tty/pid in ut doesn't exist anymore.
 *
 * Based on "is_phantom" in "last".
 */
bool is_phantom(const struct utmpx *ut) {
    char *path = NULL;
    asprintf(&path, "/proc/%u/loginuid", ut->ut_pid);
    if (access(path, R_OK) == 0) {
        // loginuid file exists for ut_pid
        FILE *f = fopen(path, "r");
        if (f == NULL) {
            return true;
        }

        bool ret = false;
        unsigned int loginuid;
        if (fscanf(f, "%u", &loginuid) != 1) {
            // Couldn't read loginuid; assume phantom
            ret = true;
        } else {
            // It's a phantom if the loginuid is different
            ret = pw->pw_uid != loginuid;
        }
        fclose(f);
        free(path);
        return ret;
    } else {
        free(path);
    }

    // No access to loginuid file - probably phantom, but check ut_line to be
    // sure.
    struct stat st;
    asprintf(&path, "/dev/%s", ut->ut_line);
    if (stat(path, &st)) {
        // Failed to stat
        free(path);
        return true;
    } else {
        free(path);
    }

    // It's a phantom if the tty's uid is different
    return pw->pw_uid != st.st_uid;
}

/**
 * Process a struct utmpx read (in reverse order) from wtmp. Returns true if a
 * timestamp was printed.
 *
 * Based on "process_wtmp_file" in "last".
 */
bool handle_ut(struct utmpx *ut) {
    // Fix ut_type
    if (ut->ut_line[0] == '~') {
        if (strncmp(ut->ut_user, "shutdown", 8) == 0) {
            ut->ut_type = SHUTDOWN_TIME;
        } else if (strncmp(ut->ut_user, "reboot", 6) == 0) {
            ut->ut_type = BOOT_TIME;
        } else if (strncmp(ut->ut_user, "runlevel", 8) == 0) {
            ut->ut_type = RUN_LVL;
        }
    } else {
        if (ut->ut_type != DEAD_PROCESS
                && ut->ut_user[0]
                && ut->ut_line[0]
                && strcmp(ut->ut_user, "LOGIN") != 0) {
            ut->ut_type = USER_PROCESS;
        }

        if (ut->ut_user[0] == '\0') {
            ut->ut_type = DEAD_PROCESS;
        }
    }

    // Determine if ut indicated a shutdown or reboot
    bool system_down = false;
    int x;
    switch (ut->ut_type) {
        case SHUTDOWN_TIME:
            system_down = true;
            break;

        case BOOT_TIME:
            system_down = true;
            break;

        case RUN_LVL:
            x = ut->ut_pid & 255;
            if (x == '0' || x == '6') {
                system_down = true;
            }
            break;
    }
    if (system_down) {
        // It's a shutdown/reboot; remove all future dead entries we've saved,
        // then return
        struct utmpx_list *p = dead_uts;
        while (p) {
            struct utmpx_list *n = p->next;
            free(p);
            p = n;
        }
        dead_uts = NULL;
        return false;
    }

    // Store dead processes. Not all of them wil have usernames, but we need
    // to store that the tty died for below.
    if (ut->ut_type == DEAD_PROCESS && ut->ut_line[0] != '\0') {
        struct utmpx_list *p = xomalloc(struct utmpx_list);
        memcpy(&p->ut, ut, sizeof(struct utmpx));
        p->next = dead_uts;
        p->prev = NULL;
        if (dead_uts) {
            dead_uts->prev = p;
        }
        dead_uts = p;
        return false;
    }

    // From here on down, we only care about USER_PROCESS entries for the
    // username we're looking for.
    if (ut->ut_type != USER_PROCESS
            || ut->ut_user[0] == '\0'
            || strncmp(ut->ut_user, username, 32) != 0) {
        return false;
    }

    // Find the first matching logout record in the future and delete all
    // existing records with the same ut_line.
    // If we find a logout record, then we can say the session is no longer
    // active.
    bool active = true;
    struct utmpx_list *p = dead_uts;
    while (p) {
        struct utmpx_list *n = p->next;
        if (strcmp(p->ut.ut_line, ut->ut_line) == 0) {
            active = false;
            if (p->next) {
                p->next->prev = p->prev;
            }
            if (p->prev) {
                p->prev->next = p->next;
            } else {
                dead_uts = p->next;
            }
            free(p);
        }
        p = n;
    }

    // Make sure it's within our time range. (We have to do this after checking
    // dead_uts to make sure that list stays in good condition.)
    time_t t = ut->ut_tv.tv_sec;
    if (after_time> 0 && t < after_time) {
        return false;
    }
    if (before_time> 0 && t > before_time) {
        return false;
    }

    if (active) {
        // No logout record found. Make sure the pid/tty still exist.
        active = !is_phantom(ut);
    }

    if ((active && !exclude_active) || (!active && !exclude_inactive)) {
        // Found a match!
        if (strftime_format != NULL) {
            static char buf[100];
            size_t written = strftime(buf, 100, strftime_format, localtime(&t));
            if (written > 0) {
                printf("%s", buf);
            }
        } else {
            char *ct = ctime(&t);
            ct[strlen(ct) - 1] = '\0';
            printf("%s", ct);
        }
        if (print_extra) {
            printf("\t%s\t%s", ut->ut_host, ut->ut_line);
        }
        putchar('\n');
        return true;
    }
    return false;
}

void print_usage(void) {
    printf("Usage: sessions [options] <username>\n");
    printf("  -f, --format <fmt>  The strftime format to use to print out timestamps.\n");
    printf("  -a, --active        Only print timestamps for sessions that are currently active.\n");
    printf("  -i, --inactive      Only print timestamps for sessions that are no longer active.\n");
    printf("  -n, --num <num>     Maximum number of timestamps to print.\n");
    printf("  -t, --after <ts>    Only print timestamps after the unix timestamp <ts>.\n");
    printf("  -b, --before <ts>   Only print timestamps before the unix timestamp <ts>.\n");
    printf("  -p, --print-extra   Print extra information with each timestamp.\n");
    printf("  -h, --help          Print this usage message.\n");
    printf("\n");
    printf("sessions works by reading from /var/log/wtmp.\n");
}

int main(int argc, char **argv) {
    static const struct option opts[] = {
        { "format",      required_argument, NULL, 'f' },
        { "active",      no_argument,       NULL, 'a' },
        { "inactive",    no_argument,       NULL, 'i' },
        { "num",         required_argument, NULL, 'n' },
        { "after",       required_argument, NULL, 't' },
        { "before",      required_argument, NULL, 'b' },
        { "print-extra", no_argument,       NULL, 'p' },
        { "help",        no_argument,       NULL, 'h' },
        { 0, 0, 0, 0 }
    };

    int c;
    while ((c = getopt_long(argc, argv, "f:ain:t:b:ph", opts, NULL)) != -1) {
        switch (c) {
            case 'f':
                strftime_format = strdup(optarg);
                break;
            case 'a':
                exclude_inactive = true;
                break;
            case 'i':
                exclude_active = true;
                break;
            case 'n':
                num_sessions = atoi(optarg);
                break;
            case 't':
                after_time = strtol(optarg, NULL, 10);
                break;
            case 'b':
                before_time = strtol(optarg, NULL, 10);
                break;
            case 'p':
                print_extra = true;
                break;
            default:
                print_usage();
                return 2;
        }
    }

    if (argc - optind != 1) {
        fprintf(stderr, "Missing username.\n");
        print_usage();
        return 2;
    }

    if (exclude_active && exclude_inactive) {
        fprintf(stderr, "Cannot exclude both active and inactive sessions.\n");
        return 1;
    }

    username = argv[optind];
    if (strlen(username) > 32) {
        fprintf(stderr, "Maximum username length is 32 bytes.\n");
        return 1;
    }

    errno = 0;
    pw = getpwnam(username);
    if (pw == NULL) {
        if (errno) {
            perror("Unknown username");
        } else {
            fprintf(stderr, "Unknown username: %s\n", username);
        }
        return 1;
    }

    FILE *fp = fopen("/var/log/wtmp", "r");
    if (fp == NULL) {
        perror("Error opening wtmp");
        return 1;
    }

    // Everything below here should set "status" and then "goto cleanup"
    // instead of exiting directly.
    int status = 0;

    // Set to block buffering, rather than line buffering.
    // 16384 is a magic number from "last".
    if (setvbuf(fp, NULL, _IOFBF, 16384) != 0) {
        perror("Error setting buffer");
        status = 1;
        goto cleanup;
    }

    const size_t utsize = sizeof(struct utmpx);
    off_t utpos;

    fseeko(fp, 0, SEEK_END);
    utpos = ftello(fp);
    if (utpos == -1) {
        perror("Error telling position");
        status = 1;
        goto cleanup;
    }
    if (utpos == 0) {
        // No entries in wtmp
        goto cleanup;
    }

    // Go to the start of the last entry
    utpos = ((utpos - 1) / utsize) * utsize;

    int count = 0;
    struct utmpx ut;
    for (; utpos >= 0; utpos -= utsize) {
        fseeko(fp, utpos, SEEK_SET);
        utpos = ftell(fp);
        if (utpos == -1) {
            perror("Error telling position");
            status = 1;
            goto cleanup;
        }
        if (utpos % utsize != 0) {
            fprintf(stderr, "Expected file position (%jd) to be a multiple of %lu\n",
                    (intmax_t) utpos, utsize);
            status = 1;
            goto cleanup;
        }

        size_t items_read = fread(&ut, utsize, 1, fp);
        if (items_read == 0 && ferror(fp)) {
            perror("Error reading wtmp");
            status = 1;
            goto cleanup;
        }

        count += handle_ut(&ut);
        if (num_sessions > 0 && count >= num_sessions) {
            break;
        }
    }

cleanup:
    fclose(fp);
    return status;
}

