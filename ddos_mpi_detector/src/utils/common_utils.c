#include "../include/common.h"
#include <stdarg.h>
#include <sys/time.h>

/* Print colorful project header */
void print_header(void) {
    printf("\n");
    printf("%s╔══════════════════════════════════════════════════════════════╗%s\n", COLOR_CYAN, COLOR_RESET);
    printf("%s║                                                              ║%s\n", COLOR_CYAN, COLOR_RESET);
    printf("%s║       %sDDoS Detection & Mitigation System (MPI)%s            ║%s\n", 
           COLOR_CYAN, COLOR_BOLD, COLOR_CYAN, COLOR_RESET);
    printf("%s║       %sHigh-Performance Network Traffic Analyzer%s            ║%s\n", 
           COLOR_CYAN, COLOR_WHITE, COLOR_CYAN, COLOR_RESET);
    printf("%s║                                                              ║%s\n", COLOR_CYAN, COLOR_RESET);
    printf("%s║       Version: %s%-8s%s                                   ║%s\n", 
           COLOR_CYAN, COLOR_GREEN, VERSION, COLOR_CYAN, COLOR_RESET);
    printf("%s╚══════════════════════════════════════════════════════════════╝%s\n", COLOR_CYAN, COLOR_RESET);
    printf("\n");
}

/* Print colored output */
void print_colored(const char *color, const char *format, ...) {
    va_list args;
    printf("%s", color);
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    printf("%s", COLOR_RESET);
}

/* Get current timestamp in seconds with microsecond precision */
double get_timestamp(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec + tv.tv_usec / 1000000.0;
}

/* Initialize suspicious IP list */
void suspicious_list_init(SuspiciousList *list) {
    if (!list) return;
    list->entries = NULL;
    list->count = 0;
    list->capacity = 0;
}

/* Add IP to suspicious list */
void suspicious_list_add(SuspiciousList *list, const char *ip) {
    if (!list || !ip || strlen(ip) == 0) return;
    
    /* Check if IP already exists */
    for (size_t i = 0; i < list->count; i++) {
        if (strcmp(list->entries[i].ip, ip) == 0) {
            list->entries[i].count++;
            return;
        }
    }
    
    /* Expand capacity if needed */
    if (list->count >= list->capacity) {
        size_t new_capacity = (list->capacity == 0) ? 16 : (list->capacity * 2);
        SuspiciousIP *new_entries = realloc(list->entries, 
                                            new_capacity * sizeof(SuspiciousIP));
        if (!new_entries) {
            fprintf(stderr, "Failed to allocate memory for suspicious list\n");
            return;
        }
        list->entries = new_entries;
        list->capacity = new_capacity;
    }
    
    /* Add new entry */
    strncpy(list->entries[list->count].ip, ip, MAX_IP_LENGTH - 1);
    list->entries[list->count].ip[MAX_IP_LENGTH - 1] = '\0';
    list->entries[list->count].count = 1;
    list->count++;
}

/* Free suspicious IP list */
void suspicious_list_free(SuspiciousList *list) {
    if (!list) return;
    free(list->entries);
    list->entries = NULL;
    list->count = 0;
    list->capacity = 0;
}

/* Write suspicious IPs to CSV file */
int suspicious_list_write_csv(const SuspiciousList *list, const char *path, 
                               const char *detector_name, int min_count) {
    if (!list || !path || list->count == 0) return 0;
    
    FILE *fp = fopen(path, "w");
    if (!fp) {
        perror("Failed to open blocklist file");
        return -1;
    }
    
    fprintf(fp, "ip,count,detector\n");
    
    int written = 0;
    for (size_t i = 0; i < list->count; i++) {
        if (list->entries[i].count >= min_count) {
            fprintf(fp, "%s,%d,%s\n", 
                   list->entries[i].ip, 
                   list->entries[i].count, 
                   detector_name);
            written++;
        }
    }
    
    fclose(fp);
    return written;
}
