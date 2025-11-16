#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <math.h>

/* Version */
#define VERSION "1.0.0"
#define PROJECT_NAME "DDoS MPI Detector"

/* Limits and constants */
#define MAX_LINE_LENGTH 8192
#define MAX_IP_LENGTH 64
#define MAX_PATH_LENGTH 512
#define MAX_FIELD_LENGTH 256
#define MAX_COLUMNS 128
#define MAX_FLOWS_PER_WINDOW 10000
#define MAX_SUSPICIOUS_IPS 1024

/* MPI Tags */
#define TAG_WINDOW_META 100
#define TAG_WINDOW_DATA 101
#define TAG_RESULT_META 200
#define TAG_RESULT_DATA 201
#define TAG_TERMINATE 999

/* Detection thresholds */
#define DEFAULT_ENTROPY_THRESHOLD 0.20  /* Lowered for DrDoS/reflection attacks */
#define DEFAULT_PCA_THRESHOLD 2.5       /* Normalized deviation threshold */
#define DEFAULT_CUSUM_THRESHOLD 3.0     /* Cumulative sum threshold */
#define DEFAULT_WINDOW_SIZE 500
#define DEFAULT_MIN_IP_COUNT 5

/* ANSI color codes for CLI */
#define COLOR_RESET "\033[0m"
#define COLOR_RED "\033[1;31m"
#define COLOR_GREEN "\033[1;32m"
#define COLOR_YELLOW "\033[1;33m"
#define COLOR_BLUE "\033[1;34m"
#define COLOR_MAGENTA "\033[1;35m"
#define COLOR_CYAN "\033[1;36m"
#define COLOR_WHITE "\033[1;37m"
#define COLOR_BOLD "\033[1m"

/* Detection labels */
#define LABEL_BENIGN 0
#define LABEL_ATTACK 1

/* Operating modes */
typedef enum {
    MODE_DATASET,
    MODE_CUSTOM,
    MODE_LIVE
} OperatingMode;

/* Detector types */
typedef enum {
    DETECTOR_ENTROPY = 1 << 0,
    DETECTOR_PCA = 1 << 1,
    DETECTOR_CUSUM = 1 << 2
} DetectorType;

/* Common structures */
typedef struct {
    char ip[MAX_IP_LENGTH];
    int count;
} SuspiciousIP;

typedef struct {
    SuspiciousIP *entries;
    size_t count;
    size_t capacity;
} SuspiciousList;

typedef struct {
    int total_windows;
    int evaluated_windows;
    int attack_windows;
    int benign_windows;
    int truth_windows;  /* Actual attack windows from labels */
    int true_positives;
    int false_positives;
    int true_negatives;
    int false_negatives;
    double total_processing_time;
    double avg_window_time;
    long total_flows_processed;
    double throughput_flows_per_sec;
    
    /* Extended Performance Metrics */
    double detection_lead_time_ms;      /* Time from first attack to first detection */
    double min_window_time_ms;          /* Minimum processing time */
    double max_window_time_ms;          /* Maximum processing time */
    double percentile_95_latency_ms;    /* 95th percentile latency */
    double avg_packet_processing_us;    /* Average time per packet in microseconds */
    
    /* Throughput Metrics */
    long total_packets_processed;       /* Total packet count */
    double throughput_packets_per_sec;  /* Packets/second */
    double throughput_mbps;             /* Megabits per second */
    double throughput_gbps;             /* Gigabits per second */
    
    /* Resource Utilization (estimated) */
    double avg_cpu_utilization;         /* Estimated CPU usage percentage */
    long peak_memory_bytes;             /* Peak memory usage */
    double avg_memory_mb;               /* Average memory in MB */
    
    /* Mitigation Effectiveness */
    int total_ips_detected;             /* Total suspicious IPs found */
    int total_ips_blocked;              /* Total IPs actually blocked */
    double attack_traffic_blocked_pct;  /* % of attack traffic blocked */
    double false_positive_impact_pct;   /* % of benign traffic affected */
    
    /* Scalability Metrics */
    int mpi_processes_used;             /* Number of MPI processes */
    double parallel_efficiency;         /* Speedup / #processes */
    double load_balance_factor;         /* Work distribution evenness */
} PerformanceMetrics;

/* Utility macros */
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define CLAMP(x, min, max) (MIN(MAX((x), (min)), (max)))

/* Function declarations */
void print_header(void);
void print_colored(const char *color, const char *format, ...);
double get_timestamp(void);
void suspicious_list_init(SuspiciousList *list);
void suspicious_list_add(SuspiciousList *list, const char *ip);
void suspicious_list_free(SuspiciousList *list);
int suspicious_list_write_csv(const SuspiciousList *list, const char *path, 
                               const char *detector_name, int min_count);

#endif /* COMMON_H */
