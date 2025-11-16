#ifndef ORCHESTRATOR_H
#define ORCHESTRATOR_H

#include "common.h"
#include "flow_types.h"
#include "detectors.h"
#include <mpi.h>

/* Configuration */
typedef struct {
    OperatingMode mode;
    char input_path[MAX_PATH_LENGTH];
    char output_dir[MAX_PATH_LENGTH];
    char interface[64];
    int window_size;
    double entropy_threshold;
    double pca_threshold;
    double cusum_threshold;
    int detector_mask;  /* Bitfield of DetectorType */
    bool enable_mitigation;
    int min_ip_count;
    char rate_limit[32];
    char rate_burst[32];
    int capture_duration_sec;
    int pca_components;
    int pca_warmup_windows;
    double cusum_drift;
    bool verbose;
} OrchestratorConfig;

/* MPI context */
typedef struct {
    int world_size;
    int world_rank;
    bool is_master;
} MPIContext;

/* Main orchestrator functions */
int orchestrator_init(int argc, char **argv, OrchestratorConfig *config, MPIContext *mpi_ctx);
int orchestrator_run(const OrchestratorConfig *config, const MPIContext *mpi_ctx);
void orchestrator_cleanup(void);

/* Master node functions */
int master_coordinate_dataset_analysis(const OrchestratorConfig *config, const MPIContext *mpi_ctx, int is_live_mode);
int master_coordinate_live_capture(const OrchestratorConfig *config, const MPIContext *mpi_ctx);
void master_collect_results(WindowResult *results, int num_windows, const MPIContext *mpi_ctx);
void master_generate_reports(const WindowResult *results, int num_windows, 
                             const OrchestratorConfig *config, 
                             const PerformanceMetrics *metrics);

/* Worker node functions */
void worker_process_windows(const OrchestratorConfig *config, const MPIContext *mpi_ctx);

/* Configuration parsing */
int parse_command_line(int argc, char **argv, OrchestratorConfig *config);
void print_usage(const char *program_name);
void print_config(const OrchestratorConfig *config);

/* Utilities */
void calculate_performance_metrics(const WindowResult *results, int num_windows, 
                                   PerformanceMetrics *metrics);
void print_performance_summary(const PerformanceMetrics *metrics);
void print_detector_performance(const WindowResult *results, int num_windows);

#endif /* ORCHESTRATOR_H */
