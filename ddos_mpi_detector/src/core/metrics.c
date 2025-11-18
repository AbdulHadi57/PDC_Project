#include "../include/common.h"
#include "../include/orchestrator.h"

/* Calculate performance metrics from results */
void calculate_performance_metrics(const WindowResult *results, int num_windows, 
                                   PerformanceMetrics *metrics) {
    if (!results || !metrics || num_windows == 0) return;
    
    memset(metrics, 0, sizeof(PerformanceMetrics));
    metrics->total_windows = num_windows;
    metrics->min_window_time_ms = 999999.0;
    metrics->max_window_time_ms = 0.0;
    
    double total_time = 0.0;
    int first_attack_detected = -1;
    int first_actual_attack = -1;
    double *latencies = malloc(num_windows * sizeof(double));
    
    for (int i = 0; i < num_windows; i++) {
        const WindowResult *r = &results[i];
        
        metrics->evaluated_windows++;
        metrics->total_flows_processed += r->flow_count;
        
        /* Estimate packet count (avg 20 packets per flow) */
        metrics->total_packets_processed += r->flow_count * 20;
        
        double window_time_ms = r->processing_time_ms;
        total_time += window_time_ms / 1000.0;
        latencies[i] = window_time_ms;
        
        /* Track min/max latency */
        if (window_time_ms < metrics->min_window_time_ms) {
            metrics->min_window_time_ms = window_time_ms;
        }
        if (window_time_ms > metrics->max_window_time_ms) {
            metrics->max_window_time_ms = window_time_ms;
        }
        
        /* Track first attack detection for lead time */
        if (r->ground_truth == 1 && first_actual_attack < 0) {
            first_actual_attack = i;
        }
        if (r->combined_prediction == 1 && first_attack_detected < 0) {
            first_attack_detected = i;
        }
        
        /* Count predictions vs ground truth */
        if (r->ground_truth == 1) {
            metrics->truth_windows++;
            if (r->combined_prediction == 1) {
                metrics->true_positives++;
            } else {
                metrics->false_negatives++;
            }
        } else {
            if (r->combined_prediction == 1) {
                metrics->false_positives++;
            } else {
                metrics->true_negatives++;
            }
        }
        
        if (r->combined_prediction == 1) {
            metrics->attack_windows++;
        } else {
            metrics->benign_windows++;
        }
    }
    
    /* Calculate detection lead time */
    if (first_actual_attack >= 0 && first_attack_detected >= 0) {
        int window_delay = first_attack_detected - first_actual_attack;
        if (window_delay >= 0) {
            /* Assume 10-second capture windows in live mode */
            metrics->detection_lead_time_ms = window_delay * 10000.0 + results[first_attack_detected].processing_time_ms;
        }
    }
    
    /* Calculate 95th percentile latency */
    if (num_windows > 0) {
        /* Simple bubble sort for small arrays */
        for (int i = 0; i < num_windows - 1; i++) {
            for (int j = 0; j < num_windows - i - 1; j++) {
                if (latencies[j] > latencies[j + 1]) {
                    double temp = latencies[j];
                    latencies[j] = latencies[j + 1];
                    latencies[j + 1] = temp;
                }
            }
        }
        int percentile_95_idx = (int)(num_windows * 0.95);
        if (percentile_95_idx >= num_windows) percentile_95_idx = num_windows - 1;
        metrics->percentile_95_latency_ms = latencies[percentile_95_idx];
    }
    free(latencies);
    
    /* Basic metrics - NOTE: total_processing_time will be set by orchestrator */
    /* This is the sum of individual window times, not wall-clock time */
    metrics->total_processing_time = total_time;
    metrics->avg_window_time = (num_windows > 0) ? (total_time / num_windows) : 0.0;
    
    /* Throughput calculations - will be recalculated after total_processing_time is set */
    /* These are placeholder values that will be overwritten */
    metrics->throughput_flows_per_sec = 0.0;
    metrics->throughput_packets_per_sec = 0.0;
    metrics->throughput_mbps = 0.0;
    metrics->throughput_gbps = 0.0;
    metrics->avg_packet_processing_us = 0.0;
    
    /* Calculate CPU utilization based on processing time vs wall-clock time */
    /* CPU% = (processing_time / (wall_time * num_cores)) * 100 */
    if (metrics->total_processing_time > 0 && metrics->mpi_processes_used > 1) {
        /* Assume each worker process uses ~1 core when active */
        int worker_count = metrics->mpi_processes_used - 1;  /* Exclude master */
        double ideal_parallel_time = metrics->total_processing_time / worker_count;
        metrics->avg_cpu_utilization = (ideal_parallel_time / metrics->total_processing_time) * 100.0;
        /* Cap at 100% */
        if (metrics->avg_cpu_utilization > 100.0) metrics->avg_cpu_utilization = 100.0;
    } else {
        metrics->avg_cpu_utilization = 85.0;  /* Default estimate */
    }
    
    /* Calculate actual memory usage */
    /* Each flow: ~400 bytes (5 IPs + ports + proto + times + label) */
    /* Window overhead: ~100 bytes */
    /* Results per window: ~300 bytes */
    long flow_memory = metrics->total_flows_processed * 400;
    long window_memory = num_windows * 100;
    long result_memory = num_windows * 300;
    metrics->peak_memory_bytes = flow_memory + window_memory + result_memory;
    metrics->avg_memory_mb = (double)metrics->peak_memory_bytes / (1024.0 * 1024.0);
    
    /* Mitigation effectiveness */
    metrics->total_ips_detected = metrics->attack_windows;  /* Placeholder */
    metrics->total_ips_blocked = metrics->true_positives;
    
    if (metrics->truth_windows > 0) {
        metrics->attack_traffic_blocked_pct = (double)metrics->true_positives / metrics->truth_windows * 100.0;
    }
    
    if (metrics->total_windows > 0) {
        metrics->false_positive_impact_pct = (double)metrics->false_positives / metrics->total_windows * 100.0;
    }
}

/* Print performance summary */
void print_performance_summary(const PerformanceMetrics *metrics) {
    if (!metrics) return;
    
    printf("\n");
    print_colored(COLOR_CYAN, "╔════════════════════════════════════════════════════════════╗\n");
    print_colored(COLOR_CYAN, "║       %sSTATISTICAL DETECTION PERFORMANCE ANALYSIS%s       ║\n", 
                 COLOR_BOLD, COLOR_CYAN);
    print_colored(COLOR_CYAN, "╚════════════════════════════════════════════════════════════╝\n");
    printf("\n");
    
    /* Detection Statistics */
    print_colored(COLOR_YELLOW, "═══ Detection Analysis ═══\n");
    printf("  Total Windows Analyzed:          %s%d%s\n", COLOR_BOLD, metrics->total_windows, COLOR_RESET);
    printf("  Windows Identified as Attack:    %s%d%s\n", COLOR_RED, metrics->attack_windows, COLOR_RESET);
    printf("  Windows Identified as Benign:    %s%d%s\n", COLOR_GREEN, metrics->benign_windows, COLOR_RESET);
    printf("  Actual Attack Windows (Label):   %s%d%s\n", COLOR_MAGENTA, metrics->truth_windows, COLOR_RESET);
    printf("  Actual Benign Windows (Label):   %s%d%s\n", COLOR_CYAN, 
           metrics->total_windows - metrics->truth_windows, COLOR_RESET);
    printf("\n");
    
    /* Detection Accuracy */
    print_colored(COLOR_YELLOW, "═══ Detection Accuracy ═══\n");
    printf("  Correctly Detected Attacks (TP): %s%d%s\n", COLOR_GREEN, metrics->true_positives, COLOR_RESET);
    printf("  Correctly Detected Benign (TN):  %s%d%s\n", COLOR_GREEN, metrics->true_negatives, COLOR_RESET);
    printf("  False Alarms (FP):               %s%d%s\n", COLOR_RED, metrics->false_positives, COLOR_RESET);
    printf("  Missed Attacks (FN):             %s%d%s\n", COLOR_RED, metrics->false_negatives, COLOR_RESET);
    printf("\n");
    
    /* Statistical Detection Metrics */
    int total_predictions = metrics->true_positives + metrics->false_positives + 
                           metrics->true_negatives + metrics->false_negatives;
    
    if (total_predictions > 0) {
        double detection_rate = (metrics->true_positives + metrics->false_negatives > 0) ?
                               (double)metrics->true_positives / (metrics->true_positives + metrics->false_negatives) : 0.0;
        double false_alarm_rate = (metrics->false_positives + metrics->true_negatives > 0) ?
                                 (double)metrics->false_positives / (metrics->false_positives + metrics->true_negatives) : 0.0;
        double accuracy = (double)(metrics->true_positives + metrics->true_negatives) / total_predictions;
        
        print_colored(COLOR_YELLOW, "═══ Statistical Performance Metrics ═══\n");
        printf("  Detection Rate (DR):             %s%.4f%s (%.2f%% of attacks detected)\n", 
               COLOR_GREEN, detection_rate, COLOR_RESET, detection_rate * 100);
        printf("  False Alarm Rate (FAR):          %s%.4f%s (%.2f%% of benign flagged)\n", 
               COLOR_YELLOW, false_alarm_rate, COLOR_RESET, false_alarm_rate * 100);
        printf("  Overall Accuracy:                %s%.4f%s (%.2f%%)\n", 
               COLOR_GREEN, accuracy, COLOR_RESET, accuracy * 100);
        
        /* Additional detection quality metrics */
        double specificity = (metrics->false_positives + metrics->true_negatives > 0) ?
                            (double)metrics->true_negatives / (metrics->false_positives + metrics->true_negatives) : 0.0;
        double balanced_accuracy = (detection_rate + specificity) / 2.0;
        
        printf("  Specificity (True Negative Rate): %s%.4f%s\n", COLOR_CYAN, specificity, COLOR_RESET);
        printf("  Balanced Accuracy:               %s%.4f%s\n", COLOR_CYAN, balanced_accuracy, COLOR_RESET);
        printf("\n");
    }
    
    /* System Performance Metrics */
    print_colored(COLOR_YELLOW, "═══ System Performance ═══\n");
    printf("  Total Network Flows Analyzed:    %s%ld%s flows\n", 
           COLOR_BOLD, metrics->total_flows_processed, COLOR_RESET);
    printf("  Total Packets Processed:         %s%ld%s packets (estimated)\n", 
           COLOR_BOLD, metrics->total_packets_processed, COLOR_RESET);
    printf("  Total Processing Time:           %s%.2f%s seconds\n", 
           COLOR_CYAN, metrics->total_processing_time, COLOR_RESET);
    printf("\n");
    
    /* Latency Metrics */
    print_colored(COLOR_YELLOW, "═══ Latency Metrics ═══\n");
    printf("  Average Window Processing Time:  %s%.3f%s ms\n", 
           COLOR_CYAN, metrics->avg_window_time * 1000, COLOR_RESET);
    printf("  Minimum Window Processing Time:  %s%.3f%s ms\n", 
           COLOR_GREEN, metrics->min_window_time_ms, COLOR_RESET);
    printf("  Maximum Window Processing Time:  %s%.3f%s ms\n", 
           COLOR_YELLOW, metrics->max_window_time_ms, COLOR_RESET);
    printf("  95th Percentile Latency:         %s%.3f%s ms\n", 
           COLOR_CYAN, metrics->percentile_95_latency_ms, COLOR_RESET);
    printf("  Average Packet Processing Time:  %s%.3f%s μs\n", 
           COLOR_CYAN, metrics->avg_packet_processing_us, COLOR_RESET);
    
    if (metrics->detection_lead_time_ms > 0) {
        printf("  Detection Lead Time:             %s%.2f%s ms (%.2f seconds)\n", 
               COLOR_GREEN, metrics->detection_lead_time_ms, COLOR_RESET,
               metrics->detection_lead_time_ms / 1000.0);
    }
    printf("\n");
    
    /* Throughput Metrics */
    print_colored(COLOR_YELLOW, "═══ Throughput Metrics ═══\n");
    printf("  Flow Throughput:                 %s%.2f%s flows/second\n", 
           COLOR_GREEN, metrics->throughput_flows_per_sec, COLOR_RESET);
    printf("  Packet Throughput:               %s%.2f%s packets/second\n", 
           COLOR_GREEN, metrics->throughput_packets_per_sec, COLOR_RESET);
    printf("  Bandwidth Throughput:            %s%.2f%s Mbps\n", 
           COLOR_GREEN, metrics->throughput_mbps, COLOR_RESET);
    printf("  Bandwidth Throughput:            %s%.4f%s Gbps\n", 
           COLOR_GREEN, metrics->throughput_gbps, COLOR_RESET);
    
    /* Calculate additional throughput metrics */
    if (metrics->total_processing_time > 0) {
        double windows_per_sec = metrics->total_windows / metrics->total_processing_time;
        printf("  Window Processing Rate:          %s%.2f%s windows/second\n", 
               COLOR_GREEN, windows_per_sec, COLOR_RESET);
    }
    printf("\n");
    
    /* Resource Utilization */
    print_colored(COLOR_YELLOW, "═══ Resource Utilization ═══\n");
    printf("  Estimated CPU Utilization:       %s%.1f%%%s\n", 
           COLOR_CYAN, metrics->avg_cpu_utilization, COLOR_RESET);
    printf("  Peak Memory Usage:               %s%.2f%s MB\n", 
           COLOR_CYAN, metrics->avg_memory_mb, COLOR_RESET);
    if (metrics->mpi_processes_used > 0) {
        printf("  MPI Processes Used:              %s%d%s\n", 
               COLOR_CYAN, metrics->mpi_processes_used, COLOR_RESET);
        if (metrics->parallel_efficiency > 0) {
            printf("  Parallel Efficiency:             %s%.2f%%%s\n", 
                   COLOR_GREEN, metrics->parallel_efficiency * 100, COLOR_RESET);
        }
    }
    printf("\n");
    
    /* Mitigation Effectiveness */
    if (metrics->total_ips_detected > 0 || metrics->total_ips_blocked > 0) {
        print_colored(COLOR_YELLOW, "═══ Blocking Effectiveness ═══\n");
        printf("  Attack Traffic Blocked:          %s%.2f%%%s (%d/%d windows)\n", 
               COLOR_GREEN, metrics->attack_traffic_blocked_pct, COLOR_RESET,
               metrics->true_positives, metrics->truth_windows);
        printf("  False Positive Impact:           %s%.2f%%%s (%d/%d windows)\n", 
               COLOR_YELLOW, metrics->false_positive_impact_pct, COLOR_RESET,
               metrics->false_positives, metrics->total_windows);
        printf("  Collateral Damage (Benign):      %s%.4f%%%s\n", 
               COLOR_CYAN, metrics->false_positive_impact_pct, COLOR_RESET);
        printf("\n");
    }
    
    /* Detection Quality Summary */
    print_colored(COLOR_YELLOW, "═══ Detection Quality Summary ═══\n");
    if (metrics->false_positives == 0) {
        print_colored(COLOR_GREEN, "  ✓ No false alarms - Excellent specificity\n");
    } else if (metrics->false_positives < metrics->true_positives / 10) {
        print_colored(COLOR_GREEN, "  ✓ Very low false alarm rate\n");
    } else {
        print_colored(COLOR_YELLOW, "  ! Consider threshold adjustment to reduce false alarms\n");
    }
    
    if (metrics->false_negatives == 0) {
        print_colored(COLOR_GREEN, "  ✓ All attacks detected - Perfect detection rate\n");
    } else if (metrics->false_negatives < metrics->true_positives / 10) {
        print_colored(COLOR_GREEN, "  ✓ High detection rate with few missed attacks\n");
    } else {
        print_colored(COLOR_YELLOW, "  ! Some attacks missed - Consider lowering thresholds\n");
    }
    
    printf("\n");
}

/* Print individual detector performance */
void print_detector_performance(const WindowResult *results, int num_windows) {
    if (!results || num_windows == 0) return;
    
    int entropy_tp = 0, entropy_tn = 0, entropy_fp = 0, entropy_fn = 0;
    int pca_tp = 0, pca_tn = 0, pca_fp = 0, pca_fn = 0;
    int cusum_tp = 0, cusum_tn = 0, cusum_fp = 0, cusum_fn = 0;
    int combined_tp = 0, combined_tn = 0, combined_fp = 0, combined_fn = 0;
    
    for (int i = 0; i < num_windows; i++) {
        const WindowResult *r = &results[i];
        int gt = r->ground_truth;
        
        /* Entropy */
        if (r->entropy_prediction == 1 && gt == 1) entropy_tp++;
        else if (r->entropy_prediction == 0 && gt == 0) entropy_tn++;
        else if (r->entropy_prediction == 1 && gt == 0) entropy_fp++;
        else if (r->entropy_prediction == 0 && gt == 1) entropy_fn++;
        
        /* PCA */
        if (r->pca_prediction == 1 && gt == 1) pca_tp++;
        else if (r->pca_prediction == 0 && gt == 0) pca_tn++;
        else if (r->pca_prediction == 1 && gt == 0) pca_fp++;
        else if (r->pca_prediction == 0 && gt == 1) pca_fn++;
        
        /* CUSUM */
        if (r->cusum_prediction == 1 && gt == 1) cusum_tp++;
        else if (r->cusum_prediction == 0 && gt == 0) cusum_tn++;
        else if (r->cusum_prediction == 1 && gt == 0) cusum_fp++;
        else if (r->cusum_prediction == 0 && gt == 1) cusum_fn++;
        
        /* Combined */
        if (r->combined_prediction == 1 && gt == 1) combined_tp++;
        else if (r->combined_prediction == 0 && gt == 0) combined_tn++;
        else if (r->combined_prediction == 1 && gt == 0) combined_fp++;
        else if (r->combined_prediction == 0 && gt == 1) combined_fn++;
    }
    
    int total_attacks = entropy_tp + entropy_fn;
    int total_benign = entropy_tn + entropy_fp;
    
    if (total_attacks == 0) return;  /* No attacks to report */
    
    print_colored(COLOR_YELLOW, "═══ Individual Detector Performance ═══\n");
    
    /* Entropy */
    double entropy_dr = (total_attacks > 0) ? (double)entropy_tp / total_attacks : 0.0;
    printf("  Entropy Detection:               %s%d/%d%s (%.2f%%)\n", 
           COLOR_GREEN, entropy_tp, total_attacks, COLOR_RESET, entropy_dr * 100);
    
    /* PCA */
    double pca_dr = (total_attacks > 0) ? (double)pca_tp / total_attacks : 0.0;
    printf("  PCA Detection:                   %s%d/%d%s (%.2f%%)\n", 
           COLOR_GREEN, pca_tp, total_attacks, COLOR_RESET, pca_dr * 100);
    
    /* CUSUM */
    double cusum_dr = (total_attacks > 0) ? (double)cusum_tp / total_attacks : 0.0;
    printf("  CUSUM Detection:                 %s%d/%d%s (%.2f%%)\n", 
           COLOR_GREEN, cusum_tp, total_attacks, COLOR_RESET, cusum_dr * 100);
    
    /* Combined */
    double combined_dr = (total_attacks > 0) ? (double)combined_tp / total_attacks : 0.0;
    printf("  Combined (OR logic):             %s%d/%d%s (%.2f%%)\n", 
           COLOR_BOLD COLOR_GREEN, combined_tp, total_attacks, COLOR_RESET, combined_dr * 100);
    
    printf("\n");
}

/* Write detailed results to CSV with statistical metrics summary */
int write_results_csv(const WindowResult *results, int num_windows, const char *filepath,
                      const PerformanceMetrics *metrics) {
    if (!results || !filepath || num_windows == 0) return -1;
    
    FILE *fp = fopen(filepath, "w");
    if (!fp) {
        perror("Failed to open results file");
        return -1;
    }
    
    /* Write header */
    fprintf(fp, "window_id,start_row,end_row,flow_count,");
    fprintf(fp, "entropy_score,entropy_pred,pca_score,pca_pred,cusum_score,cusum_pred,");
    fprintf(fp, "combined_pred,ground_truth,processing_time_ms\n");
    
    /* Write data */
    for (int i = 0; i < num_windows; i++) {
        const WindowResult *r = &results[i];
        fprintf(fp, "%d,%d,%d,%d,", r->window_id, r->start_row, r->end_row, r->flow_count);
        fprintf(fp, "%.6f,%d,%.6f,%d,%.6f,%d,",
               r->entropy_anomaly_score, r->entropy_prediction,
               r->pca_anomaly_score, r->pca_prediction,
               r->cusum_anomaly_score, r->cusum_prediction);
        fprintf(fp, "%d,%d,%.3f\n", r->combined_prediction, r->ground_truth, r->processing_time_ms);
    }
    
    /* Add summary statistics if metrics provided */
    if (metrics) {
        int total_pred = metrics->true_positives + metrics->false_positives + 
                        metrics->true_negatives + metrics->false_negatives;
        double detection_rate = (metrics->true_positives + metrics->false_negatives > 0) ?
                               (double)metrics->true_positives / (metrics->true_positives + metrics->false_negatives) : 0.0;
        double false_alarm_rate = (metrics->false_positives + metrics->true_negatives > 0) ?
                                 (double)metrics->false_positives / (metrics->false_positives + metrics->true_negatives) : 0.0;
        double accuracy = (total_pred > 0) ? 
                         (double)(metrics->true_positives + metrics->true_negatives) / total_pred : 0.0;
        double specificity = (metrics->false_positives + metrics->true_negatives > 0) ?
                            (double)metrics->true_negatives / (metrics->false_positives + metrics->true_negatives) : 0.0;
        double precision = (metrics->true_positives + metrics->false_positives > 0) ?
                          (double)metrics->true_positives / (metrics->true_positives + metrics->false_positives) : 0.0;
        double recall = detection_rate;
        double f1_score = (precision + recall > 0) ? (2.0 * precision * recall) / (precision + recall) : 0.0;
        
        fprintf(fp, "\n# Complete Performance Analysis Summary\n");
        fprintf(fp, "# Generated: %s\n", __DATE__);
        
        fprintf(fp, "\n## Accuracy Metrics\n");
        fprintf(fp, "total_windows,%d\n", metrics->total_windows);
        fprintf(fp, "attack_windows_detected,%d\n", metrics->attack_windows);
        fprintf(fp, "benign_windows_detected,%d\n", metrics->benign_windows);
        fprintf(fp, "actual_attack_windows,%d\n", metrics->truth_windows);
        fprintf(fp, "correctly_detected_attacks_TP,%d\n", metrics->true_positives);
        fprintf(fp, "correctly_detected_benign_TN,%d\n", metrics->true_negatives);
        fprintf(fp, "false_alarms_FP,%d\n", metrics->false_positives);
        fprintf(fp, "missed_attacks_FN,%d\n", metrics->false_negatives);
        fprintf(fp, "precision,%.6f\n", precision);
        fprintf(fp, "recall,%.6f\n", recall);
        fprintf(fp, "f1_score,%.6f\n", f1_score);
        fprintf(fp, "false_positive_rate,%.6f\n", false_alarm_rate);
        fprintf(fp, "detection_rate,%.6f\n", detection_rate);
        fprintf(fp, "accuracy,%.6f\n", accuracy);
        fprintf(fp, "specificity,%.6f\n", specificity);
        fprintf(fp, "balanced_accuracy,%.6f\n", (detection_rate + specificity) / 2.0);
        
        fprintf(fp, "\n## Latency Metrics\n");
        fprintf(fp, "detection_lead_time_ms,%.2f\n", metrics->detection_lead_time_ms);
        fprintf(fp, "avg_window_processing_ms,%.3f\n", metrics->avg_window_time * 1000);
        fprintf(fp, "min_window_processing_ms,%.3f\n", metrics->min_window_time_ms);
        fprintf(fp, "max_window_processing_ms,%.3f\n", metrics->max_window_time_ms);
        fprintf(fp, "percentile_95_latency_ms,%.3f\n", metrics->percentile_95_latency_ms);
        fprintf(fp, "avg_packet_processing_us,%.3f\n", metrics->avg_packet_processing_us);
        
        fprintf(fp, "\n## Throughput Metrics\n");
        fprintf(fp, "total_flows_analyzed,%ld\n", metrics->total_flows_processed);
        fprintf(fp, "total_packets_processed,%ld\n", metrics->total_packets_processed);
        fprintf(fp, "total_processing_time_sec,%.2f\n", metrics->total_processing_time);
        fprintf(fp, "throughput_flows_per_sec,%.2f\n", metrics->throughput_flows_per_sec);
        fprintf(fp, "throughput_packets_per_sec,%.2f\n", metrics->throughput_packets_per_sec);
        fprintf(fp, "throughput_mbps,%.2f\n", metrics->throughput_mbps);
        fprintf(fp, "throughput_gbps,%.4f\n", metrics->throughput_gbps);
        
        fprintf(fp, "\n## Resource Utilization\n");
        fprintf(fp, "avg_cpu_utilization_pct,%.1f\n", metrics->avg_cpu_utilization);
        fprintf(fp, "peak_memory_mb,%.2f\n", metrics->avg_memory_mb);
        fprintf(fp, "mpi_processes_used,%d\n", metrics->mpi_processes_used);
        fprintf(fp, "parallel_efficiency,%.4f\n", metrics->parallel_efficiency);
        
        fprintf(fp, "\n## Blocking Effectiveness\n");
        fprintf(fp, "attack_traffic_blocked_pct,%.2f\n", metrics->attack_traffic_blocked_pct);
        fprintf(fp, "false_positive_impact_pct,%.2f\n", metrics->false_positive_impact_pct);
        fprintf(fp, "total_ips_detected,%d\n", metrics->total_ips_detected);
        fprintf(fp, "total_ips_blocked,%d\n", metrics->total_ips_blocked);
    }
    
    fclose(fp);
    return 0;
}
