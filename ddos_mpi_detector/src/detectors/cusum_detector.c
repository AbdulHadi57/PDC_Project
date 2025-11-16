#include "../include/detectors.h"
#include "../include/common.h"
#include <math.h>

/* CUSUM (Cumulative Sum) Detector - Sequential change detection */

/* Initialize CUSUM detector */
int cusum_detect_init(CUSUMDetector *cusum, double threshold, double drift) {
    if (!cusum) return -1;
    
    memset(cusum, 0, sizeof(CUSUMDetector));
    cusum->threshold = (threshold > 0) ? threshold : 5.0;
    cusum->drift = (drift > 0) ? drift : 0.5;
    cusum->current_sum_positive = 0.0;
    cusum->current_sum_negative = 0.0;
    cusum->n_features = 4;  /* Key features for CUSUM */
    cusum->is_initialized = false;
    
    /* Allocate baseline arrays */
    cusum->baseline_mean = calloc(cusum->n_features, sizeof(double));
    cusum->baseline_std = calloc(cusum->n_features, sizeof(double));
    
    if (!cusum->baseline_mean || !cusum->baseline_std) {
        free(cusum->baseline_mean);
        free(cusum->baseline_std);
        return -1;
    }
    
    /* Initialize with reasonable defaults */
    for (int i = 0; i < cusum->n_features; i++) {
        cusum->baseline_std[i] = 1.0;
    }
    
    return 0;
}

/* Extract features for CUSUM analysis */
static void extract_cusum_features(const FlowWindow *window, double *features) {
    if (!window || !features || window->flow_count == 0) return;
    
    /* Calculate aggregated metrics */
    double total_packet_rate = 0.0;
    double total_byte_rate = 0.0;
    int unique_src_ips = 0;
    int syn_flags = 0;
    
    /* Simple unique IP counting (could be optimized) */
    char **seen_ips = malloc(window->flow_count * sizeof(char*));
    for (int i = 0; i < window->flow_count; i++) {
        seen_ips[i] = NULL;
    }
    
    for (int i = 0; i < window->flow_count; i++) {
        FlowRecord *flow = &window->flows[i];
        
        total_packet_rate += flow->flow_packets_per_sec;
        total_byte_rate += flow->flow_bytes_per_sec;
        syn_flags += flow->syn_flag_count;
        
        /* Check if source IP is new */
        int is_new = 1;
        for (int j = 0; j < unique_src_ips; j++) {
            if (seen_ips[j] && strcmp(seen_ips[j], flow->src_ip) == 0) {
                is_new = 0;
                break;
            }
        }
        if (is_new && strlen(flow->src_ip) > 0) {
            seen_ips[unique_src_ips] = (char*)flow->src_ip;
            unique_src_ips++;
        }
    }
    
    free(seen_ips);
    
    /* Features: packet rate, byte rate, unique IPs, SYN flags */
    features[0] = total_packet_rate / (window->flow_count + 1.0);
    features[1] = total_byte_rate / (window->flow_count + 1.0);
    features[2] = (double)unique_src_ips;
    features[3] = (double)syn_flags / (window->flow_count + 1.0);
}

/* Analyze window using CUSUM detection */
WindowResult cusum_detect_window(CUSUMDetector *cusum, const FlowWindow *window) {
    WindowResult result;
    memset(&result, 0, sizeof(WindowResult));
    suspicious_list_init(&result.suspicious_ips);
    
    if (!cusum || !window || window->flow_count == 0) {
        return result;
    }
    
    double start_time = get_timestamp();
    
    result.window_id = window->window_id;
    result.start_row = window->start_row;
    result.end_row = window->end_row;
    result.flow_count = window->flow_count;
    
    /* Extract features */
    double features[4];
    extract_cusum_features(window, features);
    
    /* Initialize baseline if not done */
    if (!cusum->is_initialized) {
        for (int i = 0; i < cusum->n_features; i++) {
            cusum->baseline_mean[i] = features[i];
            /* Set std to 10% of initial value or minimum 1.0 */
            cusum->baseline_std[i] = MAX(fabs(features[i]) * 0.1, 1.0);
        }
        cusum->baseline_count = 1;
        cusum->is_initialized = true;
        
        result.cusum_prediction = 0;
        result.cusum_anomaly_score = 0.0;
        result.cusum_positive = 0.0;
        result.cusum_negative = 0.0;
    } else {
        /* Update baseline (exponential moving average) */
        double alpha = 0.1;  /* Smoothing factor */
        for (int i = 0; i < cusum->n_features; i++) {
            cusum->baseline_mean[i] = alpha * features[i] + 
                                      (1.0 - alpha) * cusum->baseline_mean[i];
        }
        
        /* Calculate CUSUM statistics with numerical stability */
        double deviation_sum = 0.0;
        int valid_features = 0;
        
        for (int i = 0; i < cusum->n_features; i++) {
            double std_val = MAX(cusum->baseline_std[i], 1e-6);
            double deviation = (features[i] - cusum->baseline_mean[i]) / std_val;
            
            /* Cap extreme deviations */
            deviation = CLAMP(deviation, -50.0, 50.0);
            
            deviation_sum += deviation;  /* Keep sign for CUSUM */
            valid_features++;
        }
        
        /* Normalized deviation */
        double normalized_dev = (valid_features > 0) ? 
                               (deviation_sum / valid_features) : 0.0;
        
        /* Update cumulative sums */
        cusum->current_sum_positive = MAX(0.0, cusum->current_sum_positive + 
                                          normalized_dev - cusum->drift);
        cusum->current_sum_negative = MAX(0.0, cusum->current_sum_negative - 
                                          normalized_dev - cusum->drift);
        
        /* Calculate anomaly score */
        result.cusum_positive = cusum->current_sum_positive;
        result.cusum_negative = cusum->current_sum_negative;
        result.cusum_anomaly_score = MAX(cusum->current_sum_positive, 
                                        cusum->current_sum_negative);
        
        /* Make prediction */
        result.cusum_prediction = (result.cusum_anomaly_score > cusum->threshold) ? 1 : 0;
        
        /* Reset CUSUM if threshold exceeded */
        if (result.cusum_prediction == 1) {
            cusum->current_sum_positive = 0.0;
            cusum->current_sum_negative = 0.0;
            
            /* Collect suspicious IPs */
            for (int i = 0; i < window->flow_count; i++) {
                suspicious_list_add(&result.suspicious_ips, window->flows[i].src_ip);
            }
        }
    }
    
    /* Set ground truth */
    int attack_count = 0;
    for (int i = 0; i < window->flow_count; i++) {
        if (window->flows[i].is_attack) attack_count++;
    }
    result.ground_truth = (attack_count > (window->flow_count / 2)) ? 1 : 0;
    
    result.processing_time_ms = (get_timestamp() - start_time) * 1000.0;
    
    return result;
}

/* Cleanup CUSUM detector */
void cusum_detect_cleanup(CUSUMDetector *cusum) {
    if (!cusum) return;
    free(cusum->baseline_mean);
    free(cusum->baseline_std);
    memset(cusum, 0, sizeof(CUSUMDetector));
}

/* Merge results from multiple detectors */
WindowResult merge_detector_results(const WindowResult *entropy_result,
                                    const WindowResult *pca_result,
                                    const WindowResult *cusum_result,
                                    int detector_mask) {
    WindowResult merged;
    memset(&merged, 0, sizeof(WindowResult));
    suspicious_list_init(&merged.suspicious_ips);
    
    /* Use first non-NULL result for basic info */
    const WindowResult *ref = entropy_result ? entropy_result : 
                              (pca_result ? pca_result : cusum_result);
    if (!ref) return merged;
    
    merged.window_id = ref->window_id;
    merged.start_row = ref->start_row;
    merged.end_row = ref->end_row;
    merged.flow_count = ref->flow_count;
    merged.ground_truth = ref->ground_truth;
    
    /* Merge predictions (majority voting) */
    int vote_count = 0;
    int attack_votes = 0;
    
    if ((detector_mask & DETECTOR_ENTROPY) && entropy_result) {
        merged.entropy_anomaly_score = entropy_result->entropy_anomaly_score;
        merged.entropy_prediction = entropy_result->entropy_prediction;
        vote_count++;
        if (entropy_result->entropy_prediction) attack_votes++;
    }
    
    if ((detector_mask & DETECTOR_PCA) && pca_result) {
        merged.pca_anomaly_score = pca_result->pca_anomaly_score;
        merged.pca_prediction = pca_result->pca_prediction;
        vote_count++;
        if (pca_result->pca_prediction) attack_votes++;
    }
    
    if ((detector_mask & DETECTOR_CUSUM) && cusum_result) {
        merged.cusum_anomaly_score = cusum_result->cusum_anomaly_score;
        merged.cusum_prediction = cusum_result->cusum_prediction;
        vote_count++;
        if (cusum_result->cusum_prediction) attack_votes++;
    }
    
    /* Combined prediction: OR logic (any detector triggers = attack) */
    merged.combined_prediction = (attack_votes > 0) ? 1 : 0;
    
    /* Merge suspicious IPs */
    if (entropy_result && entropy_result->entropy_prediction) {
        for (size_t i = 0; i < entropy_result->suspicious_ips.count; i++) {
            suspicious_list_add(&merged.suspicious_ips, 
                              entropy_result->suspicious_ips.entries[i].ip);
        }
    }
    if (pca_result && pca_result->pca_prediction) {
        for (size_t i = 0; i < pca_result->suspicious_ips.count; i++) {
            suspicious_list_add(&merged.suspicious_ips, 
                              pca_result->suspicious_ips.entries[i].ip);
        }
    }
    if (cusum_result && cusum_result->cusum_prediction) {
        for (size_t i = 0; i < cusum_result->suspicious_ips.count; i++) {
            suspicious_list_add(&merged.suspicious_ips, 
                              cusum_result->suspicious_ips.entries[i].ip);
        }
    }
    
    return merged;
}
