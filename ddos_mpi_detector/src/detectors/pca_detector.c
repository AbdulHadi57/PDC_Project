#include "../include/detectors.h"
#include "../include/common.h"
#include <math.h>

/* Simplified PCA detector - focuses on key flow features */

/* Helper: calculate mean of feature array */
static double calc_mean(double *values, int count) {
    if (count == 0) return 0.0;
    double sum = 0.0;
    for (int i = 0; i < count; i++) {
        sum += values[i];
    }
    return sum / count;
}

/* Helper: calculate standard deviation */
static double calc_std(double *values, int count, double mean) {
    if (count <= 1) return 0.0;
    double sum_sq = 0.0;
    for (int i = 0; i < count; i++) {
        double diff = values[i] - mean;
        sum_sq += diff * diff;
    }
    return sqrt(sum_sq / (count - 1));
}

/* Initialize PCA detector */
int pca_detect_init(PCADetector *pca, int n_components, int warmup_windows) {
    if (!pca) return -1;
    
    memset(pca, 0, sizeof(PCADetector));
    pca->n_components = (n_components > 0) ? n_components : 4;
    pca->n_features = 6;  /* Flow features */
    pca->warmup_target = (warmup_windows > 0) ? warmup_windows : 10;
    pca->warmup_count = 0;
    pca->is_trained = false;
    
    /* Allocate arrays */
    pca->mean = calloc(pca->n_features, sizeof(double));
    pca->std = calloc(pca->n_features, sizeof(double));
    
    if (!pca->mean || !pca->std) {
        free(pca->mean);
        free(pca->std);
        return -1;
    }
    
    /* Initialize baseline values */
    for (int i = 0; i < pca->n_features; i++) {
        pca->std[i] = 1.0;  /* Avoid division by zero */
    }
    
    return 0;
}

/* Extract PCA features from flow window */
static void extract_pca_features(const FlowWindow *window, double *features) {
    if (!window || !features || window->flow_count == 0) return;
    
    double total_duration = 0.0;
    double total_bytes_per_sec = 0.0;
    double total_pkts_per_sec = 0.0;
    double total_fwd = 0.0;
    double total_bwd = 0.0;
    double total_pkt_len = 0.0;
    int count = 0;
    
    for (int i = 0; i < window->flow_count; i++) {
        FlowRecord *flow = &window->flows[i];
        if (flow->flow_duration >= 0) {
            total_duration += flow->flow_duration;
            total_bytes_per_sec += flow->flow_bytes_per_sec;
            total_pkts_per_sec += flow->flow_packets_per_sec;
            total_fwd += flow->total_fwd_packets;
            total_bwd += flow->total_bwd_packets;
            total_pkt_len += flow->packet_length_mean;
            count++;
        }
    }
    
    if (count > 0) {
        features[0] = total_duration / count;
        features[1] = total_bytes_per_sec / count;
        features[2] = total_pkts_per_sec / count;
        features[3] = total_fwd / count;
        features[4] = total_bwd / count;
        features[5] = total_pkt_len / count;
    }
}

/* Analyze window using PCA-based detection */
WindowResult pca_detect_window(PCADetector *pca, const FlowWindow *window, double threshold) {
    WindowResult result;
    memset(&result, 0, sizeof(WindowResult));
    suspicious_list_init(&result.suspicious_ips);
    
    if (!pca || !window || window->flow_count == 0) {
        return result;
    }
    
    double start_time = get_timestamp();
    
    result.window_id = window->window_id;
    result.start_row = window->start_row;
    result.end_row = window->end_row;
    result.flow_count = window->flow_count;
    
    /* Extract features */
    double features[6];
    extract_pca_features(window, features);
    
    /* Training phase (warmup) - collect statistics */
    if (!pca->is_trained && pca->warmup_count < pca->warmup_target) {
        /* Accumulate mean */
        for (int i = 0; i < pca->n_features; i++) {
            pca->mean[i] += features[i];
        }
        pca->warmup_count++;
        
        if (pca->warmup_count >= pca->warmup_target) {
            /* Calculate final mean */
            for (int i = 0; i < pca->n_features; i++) {
                pca->mean[i] /= pca->warmup_target;
            }
            
            /* Calculate standard deviations - use larger values for real traffic variance */
            /* Network traffic has high natural variance - use 50% of mean as std, minimum 10.0 */
            for (int i = 0; i < pca->n_features; i++) {
                pca->std[i] = MAX(fabs(pca->mean[i]) * 0.5, 10.0);
            }
            
            pca->is_trained = true;
        }
        
        /* During warmup, assume benign */
        result.pca_prediction = 0;
        result.pca_anomaly_score = 0.0;
    } else if (pca->is_trained) {
        /* Detection phase - calculate normalized deviation */
        double deviation_sum = 0.0;
        int valid_features = 0;
        
        for (int i = 0; i < pca->n_features; i++) {
            /* Avoid division by zero and handle extreme values */
            double std_val = MAX(pca->std[i], 1e-6);
            double normalized = (features[i] - pca->mean[i]) / std_val;
            
            /* Cap extreme values to prevent overflow */
            normalized = CLAMP(normalized, -100.0, 100.0);
            
            deviation_sum += fabs(normalized);
            valid_features++;
        }
        
        /* Average absolute deviation */
        double avg_deviation = (valid_features > 0) ? 
                               (deviation_sum / valid_features) : 0.0;
        
        result.pca_spe = avg_deviation;
        result.pca_anomaly_score = avg_deviation;
        
        /* Make prediction - threshold should be around 2-3 for normalized data */
        result.pca_prediction = (avg_deviation > threshold) ? 1 : 0;
        
        /* If attack detected, collect suspicious IPs */
        if (result.pca_prediction == 1) {
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

/* Cleanup PCA detector */
void pca_detect_cleanup(PCADetector *pca) {
    if (!pca) return;
    free(pca->mean);
    free(pca->std);
    memset(pca, 0, sizeof(PCADetector));
}
