#ifndef DETECTORS_H
#define DETECTORS_H

#include "flow_types.h"
#include "common.h"

/* Window analysis result */
typedef struct {
    int window_id;
    int start_row;
    int end_row;
    int flow_count;
    
    /* Entropy metrics */
    double entropy_src_ip;
    double entropy_dst_ip;
    double entropy_src_port;
    double entropy_dst_port;
    double entropy_flow_signature;
    double norm_entropy_src_ip;
    double norm_entropy_dst_ip;
    double norm_entropy_src_port;
    double norm_entropy_dst_port;
    double norm_entropy_flow_signature;
    double entropy_anomaly_score;
    
    /* PCA metrics */
    double pca_spe;  /* Squared Prediction Error */
    double pca_t2;   /* Hotelling's T-squared */
    double pca_anomaly_score;
    
    /* CUSUM metrics */
    double cusum_positive;
    double cusum_negative;
    double cusum_anomaly_score;
    
    /* Combined detection */
    int entropy_prediction;  /* 0 = benign, 1 = attack */
    int pca_prediction;
    int cusum_prediction;
    int combined_prediction;
    
    /* Ground truth (from label) */
    int ground_truth;
    
    /* Performance */
    double processing_time_ms;
    
    /* Suspicious IPs in this window */
    SuspiciousList suspicious_ips;
} WindowResult;

/* Entropy detector */
int entropy_detect_init(void);
WindowResult entropy_detect_window(const FlowWindow *window, double threshold);
void entropy_detect_cleanup(void);

/* PCA detector */
typedef struct {
    int n_components;
    int n_features;
    int warmup_count;
    int warmup_target;
    bool is_trained;
    
    double *mean;           /* n_features */
    double *std;            /* n_features */
    double **covariance;    /* n_features x n_features */
    double **eigenvectors;  /* n_features x n_components */
    double *eigenvalues;    /* n_components */
    
    double spe_mean;
    double spe_std;
    double t2_mean;
    double t2_std;
} PCADetector;

int pca_detect_init(PCADetector *pca, int n_components, int warmup_windows);
WindowResult pca_detect_window(PCADetector *pca, const FlowWindow *window, double threshold);
void pca_detect_cleanup(PCADetector *pca);

/* CUSUM detector */
typedef struct {
    double target_mean;
    double current_sum_positive;
    double current_sum_negative;
    double threshold;
    double drift;
    int n_features;
    bool is_initialized;
    
    /* Reference statistics */
    double *baseline_mean;
    double *baseline_std;
    int baseline_count;
} CUSUMDetector;

int cusum_detect_init(CUSUMDetector *cusum, double threshold, double drift);
WindowResult cusum_detect_window(CUSUMDetector *cusum, const FlowWindow *window);
void cusum_detect_cleanup(CUSUMDetector *cusum);

/* Combined detector result merging */
WindowResult merge_detector_results(const WindowResult *entropy_result,
                                    const WindowResult *pca_result,
                                    const WindowResult *cusum_result,
                                    int detector_mask);

#endif /* DETECTORS_H */
