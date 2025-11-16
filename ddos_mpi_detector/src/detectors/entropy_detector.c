#include "../include/detectors.h"
#include "../include/common.h"
#include <math.h>

/* Helper: calculate Shannon entropy */
static double calculate_entropy(char **values, int count) {
    if (count <= 0) return 0.0;
    
    /* Sort values */
    for (int i = 0; i < count - 1; i++) {
        for (int j = i + 1; j < count; j++) {
            if (strcmp(values[i], values[j]) > 0) {
                char *temp = values[i];
                values[i] = values[j];
                values[j] = temp;
            }
        }
    }
    
    double entropy = 0.0;
    int run_length = 1;
    int unique_count = 0;
    
    for (int i = 1; i <= count; i++) {
        if (i < count && strcmp(values[i], values[i-1]) == 0) {
            run_length++;
        } else {
            double probability = (double)run_length / (double)count;
            if (probability > 0) {
                entropy -= probability * log2(probability);
            }
            unique_count++;
            run_length = 1;
        }
    }
    
    /* Normalize by maximum possible entropy */
    double max_entropy = (unique_count > 1) ? log2((double)unique_count) : 1.0;
    return (max_entropy > 0) ? (entropy / max_entropy) : 0.0;
}

/* Entropy detector initialization */
int entropy_detect_init(void) {
    /* No special initialization needed for entropy */
    return 0;
}

/* Analyze window using entropy-based detection */
WindowResult entropy_detect_window(const FlowWindow *window, double threshold) {
    WindowResult result;
    memset(&result, 0, sizeof(WindowResult));
    suspicious_list_init(&result.suspicious_ips);
    
    if (!window || window->flow_count == 0) {
        return result;
    }
    
    double start_time = get_timestamp();
    
    result.window_id = window->window_id;
    result.start_row = window->start_row;
    result.end_row = window->end_row;
    result.flow_count = window->flow_count;
    
    /* Extract features for entropy calculation */
    char **src_ips = malloc(window->flow_count * sizeof(char*));
    char **dst_ips = malloc(window->flow_count * sizeof(char*));
    char **src_ports = malloc(window->flow_count * sizeof(char*));
    char **dst_ports = malloc(window->flow_count * sizeof(char*));
    char **signatures = malloc(window->flow_count * sizeof(char*));
    
    if (!src_ips || !dst_ips || !src_ports || !dst_ports || !signatures) {
        free(src_ips);
        free(dst_ips);
        free(src_ports);
        free(dst_ports);
        free(signatures);
        return result;
    }
    
    int valid_count = 0;
    int attack_count = 0;
    
    for (int i = 0; i < window->flow_count; i++) {
        FlowRecord *flow = &window->flows[i];
        
        if (strlen(flow->src_ip) > 0 && strlen(flow->dst_ip) > 0) {
            src_ips[valid_count] = malloc(MAX_IP_LENGTH);
            dst_ips[valid_count] = malloc(MAX_IP_LENGTH);
            src_ports[valid_count] = malloc(16);
            dst_ports[valid_count] = malloc(16);
            signatures[valid_count] = malloc(256);
            
            if (src_ips[valid_count] && dst_ips[valid_count] && 
                src_ports[valid_count] && dst_ports[valid_count] && 
                signatures[valid_count]) {
                
                strcpy(src_ips[valid_count], flow->src_ip);
                strcpy(dst_ips[valid_count], flow->dst_ip);
                snprintf(src_ports[valid_count], 16, "%u", flow->src_port);
                snprintf(dst_ports[valid_count], 16, "%u", flow->dst_port);
                snprintf(signatures[valid_count], 256, "%s|%s|%u|%u",
                        flow->src_ip, flow->dst_ip, 
                        flow->src_port, flow->dst_port);
                
                valid_count++;
                
                if (flow->is_attack) {
                    attack_count++;
                }
            }
        }
    }
    
    if (valid_count > 0) {
        /* Calculate entropies */
        result.entropy_src_ip = calculate_entropy(src_ips, valid_count);
        result.entropy_dst_ip = calculate_entropy(dst_ips, valid_count);
        result.entropy_src_port = calculate_entropy(src_ports, valid_count);
        result.entropy_dst_port = calculate_entropy(dst_ports, valid_count);
        result.entropy_flow_signature = calculate_entropy(signatures, valid_count);
        
        /* Store normalized values (already normalized by calculate_entropy) */
        result.norm_entropy_src_ip = result.entropy_src_ip;
        result.norm_entropy_dst_ip = result.entropy_dst_ip;
        result.norm_entropy_src_port = result.entropy_src_port;
        result.norm_entropy_dst_port = result.entropy_dst_port;
        result.norm_entropy_flow_signature = result.entropy_flow_signature;
        
        /* Calculate anomaly score (entropy deficit) */
        double deficit_sum = 0.0;
        int features_used = 0;
        
        if (result.norm_entropy_src_ip >= 0) {
            deficit_sum += (1.0 - result.norm_entropy_src_ip);
            features_used++;
        }
        if (result.norm_entropy_dst_ip >= 0) {
            deficit_sum += (1.0 - result.norm_entropy_dst_ip);
            features_used++;
        }
        if (result.norm_entropy_src_port >= 0) {
            deficit_sum += (1.0 - result.norm_entropy_src_port);
            features_used++;
        }
        if (result.norm_entropy_dst_port >= 0) {
            deficit_sum += (1.0 - result.norm_entropy_dst_port);
            features_used++;
        }
        if (result.norm_entropy_flow_signature >= 0) {
            deficit_sum += (1.0 - result.norm_entropy_flow_signature);
            features_used++;
        }
        
        result.entropy_anomaly_score = (features_used > 0) ? 
                                       (deficit_sum / features_used) : 0.0;
        
        /* Make prediction */
        result.entropy_prediction = (result.entropy_anomaly_score > threshold) ? 1 : 0;
        
        /* If attack detected, collect suspicious source IPs */
        if (result.entropy_prediction == 1) {
            for (int i = 0; i < valid_count; i++) {
                suspicious_list_add(&result.suspicious_ips, src_ips[i]);
            }
        }
        
        /* Set ground truth from labels */
        result.ground_truth = (attack_count > (valid_count / 2)) ? 1 : 0;
    }
    
    /* Cleanup */
    for (int i = 0; i < valid_count; i++) {
        free(src_ips[i]);
        free(dst_ips[i]);
        free(src_ports[i]);
        free(dst_ports[i]);
        free(signatures[i]);
    }
    free(src_ips);
    free(dst_ips);
    free(src_ports);
    free(dst_ports);
    free(signatures);
    
    result.processing_time_ms = (get_timestamp() - start_time) * 1000.0;
    
    return result;
}

/* Cleanup entropy detector */
void entropy_detect_cleanup(void) {
    /* No cleanup needed */
}
