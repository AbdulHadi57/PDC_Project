#ifndef FLOW_TYPES_H
#define FLOW_TYPES_H

#include "common.h"

/* Flow record structure matching CIC-DDoS2019 dataset */
typedef struct {
    /* 5-tuple */
    char src_ip[MAX_IP_LENGTH];
    char dst_ip[MAX_IP_LENGTH];
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    
    /* Temporal features */
    char timestamp[64];
    double flow_duration;
    
    /* Packet statistics */
    int total_fwd_packets;
    int total_bwd_packets;
    double total_length_fwd_packets;
    double total_length_bwd_packets;
    
    /* Packet lengths */
    double fwd_packet_length_max;
    double fwd_packet_length_min;
    double fwd_packet_length_mean;
    double fwd_packet_length_std;
    double bwd_packet_length_max;
    double bwd_packet_length_min;
    double bwd_packet_length_mean;
    double bwd_packet_length_std;
    
    /* Flow statistics */
    double flow_bytes_per_sec;
    double flow_packets_per_sec;
    double flow_iat_mean;
    double flow_iat_std;
    double flow_iat_max;
    double flow_iat_min;
    
    /* Forward IAT */
    double fwd_iat_total;
    double fwd_iat_mean;
    double fwd_iat_std;
    double fwd_iat_max;
    double fwd_iat_min;
    
    /* Backward IAT */
    double bwd_iat_total;
    double bwd_iat_mean;
    double bwd_iat_std;
    double bwd_iat_max;
    double bwd_iat_min;
    
    /* Flags */
    int fwd_psh_flags;
    int bwd_psh_flags;
    int fwd_urg_flags;
    int bwd_urg_flags;
    int fwd_header_length;
    int bwd_header_length;
    
    /* Packet rates */
    double fwd_packets_per_sec;
    double bwd_packets_per_sec;
    
    /* Packet size */
    double min_packet_length;
    double max_packet_length;
    double packet_length_mean;
    double packet_length_std;
    double packet_length_variance;
    
    /* TCP flags */
    int fin_flag_count;
    int syn_flag_count;
    int rst_flag_count;
    int psh_flag_count;
    int ack_flag_count;
    int urg_flag_count;
    int cwe_flag_count;
    int ece_flag_count;
    
    /* Ratios */
    double down_up_ratio;
    double average_packet_size;
    double avg_fwd_segment_size;
    double avg_bwd_segment_size;
    
    /* Window sizes */
    int init_win_bytes_forward;
    int init_win_bytes_backward;
    
    /* Active/Idle times */
    double active_mean;
    double active_std;
    double active_max;
    double active_min;
    double idle_mean;
    double idle_std;
    double idle_max;
    double idle_min;
    
    /* Label */
    char label[64];
    int is_attack; /* 0 = benign, 1 = attack */
} FlowRecord;

/* Schema for CSV parsing */
typedef struct {
    int src_ip_idx;
    int dst_ip_idx;
    int src_port_idx;
    int dst_port_idx;
    int protocol_idx;
    int timestamp_idx;
    int flow_duration_idx;
    int total_fwd_packets_idx;
    int total_bwd_packets_idx;
    int flow_bytes_per_sec_idx;
    int flow_packets_per_sec_idx;
    int fwd_iat_mean_idx;
    int packet_length_mean_idx;
    int syn_flag_count_idx;
    int label_idx;
    int column_count;
} CSVSchema;

/* Window of flows for analysis */
typedef struct {
    FlowRecord *flows;
    int flow_count;
    int window_id;
    int start_row;
    int end_row;
} FlowWindow;

#endif /* FLOW_TYPES_H */
