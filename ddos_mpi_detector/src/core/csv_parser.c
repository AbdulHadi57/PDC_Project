#include "../include/flow_types.h"
#include "../include/common.h"
#include <ctype.h>

/* Helper: trim whitespace from string */
static void trim_whitespace(char *str) {
    if (!str) return;
    
    /* Trim leading */
    char *start = str;
    while (*start && isspace((unsigned char)*start)) start++;
    
    /* Trim trailing */
    char *end = str + strlen(str) - 1;
    while (end > start && isspace((unsigned char)*end)) *end-- = '\0';
    
    /* Move trimmed string to beginning if needed */
    if (start != str) {
        memmove(str, start, strlen(start) + 1);
    }
}

/* Parse CSV line into fields */
int parse_csv_line(const char *line, char **fields, int max_fields) {
    if (!line || !fields) return -1;
    
    int field_count = 0;
    int in_quotes = 0;
    char buffer[MAX_FIELD_LENGTH];
    int buffer_pos = 0;
    
    for (const char *p = line; *p && field_count < max_fields; p++) {
        if (*p == '"') {
            in_quotes = !in_quotes;
        } else if (*p == ',' && !in_quotes) {
            /* End of field */
            buffer[buffer_pos] = '\0';
            fields[field_count] = malloc(strlen(buffer) + 1);
            if (fields[field_count]) {
                strcpy(fields[field_count], buffer);
                trim_whitespace(fields[field_count]);
            }
            field_count++;
            buffer_pos = 0;
        } else {
            if (buffer_pos < MAX_FIELD_LENGTH - 1) {
                buffer[buffer_pos++] = *p;
            }
        }
    }
    
    /* Last field */
    if (field_count < max_fields) {
        buffer[buffer_pos] = '\0';
        fields[field_count] = malloc(strlen(buffer) + 1);
        if (fields[field_count]) {
            strcpy(fields[field_count], buffer);
            trim_whitespace(fields[field_count]);
        }
        field_count++;
    }
    
    return field_count;
}

/* Free parsed fields */
void free_csv_fields(char **fields, int count) {
    for (int i = 0; i < count; i++) {
        free(fields[i]);
    }
}

/* Find column index by name (case-insensitive substring match) */
static int find_column_index(char **header_fields, int field_count, const char **candidates) {
    for (int i = 0; i < field_count; i++) {
        if (!header_fields[i]) continue;
        
        char lower_field[MAX_FIELD_LENGTH];
        strncpy(lower_field, header_fields[i], MAX_FIELD_LENGTH - 1);
        lower_field[MAX_FIELD_LENGTH - 1] = '\0';
        
        /* Convert to lowercase */
        for (char *p = lower_field; *p; p++) {
            *p = tolower((unsigned char)*p);
        }
        
        /* Check against all candidates */
        for (int j = 0; candidates[j] != NULL; j++) {
            if (strstr(lower_field, candidates[j]) != NULL) {
                return i;
            }
        }
    }
    return -1;
}

/* Parse CSV header and create schema */
int parse_csv_schema(const char *header_line, CSVSchema *schema) {
    if (!header_line || !schema) return -1;
    
    char *fields[MAX_COLUMNS];
    int field_count = parse_csv_line(header_line, fields, MAX_COLUMNS);
    
    if (field_count <= 0) return -1;
    
    /* Initialize schema */
    memset(schema, 0, sizeof(CSVSchema));
    schema->column_count = field_count;
    
    /* Define column name candidates */
    const char *src_ip_names[] = {"source ip", "src ip", "ip.src", NULL};
    const char *dst_ip_names[] = {"destination ip", "dst ip", "ip.dst", NULL};
    const char *src_port_names[] = {"source port", "src port", "sport", NULL};
    const char *dst_port_names[] = {"destination port", "dst port", "dport", NULL};
    const char *protocol_names[] = {"protocol", "proto", NULL};
    const char *timestamp_names[] = {"timestamp", "time", NULL};
    const char *duration_names[] = {"flow duration", "duration", NULL};
    const char *fwd_pkt_names[] = {"total fwd packets", "fwd packets", NULL};
    const char *bwd_pkt_names[] = {"total backward packets", "bwd packets", NULL};
    const char *bytes_per_sec_names[] = {"flow bytes/s", "bytes/s", NULL};
    const char *pkts_per_sec_names[] = {"flow packets/s", "packets/s", NULL};
    const char *fwd_iat_mean_names[] = {"fwd iat mean", NULL};
    const char *pkt_len_mean_names[] = {"packet length mean", "pkt len mean", NULL};
    const char *syn_flag_names[] = {"syn flag count", "syn flag", NULL};
    const char *label_names[] = {"label", "class", NULL};
    
    /* Find column indices */
    schema->src_ip_idx = find_column_index(fields, field_count, src_ip_names);
    schema->dst_ip_idx = find_column_index(fields, field_count, dst_ip_names);
    schema->src_port_idx = find_column_index(fields, field_count, src_port_names);
    schema->dst_port_idx = find_column_index(fields, field_count, dst_port_names);
    schema->protocol_idx = find_column_index(fields, field_count, protocol_names);
    schema->timestamp_idx = find_column_index(fields, field_count, timestamp_names);
    schema->flow_duration_idx = find_column_index(fields, field_count, duration_names);
    schema->total_fwd_packets_idx = find_column_index(fields, field_count, fwd_pkt_names);
    schema->total_bwd_packets_idx = find_column_index(fields, field_count, bwd_pkt_names);
    schema->flow_bytes_per_sec_idx = find_column_index(fields, field_count, bytes_per_sec_names);
    schema->flow_packets_per_sec_idx = find_column_index(fields, field_count, pkts_per_sec_names);
    schema->fwd_iat_mean_idx = find_column_index(fields, field_count, fwd_iat_mean_names);
    schema->packet_length_mean_idx = find_column_index(fields, field_count, pkt_len_mean_names);
    schema->syn_flag_count_idx = find_column_index(fields, field_count, syn_flag_names);
    schema->label_idx = find_column_index(fields, field_count, label_names);
    
    free_csv_fields(fields, field_count);
    
    /* Verify essential columns exist */
    if (schema->src_ip_idx < 0 || schema->dst_ip_idx < 0) {
        fprintf(stderr, "Error: CSV missing essential columns (Source IP, Destination IP)\n");
        return -1;
    }
    
    return 0;
}

/* Parse single flow record from CSV line */
int parse_flow_record(const char *line, const CSVSchema *schema, FlowRecord *flow) {
    if (!line || !schema || !flow) return -1;
    
    char *fields[MAX_COLUMNS];
    int field_count = parse_csv_line(line, fields, MAX_COLUMNS);
    
    if (field_count != schema->column_count) {
        free_csv_fields(fields, field_count);
        return -1;
    }
    
    /* Initialize flow record */
    memset(flow, 0, sizeof(FlowRecord));
    
    /* Parse essential fields */
    if (schema->src_ip_idx >= 0 && schema->src_ip_idx < field_count) {
        strncpy(flow->src_ip, fields[schema->src_ip_idx], MAX_IP_LENGTH - 1);
    }
    if (schema->dst_ip_idx >= 0 && schema->dst_ip_idx < field_count) {
        strncpy(flow->dst_ip, fields[schema->dst_ip_idx], MAX_IP_LENGTH - 1);
    }
    if (schema->src_port_idx >= 0 && schema->src_port_idx < field_count) {
        flow->src_port = (uint16_t)atoi(fields[schema->src_port_idx]);
    }
    if (schema->dst_port_idx >= 0 && schema->dst_port_idx < field_count) {
        flow->dst_port = (uint16_t)atoi(fields[schema->dst_port_idx]);
    }
    if (schema->protocol_idx >= 0 && schema->protocol_idx < field_count) {
        flow->protocol = (uint8_t)atoi(fields[schema->protocol_idx]);
    }
    if (schema->timestamp_idx >= 0 && schema->timestamp_idx < field_count) {
        strncpy(flow->timestamp, fields[schema->timestamp_idx], 63);
    }
    if (schema->flow_duration_idx >= 0 && schema->flow_duration_idx < field_count) {
        flow->flow_duration = atof(fields[schema->flow_duration_idx]);
    }
    if (schema->total_fwd_packets_idx >= 0 && schema->total_fwd_packets_idx < field_count) {
        flow->total_fwd_packets = atoi(fields[schema->total_fwd_packets_idx]);
    }
    if (schema->total_bwd_packets_idx >= 0 && schema->total_bwd_packets_idx < field_count) {
        flow->total_bwd_packets = atoi(fields[schema->total_bwd_packets_idx]);
    }
    if (schema->flow_bytes_per_sec_idx >= 0 && schema->flow_bytes_per_sec_idx < field_count) {
        flow->flow_bytes_per_sec = atof(fields[schema->flow_bytes_per_sec_idx]);
    }
    if (schema->flow_packets_per_sec_idx >= 0 && schema->flow_packets_per_sec_idx < field_count) {
        flow->flow_packets_per_sec = atof(fields[schema->flow_packets_per_sec_idx]);
    }
    if (schema->packet_length_mean_idx >= 0 && schema->packet_length_mean_idx < field_count) {
        flow->packet_length_mean = atof(fields[schema->packet_length_mean_idx]);
    }
    if (schema->syn_flag_count_idx >= 0 && schema->syn_flag_count_idx < field_count) {
        flow->syn_flag_count = atoi(fields[schema->syn_flag_count_idx]);
    }
    if (schema->label_idx >= 0 && schema->label_idx < field_count) {
        strncpy(flow->label, fields[schema->label_idx], 63);
        /* Determine if attack */
        char lower_label[64];
        strncpy(lower_label, flow->label, 63);
        lower_label[63] = '\0';
        for (char *p = lower_label; *p; p++) {
            *p = tolower((unsigned char)*p);
        }
        flow->is_attack = (strstr(lower_label, "benign") == NULL && strlen(flow->label) > 0);
    }
    
    free_csv_fields(fields, field_count);
    return 0;
}

/* Read CSV dataset into flow windows */
int read_csv_dataset(const char *filepath, FlowWindow **windows, int *num_windows, 
                     int window_size) {
    FILE *fp = fopen(filepath, "r");
    if (!fp) {
        perror("Failed to open dataset file");
        return -1;
    }
    
    /* Read header */
    char header_line[MAX_LINE_LENGTH];
    if (!fgets(header_line, sizeof(header_line), fp)) {
        fclose(fp);
        return -1;
    }
    
    /* Parse schema */
    CSVSchema schema;
    if (parse_csv_schema(header_line, &schema) < 0) {
        fclose(fp);
        return -1;
    }
    
    /* Count total lines first */
    int total_flows = 0;
    while (fgets(header_line, sizeof(header_line), fp)) {
        total_flows++;
    }
    rewind(fp);
    fgets(header_line, sizeof(header_line), fp); /* Skip header again */
    
    /* Calculate number of windows */
    *num_windows = (total_flows + window_size - 1) / window_size;
    *windows = calloc(*num_windows, sizeof(FlowWindow));
    if (!*windows) {
        fclose(fp);
        return -1;
    }
    
    /* Read flows into windows */
    int current_window = 0;
    int flows_in_window = 0;
    FlowRecord *current_flows = malloc(window_size * sizeof(FlowRecord));
    if (!current_flows) {
        free(*windows);
        fclose(fp);
        return -1;
    }
    
    char line[MAX_LINE_LENGTH];
    int row_num = 0;
    while (fgets(line, sizeof(line), fp)) {
        FlowRecord flow;
        if (parse_flow_record(line, &schema, &flow) == 0) {
            current_flows[flows_in_window++] = flow;
            
            if (flows_in_window >= window_size) {
                /* Store completed window */
                (*windows)[current_window].flows = malloc(flows_in_window * sizeof(FlowRecord));
                memcpy((*windows)[current_window].flows, current_flows, 
                       flows_in_window * sizeof(FlowRecord));
                (*windows)[current_window].flow_count = flows_in_window;
                (*windows)[current_window].window_id = current_window;
                (*windows)[current_window].start_row = row_num - flows_in_window + 1;
                (*windows)[current_window].end_row = row_num;
                
                current_window++;
                flows_in_window = 0;
            }
            row_num++;
        }
    }
    
    /* Handle remaining flows */
    if (flows_in_window > 0) {
        (*windows)[current_window].flows = malloc(flows_in_window * sizeof(FlowRecord));
        memcpy((*windows)[current_window].flows, current_flows, 
               flows_in_window * sizeof(FlowRecord));
        (*windows)[current_window].flow_count = flows_in_window;
        (*windows)[current_window].window_id = current_window;
        (*windows)[current_window].start_row = row_num - flows_in_window + 1;
        (*windows)[current_window].end_row = row_num;
        current_window++;
    }
    
    free(current_flows);
    fclose(fp);
    
    *num_windows = current_window;
    return current_window;
}

/* Free flow windows */
void free_flow_windows(FlowWindow *windows, int num_windows) {
    if (!windows) return;
    for (int i = 0; i < num_windows; i++) {
        free(windows[i].flows);
    }
    free(windows);
}
