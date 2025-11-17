#include "../include/orchestrator.h"
#include "../include/common.h"
#include <mpi.h>

/* MPI communication helpers */

/* Send flow window to worker */
int mpi_send_window(const FlowWindow *window, int dest_rank) {
    if (!window) return -1;
    
    /* Send metadata */
    int metadata[4] = {window->window_id, window->start_row, window->end_row, window->flow_count};
    MPI_Send(metadata, 4, MPI_INT, dest_rank, TAG_WINDOW_META, MPI_COMM_WORLD);
    
    /* Send flow data */
    if (window->flow_count > 0) {
        MPI_Send(window->flows, window->flow_count * sizeof(FlowRecord), MPI_BYTE, 
                dest_rank, TAG_WINDOW_DATA, MPI_COMM_WORLD);
    }
    
    return 0;
}

/* Receive flow window from master */
int mpi_recv_window(FlowWindow *window, int source_rank) {
    if (!window) return -1;
    
    /* Receive metadata */
    int metadata[4];
    MPI_Recv(metadata, 4, MPI_INT, source_rank, TAG_WINDOW_META, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
    
    window->window_id = metadata[0];
    window->start_row = metadata[1];
    window->end_row = metadata[2];
    window->flow_count = metadata[3];
    
    /* Receive flow data */
    if (window->flow_count > 0) {
        window->flows = malloc(window->flow_count * sizeof(FlowRecord));
        if (!window->flows) return -1;
        
        MPI_Recv(window->flows, window->flow_count * sizeof(FlowRecord), MPI_BYTE,
                source_rank, TAG_WINDOW_DATA, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
    } else {
        window->flows = NULL;
    }
    
    return 0;
}

/* Send window result to master */
int mpi_send_result(const WindowResult *result, int dest_rank) {
    if (!result) return -1;
    
    /* Send result metadata */
    int metadata[9] = {
        result->window_id, result->start_row, result->end_row, result->flow_count,
        result->entropy_prediction, result->pca_prediction, result->cusum_prediction,
        result->combined_prediction, result->ground_truth
    };
    MPI_Send(metadata, 9, MPI_INT, dest_rank, TAG_RESULT_META, MPI_COMM_WORLD);
    
    /* Send metrics */
    double metrics[10] = {
        result->entropy_anomaly_score, result->pca_anomaly_score, result->cusum_anomaly_score,
        result->norm_entropy_src_ip, result->norm_entropy_dst_ip,
        result->pca_spe, result->pca_t2, result->cusum_positive, result->cusum_negative,
        result->processing_time_ms
    };
    MPI_Send(metrics, 10, MPI_DOUBLE, dest_rank, TAG_RESULT_DATA, MPI_COMM_WORLD);
    
    /* Send suspicious IP count and list */
    int ip_count = result->suspicious_ips.count;
    MPI_Send(&ip_count, 1, MPI_INT, dest_rank, TAG_RESULT_DATA, MPI_COMM_WORLD);
    
    if (ip_count > 0) {
        for (int i = 0; i < ip_count; i++) {
            MPI_Send(result->suspicious_ips.entries[i].ip, MAX_IP_LENGTH, MPI_CHAR,
                    dest_rank, TAG_RESULT_DATA, MPI_COMM_WORLD);
            MPI_Send(&result->suspicious_ips.entries[i].count, 1, MPI_INT,
                    dest_rank, TAG_RESULT_DATA, MPI_COMM_WORLD);
        }
    }
    
    return 0;
}

/* Receive window result from worker */
int mpi_recv_result(WindowResult *result, int source_rank) {
    if (!result) return -1;
    
    memset(result, 0, sizeof(WindowResult));
    suspicious_list_init(&result->suspicious_ips);
    
    /* Receive result metadata */
    int metadata[9];
    MPI_Recv(metadata, 9, MPI_INT, source_rank, TAG_RESULT_META, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
    
    result->window_id = metadata[0];
    result->start_row = metadata[1];
    result->end_row = metadata[2];
    result->flow_count = metadata[3];
    result->entropy_prediction = metadata[4];
    result->pca_prediction = metadata[5];
    result->cusum_prediction = metadata[6];
    result->combined_prediction = metadata[7];
    result->ground_truth = metadata[8];
    
    /* Receive metrics */
    double metrics[10];
    MPI_Recv(metrics, 10, MPI_DOUBLE, source_rank, TAG_RESULT_DATA, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
    
    result->entropy_anomaly_score = metrics[0];
    result->pca_anomaly_score = metrics[1];
    result->cusum_anomaly_score = metrics[2];
    result->norm_entropy_src_ip = metrics[3];
    result->norm_entropy_dst_ip = metrics[4];
    result->pca_spe = metrics[5];
    result->pca_t2 = metrics[6];
    result->cusum_positive = metrics[7];
    result->cusum_negative = metrics[8];
    result->processing_time_ms = metrics[9];
    
    /* Receive suspicious IPs */
    int ip_count;
    MPI_Recv(&ip_count, 1, MPI_INT, source_rank, TAG_RESULT_DATA, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
    
    for (int i = 0; i < ip_count; i++) {
        char ip[MAX_IP_LENGTH];
        int count;
        MPI_Recv(ip, MAX_IP_LENGTH, MPI_CHAR, source_rank, TAG_RESULT_DATA, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
        MPI_Recv(&count, 1, MPI_INT, source_rank, TAG_RESULT_DATA, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
        
        for (int j = 0; j < count; j++) {
            suspicious_list_add(&result->suspicious_ips, ip);
        }
    }
    
    return 0;
}

/* Broadcast termination signal to all workers */
void mpi_broadcast_terminate(const MPIContext *mpi_ctx) {
    if (!mpi_ctx || !mpi_ctx->is_master) return;
    
    int terminate_signal = -1;
    for (int i = 1; i < mpi_ctx->world_size; i++) {
        MPI_Send(&terminate_signal, 1, MPI_INT, i, TAG_TERMINATE, MPI_COMM_WORLD);
    }
}

/* Check for termination signal (worker) */
int mpi_check_terminate(void) {
    int flag;
    MPI_Status status;
    MPI_Iprobe(0, TAG_TERMINATE, MPI_COMM_WORLD, &flag, &status);
    return flag;
}
