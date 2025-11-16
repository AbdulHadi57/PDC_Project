#include "../include/common.h"
#include <unistd.h>

/* Placeholder for mitigation engine */

/* Execute iptables block command */
int apply_iptables_block(const char *ip, const char *chain) {
    if (!ip || !chain) return -1;
    
    char command[512];
    snprintf(command, sizeof(command), "iptables -C %s -s %s -j DROP 2>/dev/null", chain, ip);
    
    /* Check if rule already exists */
    if (system(command) == 0) {
        printf("  [INFO] iptables rule already exists for %s\n", ip);
        return 0;
    }
    
    /* Add new rule */
    snprintf(command, sizeof(command), "iptables -A %s -s %s -j DROP", chain, ip);
    int result = system(command);
    
    if (result == 0) {
        print_colored(COLOR_GREEN, "  [✓] Blocked IP: %s\n", ip);
    } else {
        print_colored(COLOR_RED, "  [✗] Failed to block IP: %s\n", ip);
    }
    
    return result;
}

/* Apply tc rate limiting */
int apply_tc_rate_limit(const char *ip, const char *interface, 
                       const char *rate, const char *burst) {
    if (!ip || !interface || !rate || !burst) return -1;
    
    char command[1024];
    
    /* Ensure ingress qdisc exists - check more reliably */
    snprintf(command, sizeof(command), 
            "tc qdisc show dev %s | grep -q ingress", interface);
    
    if (system(command) != 0) {
        /* Ingress qdisc doesn't exist, create it */
        snprintf(command, sizeof(command), 
                "tc qdisc add dev %s handle ffff: ingress", interface);
        int qdisc_result = system(command);
        
        if (qdisc_result != 0) {
            print_colored(COLOR_RED, "  [✗] Failed to create ingress qdisc on %s\n", interface);
            return -1;
        }
    }
    
    /* Add rate limiting filter */
    snprintf(command, sizeof(command),
            "tc filter add dev %s parent ffff: protocol ip prio 1 u32 "
            "match ip src %s/32 police rate %s burst %s drop flowid :1",
            interface, ip, rate, burst);
    
    int result = system(command);
    
    if (result == 0) {
        print_colored(COLOR_CYAN, "  [✓] Rate limited IP: %s (%s)\n", ip, rate);
    } else {
        /* Check if filter already exists (not an error) */
        snprintf(command, sizeof(command),
                "tc filter show dev %s parent ffff: | grep -q %s", interface, ip);
        if (system(command) == 0) {
            print_colored(COLOR_YELLOW, "  [~] Rate limit already exists for: %s\n", ip);
        } else {
            print_colored(COLOR_RED, "  [✗] Failed to add rate limit for: %s\n", ip);
        }
    }
    
    return 0;  /* Don't fail on duplicate */
}

/* Apply mitigation for list of suspicious IPs */
int apply_mitigation(const SuspiciousList *list, const char *interface,
                    const char *rate_limit, const char *rate_burst,
                    int min_count, bool enable_block, bool enable_rate_limit) {
    if (!list || list->count == 0) {
        printf("No suspicious IPs to mitigate.\n");
        return 0;
    }
    
    print_colored(COLOR_YELLOW, "\n╔════════════════════════════════════════════════════════════╗\n");
    print_colored(COLOR_YELLOW, "║          %sMITIGATION ACTIONS%s                             ║\n",
                 COLOR_BOLD, COLOR_YELLOW);
    print_colored(COLOR_YELLOW, "╚════════════════════════════════════════════════════════════╝\n\n");
    
    int mitigated_count = 0;
    
    for (size_t i = 0; i < list->count; i++) {
        if (list->entries[i].count < min_count) {
            continue;
        }
        
        const char *ip = list->entries[i].ip;
        int count = list->entries[i].count;
        
        printf("Processing IP: %s%s%s (detections: %d)\n", 
               COLOR_RED, ip, COLOR_RESET, count);
        
        if (enable_block) {
            apply_iptables_block(ip, "INPUT");
        }
        
        if (enable_rate_limit) {
            apply_tc_rate_limit(ip, interface, rate_limit, rate_burst);
        }
        
        mitigated_count++;
    }
    
    print_colored(COLOR_GREEN, "\nMitigation complete: %d IPs processed\n", mitigated_count);
    
    return mitigated_count;
}

/* Check if running as root (required for mitigation) */
bool check_root_privileges(void) {
    return (geteuid() == 0);
}
