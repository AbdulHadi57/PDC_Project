#!/bin/bash

# Mitigation Cleanup Script
# Removes all iptables and tc rules to reset for testing

echo "═══════════════════════════════════════════════════════════"
echo "  DDoS Mitigation Cleanup Tool"
echo "═══════════════════════════════════════════════════════════"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Error: This script must be run as root"
    echo "Usage: sudo ./cleanup_mitigation.sh"
    exit 1
fi

# Count current rules
IPTABLES_COUNT=$(iptables -L INPUT -n | grep DROP | wc -l)
echo "[1] Current iptables DROP rules: $IPTABLES_COUNT"

if [ $IPTABLES_COUNT -gt 0 ]; then
    echo "    Removing all INPUT chain DROP rules..."
    iptables -F INPUT
    echo "    ✓ iptables INPUT chain flushed"
else
    echo "    (No DROP rules to remove)"
fi

# Check tc filters
INTERFACE="eth0"
TC_FILTER_COUNT=$(tc filter show dev $INTERFACE 2>/dev/null | wc -l)

echo ""
echo "[2] Current tc filters on $INTERFACE: $TC_FILTER_COUNT"

if [ $TC_FILTER_COUNT -gt 0 ]; then
    echo "    Removing all tc filters..."
    tc filter del dev $INTERFACE parent ffff: 2>/dev/null
    if [ $? -eq 0 ]; then
        echo "    ✓ tc filters removed"
    else
        echo "    ~ No tc filters to remove (or none existed)"
    fi
else
    echo "    (No tc filters to remove)"
fi

# Remove ingress qdisc
echo ""
echo "[3] Removing ingress qdisc..."
tc qdisc del dev $INTERFACE ingress 2>/dev/null
if [ $? -eq 0 ]; then
    echo "    ✓ Ingress qdisc removed"
else
    echo "    ~ Ingress qdisc not present"
fi

# Verify cleanup
echo ""
echo "═══════════════════════════════════════════════════════════"
echo "  Verification"
echo "═══════════════════════════════════════════════════════════"
echo ""

echo "[✓] iptables INPUT chain:"
REMAINING_DROPS=$(iptables -L INPUT -n | grep DROP | wc -l)
if [ $REMAINING_DROPS -eq 0 ]; then
    echo "    ✓ Clean (0 DROP rules)"
else
    echo "    ⚠ Still has $REMAINING_DROPS DROP rules:"
    iptables -L INPUT -n | grep DROP
fi

echo ""
echo "[✓] tc filters on $INTERFACE:"
REMAINING_FILTERS=$(tc filter show dev $INTERFACE 2>/dev/null | wc -l)
if [ $REMAINING_FILTERS -eq 0 ]; then
    echo "    ✓ Clean (0 filters)"
else
    echo "    ⚠ Still has filters:"
    tc filter show dev $INTERFACE
fi

echo ""
echo "═══════════════════════════════════════════════════════════"
echo "  Cleanup Complete!"
echo "═══════════════════════════════════════════════════════════"
echo ""
echo "You can now run mitigation tests again:"
echo "  cd ~/ddos_mpi_detector"
echo "  sudo mpirun --allow-run-as-root -np 3 ./bin/ddos_orchestrator"
echo ""
