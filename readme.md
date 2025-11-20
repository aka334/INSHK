# INS-THK: Hardware Implementation of Individualized Non-duplicate Sampling

**Paper**: (ϵ, β)-nonduplicate Sampling for Flow Spread Measurement with Guaranteed Accuracy

This repository contains the P4 implementation of INS-THK for Intel Tofino switches, enabling line-rate spread measurement with provable (ϵ, β)-RE accuracy guarantees.

## Quick Start

### Prerequisites
- Intel Tofino switch with P4 compiler (bf-p4c)
- Python 3.7+ with BF-RT API
- SSH access to switch

### Files
```
INSHK/
├── ins_thk.p4          # P4 data plane program
├── controller.py            # Control plane setup script
├── INS_fabric.ipynb  
└── README.md
```

## Running INS-THK

### Step 1: Compile P4 Program
```bash
# On your development machine
export SDE=/path/to/bf-sde-9.x.x
$SDE/p4_build.sh ins_thk.p4
```

### Step 2: Start Switch
```bash
# Start switchd with compiled program
$SDE/run_switchd.sh -p ins_thk
```

Wait for: `bf_switchd: server started - listening on port 9999`

### Step 3: Initialize Control Plane
In a new terminal:
```bash
# Connect to BF-RT shell and run setup
$SDE/run_bfshell.py -b setup.py
```

**You should see:**
```
================================================================================
Initializing INS + HeavyKeeper System
================================================================================
[1/5] Initializing Z register...
[2/5] Initializing P_table (sampling probabilities)...
[3/5] Initializing admission threshold...
[4/5] Initializing decay probability table...
[5/5] HeavyKeeper register initialized

✓ Initialization complete!

HeavyKeeper is now running!
================================================================================
```

### Step 4: Send Traffic
```bash
# Replay PCAP file (if available)
sudo tcpreplay -i <interface> your_trace.pcap

# OR use packet generator
scapy
>>> sendp(Ether()/IP(src="10.0.0.1", dst="192.168.1.1")/UDP(), iface="enp1s0f0")
```

### Step 5: Monitor Results
In the BF-RT shell (from Step 3):
```python
# View statistics (auto-updates every 30 seconds)
hk_mgr.print_statistics()

# Get flows with > 100 packets
hk_mgr.get_heavy_hitters(threshold=100)

# Export results to file
hk_mgr.export_results("results.txt")
```


## Understanding the Output

```
================================================================================
HeavyKeeper Fingerprint Manager Statistics
================================================================================
Total insertions:     847        ← New flows inserted
Total replacements:   23         ← Flows evicted due to collisions
Active flows:         824        ← Currently tracked flows

Top Heavy Hitters:
 1.    523 pkts | 10.0.0.5 → 192.168.1.1 (fp:0x1a2b)
 2.    412 pkts | 10.0.0.3 → 192.168.1.1 (fp:0x7f3c)
================================================================================
```

- **Insertions**: Count of new flows entering HeavyKeeper
- **Replacements**: Hash collisions causing fingerprint updates
- **Active flows**: Flows currently being tracked
- **Heavy Hitters**: Flows sorted by packet count

## Data Structures

| Structure | Purpose |
|-----------|---------|
| `HK_reg` | Packed [fingerprint\|counter] pairs |
| `B` bitmap | Duplicate filtering |
| `Z` counter | Tracks bitmap saturation |
| `P_table` | Sampling probabilities |
| `decay_prob_table` | Decay probabilities b^(-c) |
