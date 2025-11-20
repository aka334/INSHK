#!/usr/bin/env python3
"""
Control Plane
"""
import time
import threading
import math

class FlowID:
    def __init__(self, src_ip, dst_ip, fingerprint):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.fingerprint = fingerprint
    
    def __hash__(self):
        return hash((self.src_ip, self.dst_ip))
    
    def __eq__(self, other):
        return (self.src_ip == other.src_ip and 
                self.dst_ip == other.dst_ip)
    
    def __str__(self):
        return f"{self.ip_to_str(self.src_ip)} → {self.ip_to_str(self.dst_ip)} (fp:0x{self.fingerprint:04x})"
    
    @staticmethod
    def ip_to_str(ip):
        return f"{(ip>>24)&0xFF}.{(ip>>16)&0xFF}.{(ip>>8)&0xFF}.{ip&0xFF}"

class HeavyKeeperFingerprintManager:
    def __init__(self):
        self.index_to_flow = {}
        self.replacements = 0
        self.insertions = 0
        self.lock = threading.Lock()
    
    def handle_digest(self, target, digest_list):
        """Process fingerprint replacement digest"""
        with self.lock:
            for digest in digest_list:
                try:
                    index = digest['index']
                    old_fp = digest['old_fingerprint']
                    new_fp = digest['new_fingerprint']
                    src_ip = digest['srcAddr']
                    dst_ip = digest['dstAddr']
                    
                    new_flow = FlowID(src_ip, dst_ip, new_fp)
                    
                    # Pack fingerprint and counter=1 as [fp:16][ctr:16]
                    new_value = (new_fp << 16) | 1
                    
                    print(f"✓ Writing fingerprint 0x{new_fp:04x} (counter=1) to index {index}")
                    bfrt.ins.pipe.HK_reg.mod(
                        REGISTER_INDEX=index,
                        f1=new_value
                    )
                    
                    if old_fp == 0:
                        self.insertions += 1
                        print(f"  → New flow: {new_flow}")
                    else:
                        self.replacements += 1
                        old_flow = self.index_to_flow.get(index)
                        if old_flow:
                            print(f"  → Replaced: {old_flow}")
                            print(f"  → New:      {new_flow}")
                    
                    self.index_to_flow[index] = new_flow
                    
                except Exception as e:
                    print(f"Error processing digest: {e}")
    
    def read_counter(self, index):
        """Read counter value from data plane"""
        try:
            entry = bfrt.ins.pipe.HK_reg.get(
                REGISTER_INDEX=index,
                print_ents=False
            )
            if entry:
                val = entry.data[b'SwitchIngress.HK_reg.f1']
                return val & 0xFFFF  # Lower 16 bits = counter
        except:
            pass
        return 0
    
    def get_heavy_hitters(self, threshold=100):
        """Get flows with counter > threshold"""
        with self.lock:
            heavy = []
            for index, flow in self.index_to_flow.items():
                counter = self.read_counter(index)
                if counter >= threshold:
                    heavy.append((flow, counter))
            return sorted(heavy, key=lambda x: x[1], reverse=True)
    
    def print_statistics(self):
        """Print statistics"""
        with self.lock:
            print("\n" + "=" * 80)
            print("HeavyKeeper Fingerprint Manager Statistics")
            print("=" * 80)
            print(f"Total insertions:     {self.insertions:,}")
            print(f"Total replacements:   {self.replacements:,}")
            print(f"Active flows:         {len(self.index_to_flow):,}")
            
            heavy = self.get_heavy_hitters(threshold=10)
            if heavy:
                print("\nTop Heavy Hitters:")
                print("-" * 80)
                for i, (flow, count) in enumerate(heavy[:10]):
                    print(f"{i+1:2d}. {count:6d} pkts | {flow}")
            print("=" * 80 + "\n")
    
    def export_results(self, filename="heavykeeper_results.txt"):
        """Export results to file"""
        with self.lock:
            heavy = self.get_heavy_hitters(threshold=1)
            
            with open(filename, 'w') as f:
                f.write("HeavyKeeper Results\n")
                f.write("=" * 80 + "\n\n")
                f.write(f"Total insertions: {self.insertions:,}\n")
                f.write(f"Total replacements: {self.replacements:,}\n")
                f.write(f"Active flows: {len(self.index_to_flow):,}\n\n")
                
                f.write("Heavy Hitters:\n")
                f.write("-" * 80 + "\n")
                for i, (flow, count) in enumerate(heavy):
                    f.write(f"{i+1}. {count:6d} pkts | {flow}\n")
            
            print(f"✓ Exported {len(heavy)} flows to {filename}")

def initialize_system():
    """Initialize INS + HeavyKeeper system"""
    print("=" * 80)
    print("Initializing INS + HeavyKeeper System")
    print("=" * 80)
    
    bfrt.ins.clear()
    
    # INS parameters
    m = 131072  # Bitmap size
    epsilon = 0.05
    beta = 0.05
    p_beta = 1.0 / (1.0 + (epsilon**2) * beta)
    p2 = max(p_beta, 1.0 / math.e)
    constant = m * m * p2
    
    print(f"\nINS Parameters:")
    print(f"  Bitmap size (m):    {m:,}")
    print(f"  Epsilon:            {epsilon}")
    print(f"  Beta:               {beta}")
    print(f"  p₂:                 {p2:.6f}")
    
    print(f"\n[1/5] Initializing Z register...")
    bfrt.ins.pipe.Z.mod(REGISTER_INDEX=0, f1=m)
    
    print(f"[2/5] Initializing P_table (sampling probabilities)...")
    for counter in range(min(1000, 65536)):
        # Simple linear probability for now
        prob = min(1000, counter * 10)
        bfrt.ins.pipe.P_table.mod(REGISTER_INDEX=counter, f1=prob)
    
    print(f"[3/5] Initializing admission threshold...")
    threshold = int(constant / m)
    print(f"  Threshold: {threshold}")
    bfrt.ins.pipe.admission_threshold_reg.mod(REGISTER_INDEX=0, f1=threshold)
    
    print(f"[4/5] Initializing decay probability table...")
    b = 1.08  # Decay base
    for C in range(min(1000, 65536)):
        decay_prob = int((b ** (-C)) * 65535)
        bfrt.ins.pipe.decay_prob_table.mod(REGISTER_INDEX=C, f1=decay_prob)
    
    print(f"[5/5] HeavyKeeper register initialized (all zeros)")
    
    print("\n✓ Initialization complete!")
    print("=" * 80 + "\n")

def start_heavykeeper():
    """Start HeavyKeeper control plane"""
    print("=" * 80)
    print("Starting HeavyKeeper Control Plane")
    print("=" * 80 + "\n")
    
    initialize_system()
    
    global hk_mgr
    hk_mgr = HeavyKeeperFingerprintManager()
    
    print("Registering digest callback...")
    try:
        bfrt.ins.pipe.SwitchIngress.hk_digest.callback_register(
            hk_mgr.handle_digest
        )
        print("✓ Digest callback registered\n")
    except Exception as e:
        print(f"⚠️  Warning: {e}\n")
    
    print("=" * 80)
    print("HeavyKeeper is now running!")
    print("=" * 80)
    print("\nControl plane will write fingerprints when counter reaches 0")
    print("\nAvailable commands:")
    print("  hk_mgr.print_statistics()        - Show current stats")
    print("  hk_mgr.get_heavy_hitters(100)    - Get flows with count > 100")
    print("  hk_mgr.export_results()          - Export results to file")
    print("=" * 80 + "\n")
    
    # Periodic stats
    def stats_loop():
        while True:
            time.sleep(30)
            hk_mgr.print_statistics()
    
    stats_thread = threading.Thread(target=stats_loop, daemon=True)
    stats_thread.start()

hk_mgr = None

if __name__ == "__main__":
    start_heavykeeper()