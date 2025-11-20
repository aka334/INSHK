//===============================================================
// INS_THK
//===============================================================
#include <tna.p4>

// ---------------------------------------------------------------
// Headers & Metadata
// ---------------------------------------------------------------
header ethernet_t {
    bit<48> dst;
    bit<48> src;
    bit<16> eth_type;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

struct my_ingress_headers_t {
    ethernet_t ethernet;
    ipv4_t     ipv4;
}

struct my_ingress_metadata_t {
    bit<16> fingerprint;
    bit<32> idx;
    bit<16> c_f;
    bit<1>  sampled;
    bit<32> hash_flow;
    bit<32> hash_pkt;
    bit<1>  bitmap_hit;
    bit<16> coin;
    bit<16> prob_thousand;
    bit<16> tmp_val;

    bit<1> b_val;        
    bit<1> do_mark;       
    // NEW: scratch for HK
    bit<16> old_fp;
    bit<16> old_ctr;
    bit<16> new_fp;
    bit<16> new_ctr;

    // INS admission check
    bit<32> z_value;
    bit<32> admission_threshold;
    bit<1>  admit_to_hk;


    // NEW: Resubmit control
    bit<1> is_resubmitted;     
    bit<1> needs_hk_update;    
    bit<32> hk_update_idx;     

    // HeavyKeeper decay logic
    bit<16> decay_prob;      
    bit<16> random_val;      
    bit<1>  should_decay;    
    bit<1>  fp_match;        

    // Digest control
    bit<1>  send_digest;     

}

struct my_egress_headers_t { }
struct my_egress_metadata_t { }

// Digest for fingerprint replacement (sent to control plane)
struct hk_replacement_digest_t {
    bit<32> index;           
    bit<16> old_fingerprint; 
    bit<16> new_fingerprint; 
    bit<32> srcAddr;    
    bit<32> dstAddr;
}

// ---------------------------------------------------------------
// Hash extern
// ---------------------------------------------------------------
Hash<bit<32>>(HashAlgorithm_t.CRC32) hash_flow_id;
Hash<bit<32>>(HashAlgorithm_t.CRC32) hash_pkt_id;

// ---------------------------------------------------------------
// Tofino Register Definitions (HeavyKeeper + INS)
// ---------------------------------------------------------------

// Adjustable sizes
const bit<32> HK_REG_SIZE = 65536;
const bit<32> B_SIZE      = 131072;

// Register for HeavyKeeper: <data_type, index_type>
Register<bit<32>, bit<32>>(HK_REG_SIZE) HK_reg;

// 1-bit bitmap for duplicate filtering
Register<bit<1>, bit<32>>(B_SIZE) B;

// Scalar register for number of zeros (single entry)
Register<bit<32>, bit<32>>(1) Z;

// Probability lookup table: maps counter → probability×1000
const bit<32> TABLE_SIZE = 65536;
Register<bit<16>, bit<16>>(TABLE_SIZE, 0) P_table;

// RegisterAction to read probability value
RegisterAction<bit<16>, bit<16>, bit<16>>(P_table) P_table_read = {
    void apply(inout bit<16> val, out bit<16> rv) { rv = val; }
};

// Simple 32-bit threshold (updated by control plane)
Register<bit<32>, bit<32>>(1) admission_threshold_reg;

RegisterAction<bit<32>, bit<32>, bit<32>>(admission_threshold_reg) read_threshold = {
    void apply(inout bit<32> val, out bit<32> rv) {
        rv = val;
    }
};

// Decay probability table: b^(-C) for exponential decay
// Maps counter value C → decay probability (scaled to 16-bit)
Register<bit<16>, bit<16>>(65536) decay_prob_table;

RegisterAction<bit<16>, bit<16>, bit<16>>(decay_prob_table) read_decay_prob = {
    void apply(inout bit<16> val, out bit<16> rv) {
        rv = val;
    }
};

// ---------------------------------------------------------------
// Combined RegisterAction for Bitmap (Read + Conditional Write)
// ---------------------------------------------------------------
RegisterAction<bit<1>, bit<32>, bit<1>>(B) B_read_and_write = {
    void apply(inout bit<1> val, out bit<1> rv) {
        rv = val;  // return old value
        val = 1;   // write 1
    }
};

RegisterAction<bit<1>, bit<32>, bit<1>>(B) B_read_only = {
    void apply(inout bit<1> val, out bit<1> rv) {
        rv = val;  // just read
    }
};

// --- Z : scalar register tracking number of zero bits ---

RegisterAction<bit<32>, bit<32>, void>(Z) Z_decrement = {
    void apply(inout bit<32> val) { val = val - 1; }
};

// Add after existing RegisterActions, before control block:

// RegisterAction to read Z value
RegisterAction<bit<32>, bit<32>, bit<32>>(Z) Z_read_value = {
    void apply(inout bit<32> val, out bit<32> rv) {
        rv = val;
    }
};

// ============ HeavyKeeper RegisterActions ============

// Read both fingerprint and counter
RegisterAction<bit<32>, bit<32>, bit<32>>(HK_reg) hk_read = {
    void apply(inout bit<32> val, out bit<32> rv) {
        rv = val;  // Return [fingerprint:16][counter:16]
    }
};

// Increment counter only (simple version)
RegisterAction<bit<32>, bit<32>, void>(HK_reg) hk_increment_ctr = {
    void apply(inout bit<32> val) {
        val = val + 1;  
    }
};

// Decrement counter and return full value
RegisterAction<bit<32>, bit<32>, bit<32>>(HK_reg) hk_decrement_ctr = {
    void apply(inout bit<32> val, out bit<32> rv) {
        val = val - 1; 
        rv = val;      
    }
};
///////////////////////////////////
// ---------------------------------------------------------------
// Ingress Parser / Deparser
// ---------------------------------------------------------------
parser MyIngressParser(
    packet_in pkt,
    out my_ingress_headers_t h,
    out my_ingress_metadata_t m,
    out ingress_intrinsic_metadata_t ig_intr_md
) {
    state start {
        m.fingerprint = 0;
        m.idx         = 0;
        m.c_f         = 0;
        m.sampled     = 0;
        m.hash_flow   = 0;
        m.hash_pkt    = 0;
        m.bitmap_hit  = 0;
        m.coin = 0;
        m.prob_thousand = 0;
        m.tmp_val = 0;
        m.old_fp   = 0;
        m.old_ctr  = 0;
        m.new_fp   = 0;
        m.new_ctr  = 0;   
        m.b_val =0;
        m.do_mark = 0;
        m.z_value = 0;
        m.admission_threshold = 0;
        m.admit_to_hk = 0;

        m.is_resubmitted = 0;
        m.needs_hk_update = 0;
        m.hk_update_idx = 0;

        m.decay_prob = 0;
        m.random_val = 0;
        m.should_decay = 0;
        m.fp_match = 0;
        m.send_digest = 0;

        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        transition select(ig_intr_md.resubmit_flag) {
            1: resubmitted;
            default: parse_eth;
        }
    }

    state resubmitted {
        m.is_resubmitted = 1;
        transition parse_eth;
    }

    state parse_eth {
        pkt.extract(h.ethernet);
        transition select(h.ethernet.eth_type) {
            0x0800: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(h.ipv4);
        transition accept;
    }
}

control MyIngressDeparser(
    packet_out pkt,
    inout my_ingress_headers_t h,
    in my_ingress_metadata_t m,
    in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md
) {
    Resubmit() resubmit;
    Digest<hk_replacement_digest_t>() hk_digest;
    
    apply {
        // Send digest if needed
        if (m.send_digest == 1) {
            hk_digest.pack({
                m.hk_update_idx,
                m.old_fp,
                m.fingerprint,
                h.ipv4.srcAddr,
                h.ipv4.dstAddr
            });
        }
        
        // Resubmit if needed
        if (ig_dprsr_md.resubmit_type == 1) {
            resubmit.emit();
        }
        
        // Emit packet
        pkt.emit(h.ethernet);
        pkt.emit(h.ipv4);
    }
}

// ---------------------------------------------------------------
// Ingress Control (NO-OP for now)
// ---------------------------------------------------------------
control MyIngress(
    inout my_ingress_headers_t h,
    inout my_ingress_metadata_t m,
    in ingress_intrinsic_metadata_t ig_intr_md,
    in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t ig_tm_md
) {
    //Digest<hk_replacement_digest_t>() hk_digest;
    // ============ HK Update Actions (for resubmitted packets) ============
    action hk_increment_action() {
        hk_increment_ctr.execute(m.hk_update_idx);
    }

    action hk_decrement_action() {
        hk_decrement_ctr.execute(m.hk_update_idx);
    }

    action hk_no_update_action() {
        // Do nothing
    }

    table hk_update_table {
        key = {
            m.is_resubmitted : exact;
            m.old_ctr : ternary;
            m.fp_match : exact;
            m.should_decay : exact;
        }
        actions = {
            hk_increment_action;
            hk_decrement_action;
            hk_no_update_action;
        }
        default_action = hk_no_update_action;
        size = 16;
    }

    // ============ Action to trigger resubmit ============
    action trigger_resubmit() {
        ig_dprsr_md.resubmit_type = 1;  // Set resubmit flag
        m.needs_hk_update = 1;
        m.hk_update_idx = m.hash_flow;
    }

    action no_resubmit() {
        ig_dprsr_md.resubmit_type = 0;
    }

    table resubmit_decision_table {
        key = {
            m.admit_to_hk : exact;      
            m.is_resubmitted : exact;
        }
        actions = {
            trigger_resubmit;
            no_resubmit;
        }
        const entries = {
            (1w1, 1w0) : trigger_resubmit(); 
        }
        default_action = no_resubmit;
        size = 4;
    }
    // ============ Stage 0: Compute Flow Hash ============
    action compute_flow_hash_action() {
        m.hash_flow = hash_flow_id.get({
            h.ipv4.srcAddr,
            h.ipv4.dstAddr
        });
    }

    table compute_flow_hash_table {
        actions = { compute_flow_hash_action; }
        size = 1;
        default_action = compute_flow_hash_action;
    }
    // ============================================================================
    // Stage 1: Read HK
    action hk_read_action() {
        bit<32> hk_val = hk_read.execute(m.hash_flow);
        m.old_fp = (bit<16>)(hk_val >> 16);      
        m.old_ctr = (bit<16>)(hk_val & 0xFFFF);  
    }

    table hk_read_table {
        actions = { hk_read_action; }
        size = 1;
        default_action = hk_read_action;
    }
    ///////////////////////////////////////////////////////////////////////////////
    // ============ Stage 1.5: Extract fingerprint ============
    action extract_fingerprint_action() {
        // Use part of hash_flow as fingerprint
        m.fingerprint = (bit<16>)(m.hash_flow & 0xFFFF);
    }

    table extract_fingerprint_table {
        actions = { extract_fingerprint_action; }
        size = 1;
        default_action = extract_fingerprint_action;
    }

    // ============ Stage 1.6: Check fingerprint match ============
    action set_fp_match() {
        m.fp_match = 1;
    }

    action set_fp_no_match() {
        m.fp_match = 0;
    }

    table check_fp_match_table {
        key = {
            m.old_fp : exact;
            m.fingerprint : exact;
        }
        actions = { 
            set_fp_match;
            set_fp_no_match;
        }
        default_action = set_fp_no_match;
        size = 1024;
    }

    // ============ Stage 1.7: Read decay probability ============
    action read_decay_prob_action() {
        bit<16> prob = read_decay_prob.execute(m.old_ctr);
        m.decay_prob = prob;
    }

    table read_decay_prob_table {
        actions = { read_decay_prob_action; }
        size = 1;
        default_action = read_decay_prob_action;
    }

    // ============ Stage 1.8: Generate random and decide decay ============
    action generate_random_action() {
        // Use hash_pkt as source of randomness
        m.random_val = (bit<16>)(m.hash_pkt & 0xFFFF);
    }

    table generate_random_table {
        actions = { generate_random_action; }
        size = 1;
        default_action = generate_random_action;
    }

    action set_should_decay() {
        m.should_decay = 1;
    }

    action set_no_decay() {
        m.should_decay = 0;
    }


    table decide_decay_table {
        key = {
            m.random_val : range;
            m.decay_prob : exact;
        }
        actions = { 
            set_should_decay; 
            set_no_decay; 
        }
        default_action = set_no_decay;
        size = 1024;
    }
    ////////////////////////////////////////////////////////////////////////
    // Stage 2: Get probability
    action sampling_action() {
        bit<16> p_thousand = P_table_read.execute(m.old_ctr);
        m.prob_thousand = p_thousand;
    }

    table sampling_table {
        actions = { sampling_action; }
        size = 1;
        default_action = sampling_action;
    }

    // Stage 3: Compute hash
    // Stage 3: Compute hash
    // Stage 3: Compute hash
    action compute_hash_action() {
        // hash_flow already computed in Stage 0
        
        bit<32> hash_val = hash_pkt_id.get({
            m.hash_flow, 
            h.ipv4.srcAddr, 
            h.ipv4.dstAddr
        });
        m.coin = (bit<16>)(hash_val & 0x3FF);
        m.idx  = (bit<32>)(hash_val & (B_SIZE - 1));
        m.hash_pkt = hash_val;
    }

    table compute_hash_table {
        key = {
            h.ipv4.srcAddr : exact;
        }
        actions = { compute_hash_action; }
        size = 1;
        const default_action = compute_hash_action;
    }

    // Stage 4: Sampling decision
    action set_sampled() {
        m.sampled = 1;
    }

    action set_not_sampled() {
        m.sampled = 0;
    }

    table sampling_decision {
        key = {
            m.coin          : range;
            m.prob_thousand : exact;
        }
        actions = { set_sampled; set_not_sampled; }
        default_action = set_not_sampled;
        size = 1024;
    }

    // Stage 5: Bitmap read and mark
    action bitmap_read_and_mark_action() {
        bit<1> bval = B_read_and_write.execute(m.idx);
        m.b_val = bval;
    }

    action bitmap_skip_action() {
        m.b_val = 1;  // Act as if duplicate
    }

    table bitmap_read_and_mark_table {
        key = {
            m.sampled : exact;
        }
        actions = { bitmap_read_and_mark_action; bitmap_skip_action; }
        const entries = {
            1w1 : bitmap_read_and_mark_action();
            1w0 : bitmap_skip_action();
        }
        size = 2;
    }

    // Stage 6: Check bitmap result
    action set_new_entry() {
        m.bitmap_hit = 1;
    }

    action set_duplicate() {
        m.bitmap_hit = 0;
    }

    table bitmap_check_table {
        key = {
            m.b_val : exact;
        }
        actions = { set_new_entry; set_duplicate; }
        const entries = {
            1w0 : set_new_entry();
            1w1 : set_duplicate();
        }
        size = 2;
    }

    // Stage 7: Z decrement
    action z_decrement_action() {
        Z_decrement.execute(0);
    }

    action z_no_decrement_action() {
        // Do nothing
    }

    table z_decrement_table {
        key = {
            m.bitmap_hit : exact;
            m.sampled : exact;
        }
        actions = { z_decrement_action; z_no_decrement_action; }
        const entries = {
            (1w1, 1w1) : z_decrement_action();  // Only if new and sampled
        }
        default_action = z_no_decrement_action;
        size = 4;
    }

    // ============ NEW: Stage 8 - Read Z ============
    action read_z_action() {
        bit<32> z_val = Z_read_value.execute(0);
        m.z_value = z_val;
    }

    table read_z_table {
        actions = { read_z_action; }
        size = 1;
        default_action = read_z_action;
    }


    // ============ NEW: Stage 10 - Compute H(f,e) × z ============
    // Read threshold (computed by control plane)
    action read_threshold_action() {
        m.admission_threshold = read_threshold.execute(0);
    }

    table read_threshold_table {
        actions = { read_threshold_action; }
        size = 1;
        default_action = read_threshold_action;
    }
    // ============ NEW: Stage 11 - Admission decision ============
    action admit_action() {
        m.admit_to_hk = 1;
    }

    action reject_action() {
        m.admit_to_hk = 0;
    }

   table admission_decision_table {
        key = {
            m.bitmap_hit : exact;
            m.sampled : exact;
            m.hash_pkt : ternary;          // For comparison
            m.admission_threshold : ternary; // Against threshold
        }
        actions = {
            admit_action;
            reject_action;
        }
        default_action = reject_action;
        size = 1024;  // Needs to be larger for ternary matches
    }

    apply {
        
        if (m.is_resubmitted == 1) {
            // ============ PASS 2: HeavyKeeper Update ============
            
            if (m.old_ctr == 0) {
                // Case 1: Empty slot → Insert (increment to 1)
                hk_increment_ctr.execute(m.hk_update_idx);
                m.send_digest = 1;
                
            } else if (m.fp_match == 1) {
                // Case 2: Fingerprint matches → Increment
                hk_increment_ctr.execute(m.hk_update_idx);
                
            } else if (m.should_decay == 1) {
                // Case 3: Collision with decay → Decrement
                hk_decrement_ctr.execute(m.hk_update_idx);
                
                // Check if OLD counter was 1 (will become 0 after decrement)
                if (m.old_ctr == 1) {
                    m.send_digest = 1;  // Counter will be 0 after decrement
                }
            }
            
            // Forward packet
            ig_tm_md.ucast_egress_port = 1;
                
        }else{
            compute_flow_hash_table.apply();
    
            // Stage 1: Read HK (for probability lookup only)
            hk_read_table.apply();

            // ============ NEW: Stage 1.5-1.8: HeavyKeeper Logic ============
            extract_fingerprint_table.apply();     // Extract fingerprint from hash
            check_fp_match_table.apply();          // Check if fingerprint matches
            read_decay_prob_table.apply();         // Read decay probability
            generate_random_table.apply();         // Generate random value
            decide_decay_table.apply();            // Decide if we should decay
            // Stage 2: Get probability
            sampling_table.apply();
            
            // Stage 3: Compute hash
            compute_hash_table.apply();
            
            // Stage 4: Sampling decision
            sampling_decision.apply();

            // Stage 5-7: Bitmap and Z operations
            bitmap_read_and_mark_table.apply();
            bitmap_check_table.apply();
            z_decrement_table.apply();

            read_z_table.apply();

            read_threshold_table.apply();

            // Initial admission decision
            admission_decision_table.apply();

            // Stage 12: Decide if we need to resubmit for HK update
            resubmit_decision_table.apply();
            
            // Forward packet
            ig_tm_md.ucast_egress_port = 1;
        }
    }
}
// ---------------------------------------------------------------
// Egress Parser / Control / Deparser (NO-OPs)
// ---------------------------------------------------------------
parser MyEgressParser(
    packet_in pkt,
    out my_egress_headers_t h,
    out my_egress_metadata_t m,
    out egress_intrinsic_metadata_t eg_intr_md
) {
    state start {
        pkt.extract(eg_intr_md);
        transition accept;
    }
}

control MyEgress(
    inout my_egress_headers_t h,
    inout my_egress_metadata_t m,
    in egress_intrinsic_metadata_t eg_intr_md,
    in egress_intrinsic_metadata_from_parser_t eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t eg_oport_md
) {
    apply {
        // no-op
    }
}

control MyEgressDeparser(
    packet_out pkt,
    inout my_egress_headers_t h,
    in my_egress_metadata_t m,
    in egress_intrinsic_metadata_for_deparser_t eg_dprsr_md
) {
    apply {
        // no payload/headers to emit on egress for now
    }
}

// ---------------------------------------------------------------
// Main
// ---------------------------------------------------------------
Pipeline(
    MyIngressParser(),
    MyIngress(),
    MyIngressDeparser(),
    MyEgressParser(),
    MyEgress(),
    MyEgressDeparser()
) pipe;

Switch(pipe) main;
