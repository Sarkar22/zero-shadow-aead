/*
 * ascon_aead.sv -- Ascon-AEAD128 (NIST SP 800-232) with a split schedule.
 * --------------------------------------------------------------------------
 * Standard AEAD cannot be hidden the way a counter-mode keystream can, because the
 * tag depends on the record. But the work divides cleanly:
 *
 *   precomputable : initialization, 12 rounds, depends only on key and nonce
 *   must wait     : 8 rounds per record block, plus 12 for finalization
 *
 * This core exposes that split. Asserting i_pre_start runs initialization from
 * (key, nonce) and parks the state, which a streaming node does during the PREVIOUS
 * inference. When the record arrives only the data and finalization rounds remain, so
 * the visible cost of authenticated encryption is 8M+12 rounds rather than 8M+24.
 *
 * ROUNDS_PER_CYCLE is the sizing knob: a permutation of r rounds costs
 * ceil(r/ROUNDS_PER_CYCLE) cycles. The paper sizes this against the shadow length.
 *
 * Scope: empty associated data (telemetry records carry no AD here). Partial final
 * blocks are supported through i_bytes. Verified bit-exact against model/ascon_aead.py,
 * which reproduces all 1089 official Ascon-AEAD128 known-answer tests.
 */
`timescale 1ns/1ps
module ascon_aead #(
    parameter int ROUNDS_PER_CYCLE = 1
) (
    input  logic         clk,
    input  logic         rst,
    // session inputs
    input  logic [127:0] i_key,
    input  logic [127:0] i_nonce,
    // phase 1: precompute initialization (run this inside the previous shadow)
    input  logic         i_pre_start,
    output logic         o_pre_done,
    // phase 2: the record itself
    input  logic [127:0] i_data,        // little-endian: [63:0]=S0 lane, [127:64]=S1
    input  logic         i_data_valid,
    input  logic         i_data_last,
    input  logic [4:0]   i_bytes,       // valid bytes in the last block (0..16)
    output logic         o_ready,
    output logic [127:0] o_ct,
    output logic         o_ct_valid,
    output logic [127:0] o_tag,
    output logic         o_tag_valid
);
    localparam int RPC = (ROUNDS_PER_CYCLE < 1) ? 1 :
                         (ROUNDS_PER_CYCLE > 12) ? 12 : ROUNDS_PER_CYCLE;
    localparam logic [63:0] IV   = 64'h00001000808c0001;
    localparam logic [63:0] DSEP = 64'h8000000000000000;

    // p12 runs schedule rounds 0..11; p8 is the same schedule started at round 4.
    function automatic logic [7:0] rc_of(input int unsigned r);
        case (r)
            0: rc_of = 8'hf0;  1: rc_of = 8'he1;  2: rc_of = 8'hd2;  3: rc_of = 8'hc3;
            4: rc_of = 8'hb4;  5: rc_of = 8'ha5;  6: rc_of = 8'h96;  7: rc_of = 8'h87;
            8: rc_of = 8'h78;  9: rc_of = 8'h69; 10: rc_of = 8'h5a; 11: rc_of = 8'h4b;
            default: rc_of = 8'h00;
        endcase
    endfunction

    function automatic logic [63:0] ror64(input logic [63:0] a, input int n);
        ror64 = (a >> n) | (a << (64 - n));
    endfunction

    function automatic logic [319:0] ascon_round(input logic [319:0] s,
                                                 input logic [7:0]   rc);
        logic [63:0] x0, x1, x2, x3, x4, t0, t1, t2, t3, t4;
        begin
            x0 = s[319:256]; x1 = s[255:192]; x2 = s[191:128];
            x3 = s[127:64];  x4 = s[63:0];
            x2 = x2 ^ {56'b0, rc};
            x0 = x0 ^ x4;  x4 = x4 ^ x3;  x2 = x2 ^ x1;
            t0 = x0 ^ (~x1 & x2);   t1 = x1 ^ (~x2 & x3);
            t2 = x2 ^ (~x3 & x4);   t3 = x3 ^ (~x4 & x0);
            t4 = x4 ^ (~x0 & x1);
            t1 = t1 ^ t0;  t0 = t0 ^ t4;  t3 = t3 ^ t2;  t2 = ~t2;
            x0 = t0 ^ ror64(t0, 19) ^ ror64(t0, 28);
            x1 = t1 ^ ror64(t1, 61) ^ ror64(t1, 39);
            x2 = t2 ^ ror64(t2,  1) ^ ror64(t2,  6);
            x3 = t3 ^ ror64(t3, 10) ^ ror64(t3, 17);
            x4 = t4 ^ ror64(t4,  7) ^ ror64(t4, 41);
            ascon_round = {x0, x1, x2, x3, x4};
        end
    endfunction

    logic [319:0] st;
    logic [3:0]   rcnt;                       // current schedule round index
    logic [127:0] key_q;
    logic [127:0] padded;                     // padded final rate (combinational temp)
    typedef enum logic [2:0] {S_IDLE, S_INIT, S_ARMED, S_ABS, S_P8, S_FIN, S_TAG} ph_t;
    ph_t ph;

    // combinational chain of RPC rounds, guarded past round 11
    logic [319:0] chain [0:RPC];
    assign chain[0] = st;
    genvar gi;
    generate
        for (gi = 0; gi < RPC; gi = gi + 1) begin : g_chain
            assign chain[gi+1] = ((rcnt + gi) < 12)
                               ? ascon_round(chain[gi], rc_of(rcnt + gi))
                               : chain[gi];
        end
    endgenerate
    wire perm_done = ((rcnt + RPC) >= 12);

    // state words, named for readability
    wire [63:0] S0 = st[319:256], S1 = st[255:192];
    wire [63:0] S2 = st[191:128], S3 = st[127:64], S4 = st[63:0];

    // rate absorption with 10* padding for a partial final block
    function automatic logic [127:0] pad_rate(input logic [127:0] rate,
                                              input logic [127:0] dat,
                                              input logic [4:0]   nb);
        logic [127:0] m, p;
        begin
            m = (nb >= 5'd16) ? {128{1'b1}} : ((128'd1 << (8*nb)) - 128'd1);
            p = (nb >= 5'd16) ? 128'd0 : (128'd1 << (8*nb));
            pad_rate = rate ^ (dat & m) ^ p;
        end
    endfunction

    assign o_ready    = (ph == S_ABS);
    assign o_pre_done = (ph == S_ARMED);

    always_ff @(posedge clk) begin
        if (rst) begin
            ph <= S_IDLE; st <= '0; rcnt <= '0; key_q <= '0;
            o_ct <= '0; o_ct_valid <= 1'b0; o_tag <= '0; o_tag_valid <= 1'b0;
        end else begin
            o_ct_valid <= 1'b0; o_tag_valid <= 1'b0;
            case (ph)
            // ---- precompute: initialization from key and nonce only ----
            S_IDLE: if (i_pre_start) begin
                key_q <= i_key;
                st    <= {IV, i_key[63:0], i_key[127:64], i_nonce[63:0], i_nonce[127:64]};
                rcnt  <= '0;
                ph    <= S_INIT;
            end
            S_INIT: begin
                st   <= chain[RPC];
                rcnt <= rcnt + RPC[3:0];
                if (perm_done) begin
                    // key addition ending init, then domain separation (empty AD)
                    st <= {chain[RPC][319:128],
                           chain[RPC][127:64]  ^ key_q[63:0],
                           chain[RPC][63:0]    ^ key_q[127:64] ^ DSEP};
                    rcnt <= 4'd4;                    // data blocks use p8
                    ph   <= S_ARMED;
                end
            end
            // ---- parked: initialization done, waiting for the record ----
            S_ARMED: if (i_data_valid) ph <= S_ABS;
            // ---- absorb record blocks, emitting ciphertext ----
            S_ABS: if (i_data_valid) begin
                o_ct       <= ({S1, S0} ^ i_data);   // caller keeps i_bytes of the last
                o_ct_valid <= 1'b1;
                if (i_data_last) begin
                    padded = pad_rate({S1, S0}, i_data, i_bytes);
                    // pad the final rate AND apply the key addition that starts
                    // finalization (S2,S3), a different offset from the other two
                    st   <= {padded[63:0], padded[127:64],
                             S2 ^ key_q[63:0], S3 ^ key_q[127:64], S4};
                    rcnt <= '0;                      // finalization uses p12
                    ph   <= S_FIN;                   // no permutation after the last block
                end else begin
                    st   <= {i_data[63:0] ^ S0, i_data[127:64] ^ S1, st[191:0]};
                    rcnt <= 4'd4;                    // between blocks: p8
                    ph   <= S_P8;
                end
            end
            // ---- p8 between record blocks ----
            S_P8: begin
                st   <= chain[RPC];
                rcnt <= rcnt + RPC[3:0];
                if (perm_done) begin
                    st   <= chain[RPC];
                    rcnt <= 4'd4;
                    ph   <= S_ABS;
                end
            end
            // ---- finalization ----
            S_FIN: begin
                st   <= chain[RPC];
                rcnt <= rcnt + RPC[3:0];
                if (perm_done) begin
                    st <= chain[RPC];
                    ph <= S_TAG;
                end
            end
            S_TAG: begin
                o_tag       <= {chain[0][63:0] ^ key_q[127:64],
                                chain[0][127:64] ^ key_q[63:0]};
                o_tag_valid <= 1'b1;
                ph          <= S_IDLE;
            end
            default: ph <= S_IDLE;
            endcase
        end
    end
endmodule
