/*
 * ascon_xof.sv -- Ascon-XOF128 keystream generator (NIST SP 800-232).
 * --------------------------------------------------------------------------
 * Expands a public 128-bit seed into an arbitrarily long 64-bit-per-beat stream.
 * In Shadow-LWE this stream is the LWE mask a[0..N-1], generated on chip so the
 * ciphertext carries only the seed instead of the full mask vector.
 *
 * Sponge (SP 800-232 Sec. 5.2): rate 64, capacity 256, p12 throughout.
 *   init    : state = p12(IV || 0^256), hardcoded below as the Table-12 constant
 *   absorb  : seed is two 64-bit little-endian blocks, then a 10* padding block
 *   squeeze : permute, then emit S0; repeat
 *
 * ROUNDS_PER_CYCLE (1..12) is the area/throughput knob: the 12-round permutation
 * takes ceil(12/ROUNDS_PER_CYCLE) cycles, so a keystream word costs that many
 * cycles. This is the parameter swept to find where mask expansion fits inside
 * the inference shadow.
 *
 * Verified bit-exact against model/ascon.py, which reproduces the official
 * Ascon-XOF128 and Ascon-Hash256 known-answer tests.
 */
`timescale 1ns/1ps
module ascon_xof #(
    parameter int ROUNDS_PER_CYCLE = 1
) (
    input  logic         clk,
    input  logic         rst,
    input  logic [127:0] i_seed,     // public per-record seed
    input  logic         i_start,    // pulse to (re)initialize with i_seed
    output logic         o_busy,
    output logic [63:0]  o_word,     // squeezed keystream word
    output logic         o_valid,
    input  logic         i_ready     // consumer back-pressure
);
    localparam int RPC = (ROUNDS_PER_CYCLE < 1) ? 1 :
                         (ROUNDS_PER_CYCLE > 12) ? 12 : ROUNDS_PER_CYCLE;

    // p12 round constants (SP 800-232 Table 5, last 12 entries)
    function automatic logic [7:0] rc_of(input int unsigned r);
        case (r)
            0: rc_of = 8'hf0;  1: rc_of = 8'he1;  2: rc_of = 8'hd2;  3: rc_of = 8'hc3;
            4: rc_of = 8'hb4;  5: rc_of = 8'ha5;  6: rc_of = 8'h96;  7: rc_of = 8'h87;
            8: rc_of = 8'h78;  9: rc_of = 8'h69; 10: rc_of = 8'h5a; 11: rc_of = 8'h4b;
            default: rc_of = 8'h00;
        endcase
    endfunction

    // state after p12(IV_XOF128 || 0^256): SP 800-232 Table 12, so the
    // initialization permutation never has to run at reset.
    localparam logic [319:0] INIT_STATE = {
        64'hda82ce768d9447eb, 64'hcc7ce6c75f1ef969, 64'he7508fd780085631,
        64'h0ee0ea53416b58cc, 64'he0547524db6f0bde };

    function automatic logic [63:0] ror64(input logic [63:0] a, input int n);
        ror64 = (a >> n) | (a << (64 - n));
    endfunction

    // one Ascon-p round: constant addition, 5-bit bitsliced S-box, linear diffusion
    function automatic logic [319:0] ascon_round(input logic [319:0] s,
                                                 input logic [7:0]   rc);
        logic [63:0] x0, x1, x2, x3, x4, t0, t1, t2, t3, t4;
        begin
            x0 = s[319:256]; x1 = s[255:192]; x2 = s[191:128];
            x3 = s[127:64];  x4 = s[63:0];
            x2 = x2 ^ {56'b0, rc};                       // pC
            x0 = x0 ^ x4;  x4 = x4 ^ x3;  x2 = x2 ^ x1;  // pS
            t0 = x0 ^ (~x1 & x2);
            t1 = x1 ^ (~x2 & x3);
            t2 = x2 ^ (~x3 & x4);
            t3 = x3 ^ (~x4 & x0);
            t4 = x4 ^ (~x0 & x1);
            t1 = t1 ^ t0;  t0 = t0 ^ t4;  t3 = t3 ^ t2;  t2 = ~t2;
            x0 = t0 ^ ror64(t0, 19) ^ ror64(t0, 28);     // pL
            x1 = t1 ^ ror64(t1, 61) ^ ror64(t1, 39);
            x2 = t2 ^ ror64(t2,  1) ^ ror64(t2,  6);
            x3 = t3 ^ ror64(t3, 10) ^ ror64(t3, 17);
            x4 = t4 ^ ror64(t4,  7) ^ ror64(t4, 41);
            ascon_round = {x0, x1, x2, x3, x4};
        end
    endfunction

    logic [319:0] st;
    logic [127:0] seed_q;                   // latched at start, stable through absorb
    logic [3:0]   rcnt;                     // rounds completed in this permutation
    typedef enum logic [2:0] {S_IDLE, S_ABS0, S_ABS1, S_PAD, S_PERM, S_EMIT} st_t;
    st_t phase;
    logic squeezing;

    // combinational chain of RPC rounds, guarded past round 11.
    // Built with continuous assigns in a generate block: indexing an unpacked
    // array of vectors inside always_comb is not handled reliably by iverilog.
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

    assign o_busy  = (phase != S_IDLE);
    assign o_word  = st[319:256];           // S0 is the rate lane
    assign o_valid = (phase == S_EMIT);

    always_ff @(posedge clk) begin
        if (rst) begin
            phase <= S_IDLE; st <= '0; rcnt <= '0; squeezing <= 1'b0; seed_q <= '0;
        end else if (i_start) begin
            // restart from any phase: absorb the first seed block into the
            // pre-permuted initial state
            seed_q    <= i_seed;
            st        <= {INIT_STATE[319:256] ^ i_seed[63:0], INIT_STATE[255:0]};
            rcnt      <= '0;
            squeezing <= 1'b0;
            phase     <= S_ABS0;
        end else begin
            case (phase)
            S_IDLE: ;   // idle until i_start
            // ---- permute after absorbing block 0 ----
            S_ABS0: begin
                st   <= chain[RPC];
                rcnt <= rcnt + RPC[3:0];
                if (perm_done) begin
                    // absorb block 1 (high half of the seed) as we leave
                    st    <= {chain[RPC][319:256] ^ seed_q[127:64], chain[RPC][255:0]};
                    rcnt  <= '0;
                    phase <= S_ABS1;
                end
            end
            // ---- permute after absorbing block 1 ----
            S_ABS1: begin
                st   <= chain[RPC];
                rcnt <= rcnt + RPC[3:0];
                if (perm_done) begin
                    st    <= chain[RPC];
                    rcnt  <= '0;
                    phase <= S_PAD;
                end
            end
            // ---- final (padding) block is absorbed WITHOUT a permutation ----
            S_PAD: begin
                st        <= {st[319:256] ^ 64'h1, st[255:0]};
                rcnt      <= '0;
                squeezing <= 1'b1;
                phase     <= S_PERM;
            end
            // ---- squeeze: permute, then present S0 ----
            S_PERM: begin
                st   <= chain[RPC];
                rcnt <= rcnt + RPC[3:0];
                if (perm_done) begin
                    st    <= chain[RPC];
                    rcnt  <= '0;
                    phase <= S_EMIT;
                end
            end
            S_EMIT: if (i_ready) phase <= S_PERM;   // next word
            default: phase <= S_IDLE;
            endcase
        end
    end
endmodule
