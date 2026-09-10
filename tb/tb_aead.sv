/*
 * tb_aead.sv -- self-checking testbench for ascon_aead.
 * Checks ciphertext and tag against the golden model (which reproduces all 1089
 * official Ascon-AEAD128 KATs), and measures the schedule split that the paper
 * claims: cycles spent in precomputable initialization versus the cycles that
 * remain visible once the record arrives.
 */
`timescale 1ns/1ps
`ifndef RPC
 `define RPC 1
`endif
module tb_aead;
    localparam int MAXB = 8;

    logic clk = 0, rst = 1;
    logic [127:0] key, nonce, data;
    logic pre_start, dvalid, dlast;
    logic [4:0] dbytes;
    wire  [127:0] ct, tag;
    wire  ct_valid, tag_valid, ready, pre_done;

    ascon_aead #(.ROUNDS_PER_CYCLE(`RPC)) dut (
        .clk(clk), .rst(rst), .i_key(key), .i_nonce(nonce),
        .i_pre_start(pre_start), .o_pre_done(pre_done),
        .i_data(data), .i_data_valid(dvalid), .i_data_last(dlast), .i_bytes(dbytes),
        .o_ready(ready), .o_ct(ct), .o_ct_valid(ct_valid),
        .o_tag(tag), .o_tag_valid(tag_valid));

    always #5 clk = ~clk;

    integer fd, n, i, k, pass = 0, fail = 0, total = 0, cyc = 0;
    integer t_pre0, t_pre1, t_dat0, t_tag;
    reg [127:0] vkey, vnon, vtag, vpt [0:MAXB-1], vct [0:MAXB-1], got [0:MAXB-1];
    reg [7:0]   vnblk, vlast;
    reg [1023:0] hdr;
    reg ok;

    always @(posedge clk) if (!rst) cyc = cyc + 1;

    task run_vector;
        begin
            // ---- phase 1: precompute (would run inside the previous inference) ----
            @(negedge clk); key = vkey; nonce = vnon; pre_start = 1'b1; t_pre0 = cyc;
            @(negedge clk); pre_start = 1'b0;
            while (pre_done !== 1'b1) @(negedge clk);
            t_pre1 = cyc;
            // ---- phase 2: the record (visible latency starts here) ----
            t_dat0 = cyc;
            for (i = 0; i < vnblk; i = i + 1) begin
                data   = vpt[i];
                dlast  = (i == vnblk - 1);
                dbytes = dlast ? vlast[4:0] : 5'd16;
                dvalid = 1'b1;
                @(negedge clk);
                while (ready !== 1'b1) @(negedge clk);   // held until accepted
                @(negedge clk);
                dvalid = 1'b0;
                if (ct_valid) got[i] = ct;
                else begin while (ct_valid !== 1'b1) @(negedge clk); got[i] = ct; end
            end
            while (tag_valid !== 1'b1) @(negedge clk);
            t_tag = cyc;
            // ---- compare ----
            ok = (tag === vtag);
            for (k = 0; k < vnblk; k = k + 1) begin
                if (k == vnblk - 1 && vlast < 16) begin
                    if (vlast > 0)
                        ok = ok && ((got[k] & ((128'd1 << (8*vlast)) - 1))
                                 === (vct[k] & ((128'd1 << (8*vlast)) - 1)));
                end else if (got[k] !== vct[k]) ok = 1'b0;
            end
            total = total + 1;
            if (ok) pass = pass + 1;
            else begin
                fail = fail + 1;
                $display("  MISMATCH nblk=%0d last=%0d: tag exp %032h got %032h",
                         vnblk, vlast, vtag, tag);
            end
            $display("    nblk=%0d last=%2d bytes | precompute %0d cyc | visible %0d cyc",
                     vnblk, vlast, t_pre1 - t_pre0, t_tag - t_dat0);
            @(negedge clk);
        end
    endtask

    initial begin
        pre_start = 0; dvalid = 0; dlast = 0; dbytes = 0;
        repeat (4) @(negedge clk); rst = 0;
        fd = $fopen("../tb/aead_vectors.hex", "r");
        if (fd == 0) begin $display("ERROR: no aead_vectors.hex"); $finish; end
        n = $fgets(hdr, fd);
        while (!$feof(fd)) begin
            n = $fscanf(fd, " %h %h %h %h", vkey, vnon, vnblk, vlast);
            if (n == 4) begin
                for (i = 0; i < vnblk; i = i + 1) n = $fscanf(fd, " %h", vpt[i]);
                for (i = 0; i < vnblk; i = i + 1) n = $fscanf(fd, " %h", vct[i]);
                n = $fscanf(fd, " %h", vtag);
                run_vector;
            end
        end
        $fclose(fd);
        $display("------------------------------------------------------------");
        $display("ASCON-AEAD128 TB (ROUNDS_PER_CYCLE=%0d): %0d/%0d exact, %0d mismatch",
                 `RPC, pass, total, fail);
        if (fail == 0 && total > 0) $display("RESULT: PASS");
        else                        $display("RESULT: FAIL");
        $finish;
    end
endmodule
