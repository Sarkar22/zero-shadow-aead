// Parameter-fixed wrapper for ASIC sign-off at the paper's recommended point.
`timescale 1ns/1ps
module ascon_aead_top (
    input  logic clk, input logic rst,
    input  logic [127:0] i_key, input logic [127:0] i_nonce,
    input  logic i_pre_start, output logic o_pre_done,
    input  logic [127:0] i_data, input logic i_data_valid, input logic i_data_last,
    input  logic [4:0] i_bytes, output logic o_ready,
    output logic [127:0] o_ct, output logic o_ct_valid,
    output logic [127:0] o_tag, output logic o_tag_valid);
  ascon_aead #(.ROUNDS_PER_CYCLE(2)) u_dut (
    .clk(clk), .rst(rst), .i_key(i_key), .i_nonce(i_nonce),
    .i_pre_start(i_pre_start), .o_pre_done(o_pre_done), .i_data(i_data),
    .i_data_valid(i_data_valid), .i_data_last(i_data_last), .i_bytes(i_bytes),
    .o_ready(o_ready), .o_ct(o_ct), .o_ct_valid(o_ct_valid),
    .o_tag(o_tag), .o_tag_valid(o_tag_valid));
endmodule
