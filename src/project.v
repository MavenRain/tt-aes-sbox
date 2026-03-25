// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Onyeka Obi
//
// Formally-verified, constant-time AES S-Box (SubBytes / InvSubBytes)
// Direct combinational implementation from FIPS 197 tables.
//
// The synthesis tool optimizes the 256-entry tables into a network of
// LUTs/gates. This is inherently constant-time in hardware: every input
// takes the same path through the same logic, with no data-dependent
// control flow, memory access patterns, or timing variation.
//
// Interface:
//   ui_in[7:0]  = input byte
//   uo_out[7:0] = substituted output byte
//   uio_in[0]   = input valid
//   uio_in[1]   = mode: 0 = encrypt (SubBytes), 1 = decrypt (InvSubBytes)
//   uio_out[0]  = output valid (one cycle latency)
//   uio_out[1]  = mode echo
//
// Properties:
//   - Purely combinational datapath (registered I/O for clean timing)
//   - Constant-time: no data-dependent control flow or mux selects
//   - Exhaustively verifiable: 256 input/output pairs per mode

`default_nettype none

module tt_um_aes_sbox (
    input  wire [7:0] ui_in,    // Dedicated inputs
    output wire [7:0] uo_out,   // Dedicated outputs
    input  wire [7:0] uio_in,   // IOs: Input path
    output wire [7:0] uio_out,  // IOs: Output path
    output wire [7:0] uio_oe,   // IOs: Enable path (active high: 0=input,1=output)
    input  wire       ena,      // always 1 when the design is powered
    input  wire       clk,      // clock
    input  wire       rst_n     // reset_n - low to reset
);

    // ---------------------------------------------------------------
    // I/O mapping
    // ---------------------------------------------------------------
    wire [7:0] sbox_in;
    wire       in_valid;
    wire       mode;         // 0 = encrypt, 1 = decrypt

    assign sbox_in  = ui_in;
    assign in_valid = uio_in[0];
    assign mode     = uio_in[1];

    // Bidirectional I/O: bits [1:0] are outputs, rest are inputs
    assign uio_oe = 8'b0000_0011;

    // ---------------------------------------------------------------
    // AES Forward S-Box (SubBytes) - FIPS 197, Figure 7
    // ---------------------------------------------------------------
    function automatic [7:0] sbox_fwd;
        input [7:0] in;
        begin
            case (in)
                8'h00: sbox_fwd = 8'h63;  8'h01: sbox_fwd = 8'h7C;  8'h02: sbox_fwd = 8'h77;  8'h03: sbox_fwd = 8'h7B;
                8'h04: sbox_fwd = 8'hF2;  8'h05: sbox_fwd = 8'h6B;  8'h06: sbox_fwd = 8'h6F;  8'h07: sbox_fwd = 8'hC5;
                8'h08: sbox_fwd = 8'h30;  8'h09: sbox_fwd = 8'h01;  8'h0A: sbox_fwd = 8'h67;  8'h0B: sbox_fwd = 8'h2B;
                8'h0C: sbox_fwd = 8'hFE;  8'h0D: sbox_fwd = 8'hD7;  8'h0E: sbox_fwd = 8'hAB;  8'h0F: sbox_fwd = 8'h76;
                8'h10: sbox_fwd = 8'hCA;  8'h11: sbox_fwd = 8'h82;  8'h12: sbox_fwd = 8'hC9;  8'h13: sbox_fwd = 8'h7D;
                8'h14: sbox_fwd = 8'hFA;  8'h15: sbox_fwd = 8'h59;  8'h16: sbox_fwd = 8'h47;  8'h17: sbox_fwd = 8'hF0;
                8'h18: sbox_fwd = 8'hAD;  8'h19: sbox_fwd = 8'hD4;  8'h1A: sbox_fwd = 8'hA2;  8'h1B: sbox_fwd = 8'hAF;
                8'h1C: sbox_fwd = 8'h9C;  8'h1D: sbox_fwd = 8'hA4;  8'h1E: sbox_fwd = 8'h72;  8'h1F: sbox_fwd = 8'hC0;
                8'h20: sbox_fwd = 8'hB7;  8'h21: sbox_fwd = 8'hFD;  8'h22: sbox_fwd = 8'h93;  8'h23: sbox_fwd = 8'h26;
                8'h24: sbox_fwd = 8'h36;  8'h25: sbox_fwd = 8'h3F;  8'h26: sbox_fwd = 8'hF7;  8'h27: sbox_fwd = 8'hCC;
                8'h28: sbox_fwd = 8'h34;  8'h29: sbox_fwd = 8'hA5;  8'h2A: sbox_fwd = 8'hE5;  8'h2B: sbox_fwd = 8'hF1;
                8'h2C: sbox_fwd = 8'h71;  8'h2D: sbox_fwd = 8'hD8;  8'h2E: sbox_fwd = 8'h31;  8'h2F: sbox_fwd = 8'h15;
                8'h30: sbox_fwd = 8'h04;  8'h31: sbox_fwd = 8'hC7;  8'h32: sbox_fwd = 8'h23;  8'h33: sbox_fwd = 8'hC3;
                8'h34: sbox_fwd = 8'h18;  8'h35: sbox_fwd = 8'h96;  8'h36: sbox_fwd = 8'h05;  8'h37: sbox_fwd = 8'h9A;
                8'h38: sbox_fwd = 8'h07;  8'h39: sbox_fwd = 8'h12;  8'h3A: sbox_fwd = 8'h80;  8'h3B: sbox_fwd = 8'hE2;
                8'h3C: sbox_fwd = 8'hEB;  8'h3D: sbox_fwd = 8'h27;  8'h3E: sbox_fwd = 8'hB2;  8'h3F: sbox_fwd = 8'h75;
                8'h40: sbox_fwd = 8'h09;  8'h41: sbox_fwd = 8'h83;  8'h42: sbox_fwd = 8'h2C;  8'h43: sbox_fwd = 8'h1A;
                8'h44: sbox_fwd = 8'h1B;  8'h45: sbox_fwd = 8'h6E;  8'h46: sbox_fwd = 8'h5A;  8'h47: sbox_fwd = 8'hA0;
                8'h48: sbox_fwd = 8'h52;  8'h49: sbox_fwd = 8'h3B;  8'h4A: sbox_fwd = 8'hD6;  8'h4B: sbox_fwd = 8'hB3;
                8'h4C: sbox_fwd = 8'h29;  8'h4D: sbox_fwd = 8'hE3;  8'h4E: sbox_fwd = 8'h2F;  8'h4F: sbox_fwd = 8'h84;
                8'h50: sbox_fwd = 8'h53;  8'h51: sbox_fwd = 8'hD1;  8'h52: sbox_fwd = 8'h00;  8'h53: sbox_fwd = 8'hED;
                8'h54: sbox_fwd = 8'h20;  8'h55: sbox_fwd = 8'hFC;  8'h56: sbox_fwd = 8'hB1;  8'h57: sbox_fwd = 8'h5B;
                8'h58: sbox_fwd = 8'h6A;  8'h59: sbox_fwd = 8'hCB;  8'h5A: sbox_fwd = 8'hBE;  8'h5B: sbox_fwd = 8'h39;
                8'h5C: sbox_fwd = 8'h4A;  8'h5D: sbox_fwd = 8'h4C;  8'h5E: sbox_fwd = 8'h58;  8'h5F: sbox_fwd = 8'hCF;
                8'h60: sbox_fwd = 8'hD0;  8'h61: sbox_fwd = 8'hEF;  8'h62: sbox_fwd = 8'hAA;  8'h63: sbox_fwd = 8'hFB;
                8'h64: sbox_fwd = 8'h43;  8'h65: sbox_fwd = 8'h4D;  8'h66: sbox_fwd = 8'h33;  8'h67: sbox_fwd = 8'h85;
                8'h68: sbox_fwd = 8'h45;  8'h69: sbox_fwd = 8'hF9;  8'h6A: sbox_fwd = 8'h02;  8'h6B: sbox_fwd = 8'h7F;
                8'h6C: sbox_fwd = 8'h50;  8'h6D: sbox_fwd = 8'h3C;  8'h6E: sbox_fwd = 8'h9F;  8'h6F: sbox_fwd = 8'hA8;
                8'h70: sbox_fwd = 8'h51;  8'h71: sbox_fwd = 8'hA3;  8'h72: sbox_fwd = 8'h40;  8'h73: sbox_fwd = 8'h8F;
                8'h74: sbox_fwd = 8'h92;  8'h75: sbox_fwd = 8'h9D;  8'h76: sbox_fwd = 8'h38;  8'h77: sbox_fwd = 8'hF5;
                8'h78: sbox_fwd = 8'hBC;  8'h79: sbox_fwd = 8'hB6;  8'h7A: sbox_fwd = 8'hDA;  8'h7B: sbox_fwd = 8'h21;
                8'h7C: sbox_fwd = 8'h10;  8'h7D: sbox_fwd = 8'hFF;  8'h7E: sbox_fwd = 8'hF3;  8'h7F: sbox_fwd = 8'hD2;
                8'h80: sbox_fwd = 8'hCD;  8'h81: sbox_fwd = 8'h0C;  8'h82: sbox_fwd = 8'h13;  8'h83: sbox_fwd = 8'hEC;
                8'h84: sbox_fwd = 8'h5F;  8'h85: sbox_fwd = 8'h97;  8'h86: sbox_fwd = 8'h44;  8'h87: sbox_fwd = 8'h17;
                8'h88: sbox_fwd = 8'hC4;  8'h89: sbox_fwd = 8'hA7;  8'h8A: sbox_fwd = 8'h7E;  8'h8B: sbox_fwd = 8'h3D;
                8'h8C: sbox_fwd = 8'h64;  8'h8D: sbox_fwd = 8'h5D;  8'h8E: sbox_fwd = 8'h19;  8'h8F: sbox_fwd = 8'h73;
                8'h90: sbox_fwd = 8'h60;  8'h91: sbox_fwd = 8'h81;  8'h92: sbox_fwd = 8'h4F;  8'h93: sbox_fwd = 8'hDC;
                8'h94: sbox_fwd = 8'h22;  8'h95: sbox_fwd = 8'h2A;  8'h96: sbox_fwd = 8'h90;  8'h97: sbox_fwd = 8'h88;
                8'h98: sbox_fwd = 8'h46;  8'h99: sbox_fwd = 8'hEE;  8'h9A: sbox_fwd = 8'hB8;  8'h9B: sbox_fwd = 8'h14;
                8'h9C: sbox_fwd = 8'hDE;  8'h9D: sbox_fwd = 8'h5E;  8'h9E: sbox_fwd = 8'h0B;  8'h9F: sbox_fwd = 8'hDB;
                8'hA0: sbox_fwd = 8'hE0;  8'hA1: sbox_fwd = 8'h32;  8'hA2: sbox_fwd = 8'h3A;  8'hA3: sbox_fwd = 8'h0A;
                8'hA4: sbox_fwd = 8'h49;  8'hA5: sbox_fwd = 8'h06;  8'hA6: sbox_fwd = 8'h24;  8'hA7: sbox_fwd = 8'h5C;
                8'hA8: sbox_fwd = 8'hC2;  8'hA9: sbox_fwd = 8'hD3;  8'hAA: sbox_fwd = 8'hAC;  8'hAB: sbox_fwd = 8'h62;
                8'hAC: sbox_fwd = 8'h91;  8'hAD: sbox_fwd = 8'h95;  8'hAE: sbox_fwd = 8'hE4;  8'hAF: sbox_fwd = 8'h79;
                8'hB0: sbox_fwd = 8'hE7;  8'hB1: sbox_fwd = 8'hC8;  8'hB2: sbox_fwd = 8'h37;  8'hB3: sbox_fwd = 8'h6D;
                8'hB4: sbox_fwd = 8'h8D;  8'hB5: sbox_fwd = 8'hD5;  8'hB6: sbox_fwd = 8'h4E;  8'hB7: sbox_fwd = 8'hA9;
                8'hB8: sbox_fwd = 8'h6C;  8'hB9: sbox_fwd = 8'h56;  8'hBA: sbox_fwd = 8'hF4;  8'hBB: sbox_fwd = 8'hEA;
                8'hBC: sbox_fwd = 8'h65;  8'hBD: sbox_fwd = 8'h7A;  8'hBE: sbox_fwd = 8'hAE;  8'hBF: sbox_fwd = 8'h08;
                8'hC0: sbox_fwd = 8'hBA;  8'hC1: sbox_fwd = 8'h78;  8'hC2: sbox_fwd = 8'h25;  8'hC3: sbox_fwd = 8'h2E;
                8'hC4: sbox_fwd = 8'h1C;  8'hC5: sbox_fwd = 8'hA6;  8'hC6: sbox_fwd = 8'hB4;  8'hC7: sbox_fwd = 8'hC6;
                8'hC8: sbox_fwd = 8'hE8;  8'hC9: sbox_fwd = 8'hDD;  8'hCA: sbox_fwd = 8'h74;  8'hCB: sbox_fwd = 8'h1F;
                8'hCC: sbox_fwd = 8'h4B;  8'hCD: sbox_fwd = 8'hBD;  8'hCE: sbox_fwd = 8'h8B;  8'hCF: sbox_fwd = 8'h8A;
                8'hD0: sbox_fwd = 8'h70;  8'hD1: sbox_fwd = 8'h3E;  8'hD2: sbox_fwd = 8'hB5;  8'hD3: sbox_fwd = 8'h66;
                8'hD4: sbox_fwd = 8'h48;  8'hD5: sbox_fwd = 8'h03;  8'hD6: sbox_fwd = 8'hF6;  8'hD7: sbox_fwd = 8'h0E;
                8'hD8: sbox_fwd = 8'h61;  8'hD9: sbox_fwd = 8'h35;  8'hDA: sbox_fwd = 8'h57;  8'hDB: sbox_fwd = 8'hB9;
                8'hDC: sbox_fwd = 8'h86;  8'hDD: sbox_fwd = 8'hC1;  8'hDE: sbox_fwd = 8'h1D;  8'hDF: sbox_fwd = 8'h9E;
                8'hE0: sbox_fwd = 8'hE1;  8'hE1: sbox_fwd = 8'hF8;  8'hE2: sbox_fwd = 8'h98;  8'hE3: sbox_fwd = 8'h11;
                8'hE4: sbox_fwd = 8'h69;  8'hE5: sbox_fwd = 8'hD9;  8'hE6: sbox_fwd = 8'h8E;  8'hE7: sbox_fwd = 8'h94;
                8'hE8: sbox_fwd = 8'h9B;  8'hE9: sbox_fwd = 8'h1E;  8'hEA: sbox_fwd = 8'h87;  8'hEB: sbox_fwd = 8'hE9;
                8'hEC: sbox_fwd = 8'hCE;  8'hED: sbox_fwd = 8'h55;  8'hEE: sbox_fwd = 8'h28;  8'hEF: sbox_fwd = 8'hDF;
                8'hF0: sbox_fwd = 8'h8C;  8'hF1: sbox_fwd = 8'hA1;  8'hF2: sbox_fwd = 8'h89;  8'hF3: sbox_fwd = 8'h0D;
                8'hF4: sbox_fwd = 8'hBF;  8'hF5: sbox_fwd = 8'hE6;  8'hF6: sbox_fwd = 8'h42;  8'hF7: sbox_fwd = 8'h68;
                8'hF8: sbox_fwd = 8'h41;  8'hF9: sbox_fwd = 8'h99;  8'hFA: sbox_fwd = 8'h2D;  8'hFB: sbox_fwd = 8'h0F;
                8'hFC: sbox_fwd = 8'hB0;  8'hFD: sbox_fwd = 8'h54;  8'hFE: sbox_fwd = 8'hBB;  8'hFF: sbox_fwd = 8'h16;
            endcase
        end
    endfunction

    // ---------------------------------------------------------------
    // AES Inverse S-Box (InvSubBytes) - FIPS 197, Figure 14
    // ---------------------------------------------------------------
    function automatic [7:0] sbox_inv;
        input [7:0] in;
        begin
            case (in)
                8'h00: sbox_inv = 8'h52;  8'h01: sbox_inv = 8'h09;  8'h02: sbox_inv = 8'h6A;  8'h03: sbox_inv = 8'hD5;
                8'h04: sbox_inv = 8'h30;  8'h05: sbox_inv = 8'h36;  8'h06: sbox_inv = 8'hA5;  8'h07: sbox_inv = 8'h38;
                8'h08: sbox_inv = 8'hBF;  8'h09: sbox_inv = 8'h40;  8'h0A: sbox_inv = 8'hA3;  8'h0B: sbox_inv = 8'h9E;
                8'h0C: sbox_inv = 8'h81;  8'h0D: sbox_inv = 8'hF3;  8'h0E: sbox_inv = 8'hD7;  8'h0F: sbox_inv = 8'hFB;
                8'h10: sbox_inv = 8'h7C;  8'h11: sbox_inv = 8'hE3;  8'h12: sbox_inv = 8'h39;  8'h13: sbox_inv = 8'h82;
                8'h14: sbox_inv = 8'h9B;  8'h15: sbox_inv = 8'h2F;  8'h16: sbox_inv = 8'hFF;  8'h17: sbox_inv = 8'h87;
                8'h18: sbox_inv = 8'h34;  8'h19: sbox_inv = 8'h8E;  8'h1A: sbox_inv = 8'h43;  8'h1B: sbox_inv = 8'h44;
                8'h1C: sbox_inv = 8'hC4;  8'h1D: sbox_inv = 8'hDE;  8'h1E: sbox_inv = 8'hE9;  8'h1F: sbox_inv = 8'hCB;
                8'h20: sbox_inv = 8'h54;  8'h21: sbox_inv = 8'h7B;  8'h22: sbox_inv = 8'h94;  8'h23: sbox_inv = 8'h32;
                8'h24: sbox_inv = 8'hA6;  8'h25: sbox_inv = 8'hC2;  8'h26: sbox_inv = 8'h23;  8'h27: sbox_inv = 8'h3D;
                8'h28: sbox_inv = 8'hEE;  8'h29: sbox_inv = 8'h4C;  8'h2A: sbox_inv = 8'h95;  8'h2B: sbox_inv = 8'h0B;
                8'h2C: sbox_inv = 8'h42;  8'h2D: sbox_inv = 8'hFA;  8'h2E: sbox_inv = 8'hC3;  8'h2F: sbox_inv = 8'h4E;
                8'h30: sbox_inv = 8'h08;  8'h31: sbox_inv = 8'h2E;  8'h32: sbox_inv = 8'hA1;  8'h33: sbox_inv = 8'h66;
                8'h34: sbox_inv = 8'h28;  8'h35: sbox_inv = 8'hD9;  8'h36: sbox_inv = 8'h24;  8'h37: sbox_inv = 8'hB2;
                8'h38: sbox_inv = 8'h76;  8'h39: sbox_inv = 8'h5B;  8'h3A: sbox_inv = 8'hA2;  8'h3B: sbox_inv = 8'h49;
                8'h3C: sbox_inv = 8'h6D;  8'h3D: sbox_inv = 8'h8B;  8'h3E: sbox_inv = 8'hD1;  8'h3F: sbox_inv = 8'h25;
                8'h40: sbox_inv = 8'h72;  8'h41: sbox_inv = 8'hF8;  8'h42: sbox_inv = 8'hF6;  8'h43: sbox_inv = 8'h64;
                8'h44: sbox_inv = 8'h86;  8'h45: sbox_inv = 8'h68;  8'h46: sbox_inv = 8'h98;  8'h47: sbox_inv = 8'h16;
                8'h48: sbox_inv = 8'hD4;  8'h49: sbox_inv = 8'hA4;  8'h4A: sbox_inv = 8'h5C;  8'h4B: sbox_inv = 8'hCC;
                8'h4C: sbox_inv = 8'h5D;  8'h4D: sbox_inv = 8'h65;  8'h4E: sbox_inv = 8'hB6;  8'h4F: sbox_inv = 8'h92;
                8'h50: sbox_inv = 8'h6C;  8'h51: sbox_inv = 8'h70;  8'h52: sbox_inv = 8'h48;  8'h53: sbox_inv = 8'h50;
                8'h54: sbox_inv = 8'hFD;  8'h55: sbox_inv = 8'hED;  8'h56: sbox_inv = 8'hB9;  8'h57: sbox_inv = 8'hDA;
                8'h58: sbox_inv = 8'h5E;  8'h59: sbox_inv = 8'h15;  8'h5A: sbox_inv = 8'h46;  8'h5B: sbox_inv = 8'h57;
                8'h5C: sbox_inv = 8'hA7;  8'h5D: sbox_inv = 8'h8D;  8'h5E: sbox_inv = 8'h9D;  8'h5F: sbox_inv = 8'h84;
                8'h60: sbox_inv = 8'h90;  8'h61: sbox_inv = 8'hD8;  8'h62: sbox_inv = 8'hAB;  8'h63: sbox_inv = 8'h00;
                8'h64: sbox_inv = 8'h8C;  8'h65: sbox_inv = 8'hBC;  8'h66: sbox_inv = 8'hD3;  8'h67: sbox_inv = 8'h0A;
                8'h68: sbox_inv = 8'hF7;  8'h69: sbox_inv = 8'hE4;  8'h6A: sbox_inv = 8'h58;  8'h6B: sbox_inv = 8'h05;
                8'h6C: sbox_inv = 8'hB8;  8'h6D: sbox_inv = 8'hB3;  8'h6E: sbox_inv = 8'h45;  8'h6F: sbox_inv = 8'h06;
                8'h70: sbox_inv = 8'hD0;  8'h71: sbox_inv = 8'h2C;  8'h72: sbox_inv = 8'h1E;  8'h73: sbox_inv = 8'h8F;
                8'h74: sbox_inv = 8'hCA;  8'h75: sbox_inv = 8'h3F;  8'h76: sbox_inv = 8'h0F;  8'h77: sbox_inv = 8'h02;
                8'h78: sbox_inv = 8'hC1;  8'h79: sbox_inv = 8'hAF;  8'h7A: sbox_inv = 8'hBD;  8'h7B: sbox_inv = 8'h03;
                8'h7C: sbox_inv = 8'h01;  8'h7D: sbox_inv = 8'h13;  8'h7E: sbox_inv = 8'h8A;  8'h7F: sbox_inv = 8'h6B;
                8'h80: sbox_inv = 8'h3A;  8'h81: sbox_inv = 8'h91;  8'h82: sbox_inv = 8'h11;  8'h83: sbox_inv = 8'h41;
                8'h84: sbox_inv = 8'h4F;  8'h85: sbox_inv = 8'h67;  8'h86: sbox_inv = 8'hDC;  8'h87: sbox_inv = 8'hEA;
                8'h88: sbox_inv = 8'h97;  8'h89: sbox_inv = 8'hF2;  8'h8A: sbox_inv = 8'hCF;  8'h8B: sbox_inv = 8'hCE;
                8'h8C: sbox_inv = 8'hF0;  8'h8D: sbox_inv = 8'hB4;  8'h8E: sbox_inv = 8'hE6;  8'h8F: sbox_inv = 8'h73;
                8'h90: sbox_inv = 8'h96;  8'h91: sbox_inv = 8'hAC;  8'h92: sbox_inv = 8'h74;  8'h93: sbox_inv = 8'h22;
                8'h94: sbox_inv = 8'hE7;  8'h95: sbox_inv = 8'hAD;  8'h96: sbox_inv = 8'h35;  8'h97: sbox_inv = 8'h85;
                8'h98: sbox_inv = 8'hE2;  8'h99: sbox_inv = 8'hF9;  8'h9A: sbox_inv = 8'h37;  8'h9B: sbox_inv = 8'hE8;
                8'h9C: sbox_inv = 8'h1C;  8'h9D: sbox_inv = 8'h75;  8'h9E: sbox_inv = 8'hDF;  8'h9F: sbox_inv = 8'h6E;
                8'hA0: sbox_inv = 8'h47;  8'hA1: sbox_inv = 8'hF1;  8'hA2: sbox_inv = 8'h1A;  8'hA3: sbox_inv = 8'h71;
                8'hA4: sbox_inv = 8'h1D;  8'hA5: sbox_inv = 8'h29;  8'hA6: sbox_inv = 8'hC5;  8'hA7: sbox_inv = 8'h89;
                8'hA8: sbox_inv = 8'h6F;  8'hA9: sbox_inv = 8'hB7;  8'hAA: sbox_inv = 8'h62;  8'hAB: sbox_inv = 8'h0E;
                8'hAC: sbox_inv = 8'hAA;  8'hAD: sbox_inv = 8'h18;  8'hAE: sbox_inv = 8'hBE;  8'hAF: sbox_inv = 8'h1B;
                8'hB0: sbox_inv = 8'hFC;  8'hB1: sbox_inv = 8'h56;  8'hB2: sbox_inv = 8'h3E;  8'hB3: sbox_inv = 8'h4B;
                8'hB4: sbox_inv = 8'hC6;  8'hB5: sbox_inv = 8'hD2;  8'hB6: sbox_inv = 8'h79;  8'hB7: sbox_inv = 8'h20;
                8'hB8: sbox_inv = 8'h9A;  8'hB9: sbox_inv = 8'hDB;  8'hBA: sbox_inv = 8'hC0;  8'hBB: sbox_inv = 8'hFE;
                8'hBC: sbox_inv = 8'h78;  8'hBD: sbox_inv = 8'hCD;  8'hBE: sbox_inv = 8'h5A;  8'hBF: sbox_inv = 8'hF4;
                8'hC0: sbox_inv = 8'h1F;  8'hC1: sbox_inv = 8'hDD;  8'hC2: sbox_inv = 8'hA8;  8'hC3: sbox_inv = 8'h33;
                8'hC4: sbox_inv = 8'h88;  8'hC5: sbox_inv = 8'h07;  8'hC6: sbox_inv = 8'hC7;  8'hC7: sbox_inv = 8'h31;
                8'hC8: sbox_inv = 8'hB1;  8'hC9: sbox_inv = 8'h12;  8'hCA: sbox_inv = 8'h10;  8'hCB: sbox_inv = 8'h59;
                8'hCC: sbox_inv = 8'h27;  8'hCD: sbox_inv = 8'h80;  8'hCE: sbox_inv = 8'hEC;  8'hCF: sbox_inv = 8'h5F;
                8'hD0: sbox_inv = 8'h60;  8'hD1: sbox_inv = 8'h51;  8'hD2: sbox_inv = 8'h7F;  8'hD3: sbox_inv = 8'hA9;
                8'hD4: sbox_inv = 8'h19;  8'hD5: sbox_inv = 8'hB5;  8'hD6: sbox_inv = 8'h4A;  8'hD7: sbox_inv = 8'h0D;
                8'hD8: sbox_inv = 8'h2D;  8'hD9: sbox_inv = 8'hE5;  8'hDA: sbox_inv = 8'h7A;  8'hDB: sbox_inv = 8'h9F;
                8'hDC: sbox_inv = 8'h93;  8'hDD: sbox_inv = 8'hC9;  8'hDE: sbox_inv = 8'h9C;  8'hDF: sbox_inv = 8'hEF;
                8'hE0: sbox_inv = 8'hA0;  8'hE1: sbox_inv = 8'hE0;  8'hE2: sbox_inv = 8'h3B;  8'hE3: sbox_inv = 8'h4D;
                8'hE4: sbox_inv = 8'hAE;  8'hE5: sbox_inv = 8'h2A;  8'hE6: sbox_inv = 8'hF5;  8'hE7: sbox_inv = 8'hB0;
                8'hE8: sbox_inv = 8'hC8;  8'hE9: sbox_inv = 8'hEB;  8'hEA: sbox_inv = 8'hBB;  8'hEB: sbox_inv = 8'h3C;
                8'hEC: sbox_inv = 8'h83;  8'hED: sbox_inv = 8'h53;  8'hEE: sbox_inv = 8'h99;  8'hEF: sbox_inv = 8'h61;
                8'hF0: sbox_inv = 8'h17;  8'hF1: sbox_inv = 8'h2B;  8'hF2: sbox_inv = 8'h04;  8'hF3: sbox_inv = 8'h7E;
                8'hF4: sbox_inv = 8'hBA;  8'hF5: sbox_inv = 8'h77;  8'hF6: sbox_inv = 8'hD6;  8'hF7: sbox_inv = 8'h26;
                8'hF8: sbox_inv = 8'hE1;  8'hF9: sbox_inv = 8'h69;  8'hFA: sbox_inv = 8'h14;  8'hFB: sbox_inv = 8'h63;
                8'hFC: sbox_inv = 8'h55;  8'hFD: sbox_inv = 8'h21;  8'hFE: sbox_inv = 8'h0C;  8'hFF: sbox_inv = 8'h7D;
            endcase
        end
    endfunction

    // ---------------------------------------------------------------
    // Combinational datapath
    // Mode mux selects on CONTROL signal only (not secret data)
    // ---------------------------------------------------------------
    wire [7:0] result_fwd;
    wire [7:0] result_inv;
    wire [7:0] sbox_result;

    assign result_fwd = sbox_fwd(sbox_in);
    assign result_inv = sbox_inv(sbox_in);
    assign sbox_result = mode ? result_inv : result_fwd;

    // ---------------------------------------------------------------
    // Registered output (one cycle latency)
    // ---------------------------------------------------------------
    reg [7:0] r_result;
    reg       r_valid;
    reg       r_mode;

    always @(posedge clk) begin
        if (!rst_n) begin
            r_result <= 8'h00;
            r_valid  <= 1'b0;
            r_mode   <= 1'b0;
        end else begin
            r_result <= sbox_result;
            r_valid  <= in_valid;
            r_mode   <= mode;
        end
    end

    assign uo_out      = r_result;
    assign uio_out[0]  = r_valid;
    assign uio_out[1]  = r_mode;
    assign uio_out[7:2] = 6'b000000;

endmodule
