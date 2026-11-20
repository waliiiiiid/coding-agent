// =============================================================================
// tb_des_core.v - self-checking testbench for des_core.v
// CSE451 Assignment 1 - Team: 2200405, 2200820, 2201048, 2200243, 2200725
//
// Run (Icarus Verilog):  iverilog -g2012 -s tb_des_core -o sim des_core.v tb_des_core.v && vvp sim
// Run (ModelSim/Questa): vlog des_core.v tb_des_core.v && vsim -c tb_des_core -do "run -all; quit"
// =============================================================================
`timescale 1ns/1ps

module tb_des_core;
    reg         clk = 1'b0;
    reg         rst_n = 1'b0;
    reg         start = 1'b0;
    reg         decrypt = 1'b0;
    reg  [63:0] key = 64'd0;
    reg  [63:0] data_in = 64'd0;
    wire [63:0] data_out;
    wire        done, busy;

    integer errors = 0;
    integer tests  = 0;

    des_core dut (
        .clk(clk), .rst_n(rst_n), .start(start), .decrypt(decrypt),
        .key(key), .data_in(data_in), .data_out(data_out),
        .done(done), .busy(busy)
    );

    always #5 clk = ~clk;                       // 100 MHz

    task run_block;
        input         dec;
        input  [63:0] k;
        input  [63:0] d;
        input  [63:0] expected;
        begin
            @(negedge clk);
            key = k; data_in = d; decrypt = dec; start = 1'b1;
            @(negedge clk);
            start = 1'b0;
            wait (done == 1'b1);
            tests = tests + 1;
            if (data_out !== expected) begin
                errors = errors + 1;
                $display("FAIL  %s key=%h in=%h out=%h expected=%h",
                         dec ? "DEC" : "ENC", k, d, data_out, expected);
            end else
                $display("PASS  %s key=%h in=%h out=%h",
                         dec ? "DEC" : "ENC", k, d, data_out);
            @(negedge clk);
        end
    endtask

    initial begin
        #22 rst_n = 1'b1;

        // --- encryption known-answer tests ---
        run_block(1'b0, 64'h133457799BBCDFF1, 64'h0123456789ABCDEF, 64'h85E813540F0AB405);
        run_block(1'b0, 64'h0000000000000000, 64'h0000000000000000, 64'h8CA64DE9C1B123A7);
        run_block(1'b0, 64'h0101010101010101, 64'h8000000000000000, 64'h95F8A5E5DD31D900);
        run_block(1'b0, 64'h0E329232EA6D0D73, 64'h8787878787878787, 64'h0000000000000000);
        run_block(1'b0, 64'hFFFFFFFFFFFFFFFF, 64'hFFFFFFFFFFFFFFFF, 64'h7359B2163E4EDC58);

        // --- decryption (inverse of the above) ---
        run_block(1'b1, 64'h133457799BBCDFF1, 64'h85E813540F0AB405, 64'h0123456789ABCDEF);
        run_block(1'b1, 64'h0000000000000000, 64'h8CA64DE9C1B123A7, 64'h0000000000000000);
        run_block(1'b1, 64'h0101010101010101, 64'h95F8A5E5DD31D900, 64'h8000000000000000);
        run_block(1'b1, 64'h0E329232EA6D0D73, 64'h0000000000000000, 64'h8787878787878787);
        run_block(1'b1, 64'hFFFFFFFFFFFFFFFF, 64'h7359B2163E4EDC58, 64'hFFFFFFFFFFFFFFFF);

        $display("-----------------------------------------");
        if (errors == 0) $display("ALL %0d TESTS PASSED", tests);
        else             $fatal(1, "%0d of %0d TESTS FAILED", errors, tests);
        $finish;
    end

    initial begin
        #20000 $fatal(1, "TIMEOUT: DES core did not complete all tests");
    end
endmodule
