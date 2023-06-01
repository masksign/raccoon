"""
mask_random.py
Copyright (c) 2023 Raccoon Signature Team. See LICENSE.

=== This is a dummy (LFSR-127) masking noise generator.

Equivalent Verilog:

//  state register, 127-bit
reg     [126:0] v_r = 127'h0f1e2d3c4b5a69788796a5b4c3d2e1f0;

//  period 2^127-1, primitive polynomial x^127+x^64+1, 64 steps
wire    [63:0]  x_w = { v_r[126:64], v_r[63] ^ v_r[126] };
wire    [126:0] v_w = { x_w[62:0] ^ v_r[62:0], x_w };

always @(posedge clk) begin
    v_r     <=  v_w;
end
"""

MRG_INIT = 0x0F1E2D3C4B5A69788796A5B4C3D2E1F0
MRG_MASK = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
MRG_QMOD = 549824583172097
MRG_QMSK = 0x1FFFFFFFFFFFF

class MaskRandom:

    def __init__(self, seed=b''):
        self.s = MRG_INIT
        for i in range(min(len(seed), 16)):
            self.s ^= seed[i] << (i * 8)

    def step64(self):
        x = (self.s >> 63) ^ (self.s >> 126);
        self.s = (((self.s ^ x) << 64) ^ x) & MRG_MASK

    def uniform_q(self):
        """Uniform number [0,q-1]."""
        while True:
            self.step64()
            z = self.s & MRG_QMSK
            if z < MRG_QMOD:
                return z

    def random_poly(self,n=512):
        """A vector of n random numbers in [0,q-1]."""
        return [ self.uniform_q() for _ in range(n) ]


#   print test values matching the verilog testbench
if (__name__ == "__main__"):

    kat = [ 0x05A7896B4D2F1, 0x14BC078F169E6, 0x168B1A47A1FC9,
            0x046E3B916EC5F, 0x05CA43AD9E72D, 0x0348F079E16E5 ]

    mrg = MaskRandom()

    for z in kat:
        x = mrg.uniform_q()
        print(f'0x{x:013X} 0x{z:013X} {x==z}')

