//  keccakf1600.c
//  Copyright (c) 2023 Raccoon Signature Team. See LICENSE.

//  === FIPS 202 Keccak permutation  for a "generic 64-bit" target.
//  Derived from free / public-domain dedicated sources.

#include "keccakf1600.h"
#include "plat_local.h"

//  clear the state

void keccak_clear(uint64_t vs[25])
{
    size_t i;

    for (i = 0; i < 25; i++) {
        vs[i] = 0;
    }
}

//  extract "rate" bytes from state

void keccak_extract(uint64_t* vs, uint8_t* data, size_t rate)
{
    size_t i;

    for (i = 0; i < rate / 8; i++) {
        put64u_le(data + 8 * i, vs[i]);
    }
}

//  absorb "rate" bytes via xor into the state

void keccak_xorbytes(uint64_t* vs, const uint8_t* data, size_t rate)
{
    size_t i;

    for (i = 0; i < rate / 8; i++) {
        vs[i] ^= get64u_le(data + 8 * i);
    }
}

//  FIPS 202 Keccak f1600 permutation, 24 rounds -- Keccak-p[1600,24](S)

void keccak_f1600(uint64_t vs[25])
{
    //  round constants
    const uint64_t rc[24] = {
        0x0000000000000001LL, 0x0000000000008082LL, 0x800000000000808ALL,
        0x8000000080008000LL, 0x000000000000808BLL, 0x0000000080000001LL,
        0x8000000080008081LL, 0x8000000000008009LL, 0x000000000000008ALL,
        0x0000000000000088LL, 0x0000000080008009LL, 0x000000008000000ALL,
        0x000000008000808BLL, 0x800000000000008BLL, 0x8000000000008089LL,
        0x8000000000008003LL, 0x8000000000008002LL, 0x8000000000000080LL,
        0x000000000000800ALL, 0x800000008000000ALL, 0x8000000080008081LL,
        0x8000000000008080LL, 0x0000000080000001LL, 0x8000000080008008LL};

    int i;
    uint64_t t, u, v, w;
    uint64_t sa, sb, sc, sd, se, sf, sg, sh, si, sj, sk, sl, sm, sn, so, sp, sq,
        sr, ss, st, su, sv, sw, sx, sy;

    //  keccak_count++;

    //  load state, little endian, aligned

    sa = vs[0];
    sb = vs[1];
    sc = vs[2];
    sd = vs[3];
    se = vs[4];
    sf = vs[5];
    sg = vs[6];
    sh = vs[7];
    si = vs[8];
    sj = vs[9];
    sk = vs[10];
    sl = vs[11];
    sm = vs[12];
    sn = vs[13];
    so = vs[14];
    sp = vs[15];
    sq = vs[16];
    sr = vs[17];
    ss = vs[18];
    st = vs[19];
    su = vs[20];
    sv = vs[21];
    sw = vs[22];
    sx = vs[23];
    sy = vs[24];

    //  iteration

    for (i = 0; i < 24; i++) {
        //  Theta

        u = sa ^ sf ^ sk ^ sp ^ su;
        v = sb ^ sg ^ sl ^ sq ^ sv;
        w = se ^ sj ^ so ^ st ^ sy;
        t = w ^ ror64(v, 63);
        sa = sa ^ t;
        sf = sf ^ t;
        sk = sk ^ t;
        sp = sp ^ t;
        su = su ^ t;

        t = sd ^ si ^ sn ^ ss ^ sx;
        v = v ^ ror64(t, 63);
        t = t ^ ror64(u, 63);
        se = se ^ t;
        sj = sj ^ t;
        so = so ^ t;
        st = st ^ t;
        sy = sy ^ t;

        t = sc ^ sh ^ sm ^ sr ^ sw;
        u = u ^ ror64(t, 63);
        t = t ^ ror64(w, 63);
        sc = sc ^ v;
        sh = sh ^ v;
        sm = sm ^ v;
        sr = sr ^ v;
        sw = sw ^ v;

        sb = sb ^ u;
        sg = sg ^ u;
        sl = sl ^ u;
        sq = sq ^ u;
        sv = sv ^ u;

        sd = sd ^ t;
        si = si ^ t;
        sn = sn ^ t;
        ss = ss ^ t;
        sx = sx ^ t;

        //  Rho Pi

        t = ror64(sb, 63);
        sb = ror64(sg, 20);
        sg = ror64(sj, 44);
        sj = ror64(sw, 3);
        sw = ror64(so, 25);
        so = ror64(su, 46);
        su = ror64(sc, 2);
        sc = ror64(sm, 21);
        sm = ror64(sn, 39);
        sn = ror64(st, 56);
        st = ror64(sx, 8);
        sx = ror64(sp, 23);
        sp = ror64(se, 37);
        se = ror64(sy, 50);
        sy = ror64(sv, 62);
        sv = ror64(si, 9);
        si = ror64(sq, 19);
        sq = ror64(sf, 28);
        sf = ror64(sd, 36);
        sd = ror64(ss, 43);
        ss = ror64(sr, 49);
        sr = ror64(sl, 54);
        sl = ror64(sh, 58);
        sh = ror64(sk, 61);
        sk = t;

        //  Chi

        t = andn64(se, sd);
        se = se ^ andn64(sb, sa);
        sb = sb ^ andn64(sd, sc);
        sd = sd ^ andn64(sa, se);
        sa = sa ^ andn64(sc, sb);
        sc = sc ^ t;

        t = andn64(sj, si);
        sj = sj ^ andn64(sg, sf);
        sg = sg ^ andn64(si, sh);
        si = si ^ andn64(sf, sj);
        sf = sf ^ andn64(sh, sg);
        sh = sh ^ t;

        t = andn64(so, sn);
        so = so ^ andn64(sl, sk);
        sl = sl ^ andn64(sn, sm);
        sn = sn ^ andn64(sk, so);
        sk = sk ^ andn64(sm, sl);
        sm = sm ^ t;

        t = andn64(st, ss);
        st = st ^ andn64(sq, sp);
        sq = sq ^ andn64(ss, sr);
        ss = ss ^ andn64(sp, st);
        sp = sp ^ andn64(sr, sq);
        sr = sr ^ t;

        t = andn64(sy, sx);
        sy = sy ^ andn64(sv, su);
        sv = sv ^ andn64(sx, sw);
        sx = sx ^ andn64(su, sy);
        su = su ^ andn64(sw, sv);
        sw = sw ^ t;

        //  Iota

        sa = sa ^ rc[i];
    }

    //  store state

    vs[0] = sa;
    vs[1] = sb;
    vs[2] = sc;
    vs[3] = sd;
    vs[4] = se;
    vs[5] = sf;
    vs[6] = sg;
    vs[7] = sh;
    vs[8] = si;
    vs[9] = sj;
    vs[10] = sk;
    vs[11] = sl;
    vs[12] = sm;
    vs[13] = sn;
    vs[14] = so;
    vs[15] = sp;
    vs[16] = sq;
    vs[17] = sr;
    vs[18] = ss;
    vs[19] = st;
    vs[20] = su;
    vs[21] = sv;
    vs[22] = sw;
    vs[23] = sx;
    vs[24] = sy;
}
