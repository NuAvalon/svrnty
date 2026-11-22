pragma circom 2.1.6;
// #588 slot-binding circuit, R3 revision (Apollo, 2026-10-31). NOT reviewed (R5 pending), NOT for use.
// R3-a: domain tags are the big-endian integer of ASCII strings (<=31 bytes, so injective into the field).
// R3-b: canonical order of (P,Y) is FULL-WIDTH: whole x (254 bits, strict decomposition), then whole y as tiebreak.
include "circomlib/circuits/babyjub.circom";
include "circomlib/circuits/escalarmulany.circom";
include "circomlib/circuits/escalarmulfix.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/aliascheck.circom";
include "fullcmp.circom";

template SlotBind() {
    // public inputs
    signal input e;     // epoch
    signal input H_e;   // slot
    signal input N;     // nullifier
    signal input K;     // one-time poll key (bound by being public)
    // witness
    signal input x;     // beacon secret
    signal input Yx; signal input Yy;   // counterpart beacon key
    signal input Qx; signal input Qy;   // Y = 8*Q  (cofactor-clearing witness => Y is in the prime-order subgroup)

    var L = 2736030358979909402780800718157159386076813972158567259200215660948447373041;
    var BASE8[2] = [
        5299619240641551281634865583518297030282874472190772894086521144482721001553,
        16950150798460657717958625567821834550301663161624707787222815936182638968203
    ];
    var DS_SLOT = 0x7376726e74793a3538383a736c6f743a7631; // ascii "svrnty:588:slot:v1"
    var DS_NULL = 0x7376726e74793a3538383a6e756c6c3a7631; // ascii "svrnty:588:null:v1"

    // C1: 1 <= x < L   (x != 0 added: x=0 would make P the identity)
    // L < 2^251, so x < L  <=>  (x fits in 251 bits) and (x < L as 251-bit numbers)
    component xb = Num2Bits(251); xb.in <== x;
    component xlt = LessThan(251); xlt.in[0] <== x; xlt.in[1] <== L; xlt.out === 1;
    component xz = IsZero(); xz.in <== x; xz.out === 0;

    // C2: P = x*G  (G = Base8, generator of the prime-order subgroup)
    component pm = EscalarMulFix(251, BASE8);
    for (var i = 0; i < 251; i++) { pm.e[i] <== xb.out[i]; }
    signal Px; signal Py;
    Px <== pm.out[0]; Py <== pm.out[1];

    // C3: Y on curve, Y in prime subgroup (Y = 8*Q with Q on curve), Y != identity
    component yc = BabyCheck(); yc.x <== Yx; yc.y <== Yy;
    component qc = BabyCheck(); qc.x <== Qx; qc.y <== Qy;
    component d1 = BabyDbl(); d1.x <== Qx;        d1.y <== Qy;
    component d2 = BabyDbl(); d2.x <== d1.xout;   d2.y <== d1.yout;
    component d3 = BabyDbl(); d3.x <== d2.xout;   d3.y <== d2.yout;
    d3.xout === Yx; d3.yout === Yy;
    component yz = IsZero(); yz.in <== Yx; yz.out === 0;   // identity is (0,1); the only other x=0 point is order 2, excluded by the subgroup check

    // C4: S = x*Y   (EscalarMulAny assumes Y is in the subgroup and != 0: both are enforced by C3 in this same system)
    component dh = EscalarMulAny(251);
    for (var i = 0; i < 251; i++) { dh.e[i] <== xb.out[i]; }
    dh.p[0] <== Yx; dh.p[1] <== Yy;

    // canonical order of (P, Y): FULL-WIDTH by x, ties by y
    component pl = PointLess(); pl.ax <== Px; pl.ay <== Py; pl.bx <== Yx; pl.by <== Yy;
    signal pFirst; pFirst <== pl.out;
    signal minx; signal miny; signal maxx; signal maxy;
    minx <== Yx + pFirst * (Px - Yx);
    miny <== Yy + pFirst * (Py - Yy);
    maxx <== Px + Yx - minx;
    maxy <== Py + Yy - miny;

    // C5: H_e = Poseidon(DS_SLOT, S, min(P,Y), max(P,Y), e)
    component hs = Poseidon(8);
    hs.inputs[0] <== DS_SLOT;
    hs.inputs[1] <== dh.out[0]; hs.inputs[2] <== dh.out[1];
    hs.inputs[3] <== minx; hs.inputs[4] <== miny;
    hs.inputs[5] <== maxx; hs.inputs[6] <== maxy;
    hs.inputs[7] <== e;
    H_e === hs.out;

    // C6: N = Poseidon(DS_NULL, x, H_e)
    component hn = Poseidon(3);
    hn.inputs[0] <== DS_NULL; hn.inputs[1] <== x; hn.inputs[2] <== H_e;
    N === hn.out;

    // C7: K is a public input; this makes it appear in a constraint
    signal Ksq; Ksq <== K * K;
}

component main { public [e, H_e, N, K] } = SlotBind();
