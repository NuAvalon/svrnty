pragma circom 2.1.6;
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/aliascheck.circom";

// a < b over the FULL field element (0 <= a,b < p). Num2Bits_strict makes the decomposition unique (rejects the in+p alias),
// then compare as (hi 2 bits, lo 252 bits). Returns lt and eq.
template FullCmp() {
    signal input a; signal input b;
    signal output lt; signal output eq;
    component ab = Num2Bits_strict(); ab.in <== a;
    component bb = Num2Bits_strict(); bb.in <== b;
    component alo = Bits2Num(252); component blo = Bits2Num(252);
    for (var i = 0; i < 252; i++) { alo.in[i] <== ab.out[i]; blo.in[i] <== bb.out[i]; }
    signal ahi; signal bhi;
    ahi <== ab.out[252] + 2 * ab.out[253];
    bhi <== bb.out[252] + 2 * bb.out[253];
    component lthi = LessThan(2); lthi.in[0] <== ahi; lthi.in[1] <== bhi;
    component eqhi = IsEqual();   eqhi.in[0] <== ahi; eqhi.in[1] <== bhi;
    component ltlo = LessThan(252); ltlo.in[0] <== alo.out; ltlo.in[1] <== blo.out;
    component eqlo = IsEqual();     eqlo.in[0] <== alo.out; eqlo.in[1] <== blo.out;
    signal t1; t1 <== eqhi.out * ltlo.out;
    lt <== lthi.out + t1;
    eq <== eqhi.out * eqlo.out;
}

// (ax,ay) < (bx,by) lexicographically on full-width x, then full-width y.
template PointLess() {
    signal input ax; signal input ay; signal input bx; signal input by;
    signal output out;
    component cx = FullCmp(); cx.a <== ax; cx.b <== bx;
    component cy = FullCmp(); cy.a <== ay; cy.b <== by;
    signal tie; tie <== cx.eq * cy.lt;
    out <== cx.lt + tie;
}

