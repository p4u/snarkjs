import * as snarkjs from "../main.js";
import { getCurveFromName } from "../src/curves.js";
import assert from "assert";
import fs from "fs";
import * as binFileUtils from "@iden3/binfileutils";
import * as fastFile from "fastfile";
import { Scalar } from "ffjavascript";
import { readBinFile } from "@iden3/binfileutils";
import { readR1csHeader } from "r1csfile";

describe("Full process (bls12-377)", function ()  {
    this.timeout(1000000000);

    const R_BLS12377 = Scalar.e("12ab655e9a2ca55660b44d1e5c37b00159aa76fed00000010a11800000000001", 16);

    let curve;

    const ptau_0 = {type: "mem"};
    const ptau_1 = {type: "mem"};
    const ptau_final = {type: "mem"};
    const r1cs_bls12377 = {type: "mem"};
    const zkey_0 = {type: "mem"};
    const zkey_1 = {type: "mem"};
    const zkey_final = {type: "mem"};
    let vKey;

    const wtns_bls12377 = {type: "mem"};
    let proof;
    let publicSignals;
    let publicSignalsWithAlias;

    before(async () => {
        curve = await getCurveFromName("bls12-377", { singleThread: true });
    });

    after(async () => {
        await curve.terminate();
    });

    it("patches the test r1cs prime to bls12-377 Fr", async () => {
        await patchR1csPrime("test/plonk_circuit/circuit.r1cs", r1cs_bls12377, R_BLS12377);
        await patchWtnsPrime("test/plonk_circuit/witness.wtns", wtns_bls12377, R_BLS12377);
    });

    it("powersoftau new", async () => {
        await snarkjs.powersOfTau.newAccumulator(curve, 8, ptau_0);
    });

    it("powersoftau contribute", async () => {
        await snarkjs.powersOfTau.contribute(ptau_0, ptau_1, "C1", "Entropy1");
    });

    it("powersoftau prepare phase2", async () => {
        await snarkjs.powersOfTau.preparePhase2(ptau_1, ptau_final);
    });

    it("powersoftau verify", async () => {
        const ok = await snarkjs.powersOfTau.verify(ptau_final);
        assert(ok);
    });

    it("groth16 setup", async () => {
        await snarkjs.zKey.newZKey(r1cs_bls12377, ptau_final, zkey_0);
    });

    it("zkey contribute", async () => {
        await snarkjs.zKey.contribute(zkey_0, zkey_1, "p2_C1", "pa_Entropy1");
    });

    it("zkey beacon", async () => {
        await snarkjs.zKey.beacon(zkey_1, zkey_final, "B3", "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20", 10);
    });

    it("zkey verify (from r1cs)", async () => {
        const ok = await snarkjs.zKey.verifyFromR1cs(r1cs_bls12377, ptau_final, zkey_final);
        assert(ok);
    });

    it("zkey verify (from init)", async () => {
        const ok = await snarkjs.zKey.verifyFromInit(zkey_0, ptau_final, zkey_final);
        assert(ok);
    });

    it("zkey export verificationkey", async () => {
        vKey = await snarkjs.zKey.exportVerificationKey(zkey_final);
        assert.equal(vKey.curve, "bls12377");
    });

    it("checks witness complies with r1cs", async () => {
        await snarkjs.wtns.check(r1cs_bls12377, wtns_bls12377);
    });

    it("groth16 proof", async () => {
        const res = await snarkjs.groth16.prove(zkey_final, wtns_bls12377);
        proof = res.proof;
        publicSignals = res.publicSignals;
        publicSignalsWithAlias = [...publicSignals];
        publicSignalsWithAlias[1] = BigInt(publicSignalsWithAlias[1]) + R_BLS12377;
    });

    it("groth16 verify", async () => {
        const ok = await snarkjs.groth16.verify(vKey, publicSignals, proof);
        assert(ok);

        const okAlias = await snarkjs.groth16.verify(vKey, publicSignalsWithAlias, proof);
        assert.equal(okAlias, false);
    });
});

async function patchR1csPrime(srcPath, dst, prime) {
    const raw = new Uint8Array(fs.readFileSync(srcPath));
    const {fd, sections} = await readBinFile(srcPath, "r1cs", 1, 1 << 22, 1 << 24);
    const header = await readR1csHeader(fd, sections, { singleThread: true });
    const section1 = sections[1][0];
    await fd.close();

    const primeBytes = new Uint8Array(header.n8);
    Scalar.toRprLE(primeBytes, 0, prime, header.n8);

    // Section 1 header is: n8 (u32) || prime (n8) || ...
    raw.set(primeBytes, section1.p + 4);

    const outFd = await fastFile.createOverride(dst);
    await outFd.write(raw);
    await outFd.close();
}

async function patchWtnsPrime(srcPath, dst, prime) {
    const raw = new Uint8Array(fs.readFileSync(srcPath));
    const {fd, sections} = await readBinFile(srcPath, "wtns", 2, 1 << 22, 1 << 24);
    const section1 = sections[1][0];
    await binFileUtils.startReadUniqueSection(fd, sections, 1);
    const n8 = await fd.readULE32();
    await binFileUtils.readBigInt(fd, n8);
    await fd.readULE32();
    await binFileUtils.endReadSection(fd);
    await fd.close();

    const primeBytes = new Uint8Array(n8);
    Scalar.toRprLE(primeBytes, 0, prime, n8);

    // Section 1 header is: n8 (u32) || q (n8) || ...
    raw.set(primeBytes, section1.p + 4);

    const outFd = await fastFile.createOverride(dst);
    await outFd.write(raw);
    await outFd.close();
}
