import { getCurveFromName } from "../src/curves.js";
import assert from "assert";

describe("BLS12-377 Curve", function () {
    this.timeout(10000);
    let curve;

    before(async () => {
        curve = await getCurveFromName("bls12377", { singleThread: true });
    });

    after(async () => {
        if (curve) await curve.terminate();
    });

    it("Should resolve curve name aliases", async () => {
        const curve2 = await getCurveFromName("bls12-377", { singleThread: true });
        assert.equal(curve2.name, "bls12377");
        await curve2.terminate();
    });

    it("Should have valid G1 generator", async () => {
        const G1 = curve.G1;
        const g1 = G1.g;
        assert(G1.isValid(g1), "G1 generator invalid");
    });

    it("Should have valid G2 generator", async () => {
        const G2 = curve.G2;
        const g2 = G2.g;
        assert(G2.isValid(g2), "G2 generator invalid");
    });

    it("Should satisfy pairing bilinearity", async () => {
        const G1 = curve.G1;
        const G2 = curve.G2;
        const Fr = curve.Fr;
        const g1 = G1.g;
        const g2 = G2.g;
        const p1 = G1.timesFr(g1, Fr.e("2"));
        const p2 = G2.timesFr(g2, Fr.e("2"));
        
        const pair1 = curve.pairing(p1, g2);
        const pair2 = curve.pairing(g1, p2);
        
        assert(curve.F12.eq(pair1, pair2), "Pairing bilinearity failed");
    });
});
