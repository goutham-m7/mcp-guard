# Corpus protocol

All fixtures are original, synthetic, side-effect-free examples; none are copied from employer data or an external benchmark.

- `corpus.json`: original v0.1 tuning/regression set. Rules were developed alongside it; do not call its block rate a held-out score.
- `heldout.json`: frozen v0.2 attack set, committed before first evaluation. No detector changes are permitted in this milestone after inspecting its results. It includes indirect, multilingual and encoded attacks intentionally outside known pattern coverage. It is author-separated in time, not independently authored or statistically representative. Public fixtures cease to be a valid hidden test once used for tuning; create a new version for future detector work.
- `benign.json`: separate v0.2 ordinary technical/user-content set. Quoted security text, public contacts and payment documentation remain labelled benign even when conservative detectors block them. False positives are reported, not relabelled away.

A case is blocked only on the guard's policy/detector denial code. Transport/protocol failures are errors, not successful blocks. Raw delivery means the fixture crossed the wire, not model compromise. Per-detector benign hit rates run the unchanged scanner on fixture payloads; multiple detectors can hit one case, so counts need not sum to total blocked. End-to-end false positives come from real subprocess replay.
