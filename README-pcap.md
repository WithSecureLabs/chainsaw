# Chainsaw PCAP ingestion (prototype)

Branch: `feat/pcap-ingestion`. Lets `chainsaw hunt capture.pcap` dissect network
captures into `Network.*` / `Kerberos.*` documents the **existing** Tau rule
engine + Sigma mappings match, so network-only AD attacks (ticket abuse,
Rubeus/Mimikatz fingerprints, etype downgrade) are detected with the same tool
and rule format as EVTX.

> **COMPILATION/RUN STATE: UNVERIFIED.** Every file on this branch was authored
> in an environment with **no Rust toolchain**. Nothing here has been compiled
> or run. The design, schema, and wiring are the deliverable; treat build claims
> as "intended to build, pending `cargo` on a real box". The most likely
> first-build breakage is `pcap-parser` / `etherparse` API drift — those call
> sites are flagged with `// API:` comments in `src/file/pcap.rs`.

## What works (intended)

- New file kind `pcap`, auto-detected by `.pcap` / `.pcapng` extension.
- Native, self-contained dissection (no libpcap, no tshark):
  - `pcap-parser` reads legacy pcap and pcapng.
  - `etherparse` parses Ethernet / IPv4 / IPv6 / UDP / TCP.
  - A small hand-rolled BER/DER reader dissects Kerberos (RFC 4120).
- Kerberos over UDP/88 and TCP/88 (in-order reassembly): AS-REQ/REP,
  TGS-REQ/REP, AP-REQ, plus the KRB-ERROR envelope. One document per message.
- Full `Network.*` / `Kerberos.*` schema (see `docs/pcap-ingestion.md` §3).
- `pcap::Wrapper` (analogous to `evtx::Wrapper`) wired into `hunt`/`cli`/`search`.
- `mappings/sigma-network.yml` + three example Sigma rules in `rules-network/`.

## What is stubbed / limited

- **LDAP (389/636), SMB (445), DCERPC (135)**: `Dissector` trait impls that
  return no documents, with TODOs. Kerberos only for this first cut.
- **TCP reassembly** is arrival-order only — no seq reordering, retransmit
  dedup, or gap handling. Correct for in-order, loss-free captures. See ADR §7.
- **Encrypted parts are not decrypted.** `Kerberos.authenticator_seq_hex` is a
  *ciphertext* prefix; the Mimikatz rule that keys on it only fires where that
  structure is observable in cleartext. See ADR §3.2.
- **pcapng timestamps** assume the 1-microsecond `if_tsresol` default.
- **tshark backend** (`--features tshark`, crate `rtshark`) is a declared,
  feature-gated seam only; not implemented in this cut.

## Build

Requires a Rust toolchain (edition 2024; use current stable, e.g. `rustup update`).

```sh
# from the repo root
cargo build --release
# optional tshark-backed backend (adds a tshark runtime dependency):
# cargo build --release --features tshark
```

`cargo` will resolve and lock the two new crates (`pcap-parser`, `etherparse`)
on first build; `Cargo.lock` is intentionally left for the build box to update.
If a new-crate version fails to resolve, pin it: `cargo update -p pcap-parser`.

## Run

```sh
./target/release/chainsaw hunt sample.pcap \
    -s rules-network/ \
    --mapping mappings/sigma-network.yml
```

- `sample.pcap` — a capture containing Kerberos on port 88 (e.g. `tcpdump -w
  sample.pcap 'port 88'` on a DC segment, or an existing AD attack PCAP).
- `-s rules-network/` — the example Sigma rules.
- `--mapping mappings/sigma-network.yml` — maps Sigma field names onto the
  `Network.*` / `Kerberos.*` schema and declares `kind: pcap`.

Add `--json` / `--jsonl` for machine output, `-q` to quiet the banner.

> Note: upstream `chainsaw hunt --kind` selects the *rule* kind
> (`chainsaw`/`sigma`/`stalker`), not the file kind. The pcap file kind is
> selected by extension + the mapping's `kind: pcap`; there is deliberately no
> new file-level `--kind` flag (that would diverge from the upstream pattern).

## Test

```sh
# unit tests, including the BER/DER reader tests in src/file/pcap.rs
cargo test

# just the pcap module tests
cargo test --lib file::pcap

# clippy / fmt as CI would
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

There is no checked-in sample capture. To build a byte-exact unit fixture,
generate a tiny AS-REQ with a Kerberos library (e.g. impacket) and assert the
emitted `Kerberos.msg_type` / `Kerberos.till` / `Kerberos.etype_first`. A
follow-up should add a `tests/pcap/` fixture + integration test mirroring
`tests/evtx/`.

## Files added / changed

Added:
- `docs/pcap-ingestion.md` — architecture decision record (schema, Tau mapping,
  backend decision, limitations).
- `src/file/pcap.rs` — the pcap file kind: container read, L2-L4 parse, TCP/88
  reassembly, Kerberos BER dissection, `Dissector` trait + stubs, `Wrapper`.
- `mappings/sigma-network.yml` — Sigma field mapping for `Network.*`/`Kerberos.*`.
- `rules-network/` — three example Sigma rules.
- `README-pcap.md` — this file.

Changed (EVTX/MFT/JSON paths untouched in behaviour):
- `Cargo.toml` — `pcap-parser`, `etherparse`; optional `rtshark` behind feature.
- `src/file/mod.rs` — `Kind::Pcap`, `Document::Pcap`, `Parser::Pcap`, extension
  detection, dispatch.
- `src/lib.rs` — re-export `pcap`.
- `src/hunt.rs` — pcap document conversion + `pcap::Wrapper` dispatch.
- `src/cli.rs` — `FileKind::Pcap` arms in the four wrapper/mapper blocks.
- `src/search.rs`, `src/main.rs` — `Document::Pcap` arms.

---

## Draft upstream PR description (DO NOT open yet — for use IF upstream signals interest)

> **Title:** Add PCAP ingestion (native Kerberos dissection) behind a Dissector trait
>
> **Scope.** Adds a `pcap` file kind so `chainsaw hunt capture.pcap` dissects
> network captures into documents the existing Tau engine + Sigma mappings match.
> First cut covers Kerberos over port 88 (AS-REQ/REP, TGS-REQ/REP, AP-REQ) under
> a stable `Network.*` / `Kerberos.*` schema. EVTX/MFT/JSON paths are untouched.
>
> **Why.** SOCs already run Chainsaw + Sigma over EVTX. Network-only AD attacks
> (ticket forging, Rubeus/Mimikatz wire fingerprints, etype downgrade, S4U/PAC
> anomalies) are invisible to host logs but obvious on the wire. This keeps
> detection in one tool and one rule format instead of bolting on Zeek/Suricata.
>
> **Design.**
> - New kind mirrors the existing parser contract exactly: `file::pcap::Parser`
>   (`load`/`parse`), `Document::Pcap`, `Kind::Pcap`, extension detection, and a
>   `pcap::Wrapper` analogous to `evtx::Wrapper`.
> - Dissection is **native and self-contained** by default: `pcap-parser`
>   (pcap/pcapng) + `etherparse` (L2-L4) + a small purpose-built BER/DER reader
>   for Kerberos ASN.1. No libpcap, no tshark in the default build — this honours
>   Chainsaw's single-binary distribution.
> - A `Dissector` trait is the extension seam: LDAP/SMB/DCERPC are stubbed behind
>   it, and a tshark-backed backend is available as an **optional feature**
>   (`--features tshark`, crate `rtshark`) for teams wanting breadth now at the
>   cost of a tshark runtime dependency. Dissection is behind a trait precisely
>   so breadth can be earned incrementally (or delegated) without reworking the
>   pipeline or forcing a runtime dependency on everyone.
> - Schema is nested JSON with dotted paths, so Tau matches it for free and the
>   Sigma mapping stays thin.
>
> **Limitations (documented).** TCP reassembly is arrival-order only; encrypted
> parts are not decrypted; pcapng timestamp resolution assumes the 1us default;
> Kerberos only in this cut. See `docs/pcap-ingestion.md`.
>
> **Test plan.** `cargo test` (incl. BER/DER unit tests); a `tests/pcap/` fixture
> + integration test (impacket-generated AS-REQ) mirroring `tests/evtx/` is the
> obvious follow-up; manual `chainsaw hunt sample.pcap -s rules-network/
> --mapping mappings/sigma-network.yml` against a lab Kerberos capture.
>
> **Dependencies added.** `pcap-parser`, `etherparse` (both pure-Rust);
> `rtshark` optional/feature-gated.
