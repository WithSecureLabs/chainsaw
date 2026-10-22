# ADR: PCAP ingestion for Chainsaw

**Status:** Prototype / proposal. **Compilation state: UNVERIFIED.** This branch was
authored in an environment with no Rust toolchain. None of the code here has been
compiled or run. Treat every "works" statement as "intended to work, pending a build on
a box with `cargo`". See `README-pcap.md` for build/test steps.

## 1. Goal

Let `chainsaw hunt capture.pcap` dissect network traffic into `field -> value` documents
that the **existing** Tau rule engine and Sigma mapping layer can match, so the SOC can
detect network-only AD attacks (Golden/Silver ticket PAC anomalies, Rubeus/Mimikatz wire
fingerprints, Kerberos etype/flag abuse) with the *same* tool and the *same* rule format
they already use for EVTX/MFT/JSON. One tool, no pivot to Zeek/Suricata.

Non-goal: re-implementing Wireshark. We want a **thin, correct** path for the
highest-value protocol (Kerberos on port 88), with a documented seam so other protocols
can be added later or delegated to tshark.

## 2. How a "file kind" works in Chainsaw today

Reading the existing code (`src/file/mod.rs`, `src/file/evtx.rs`, `src/file/mft.rs`,
`src/hunt.rs`, `src/value.rs`) the contract for a new input type is:

1. A module under `src/file/` exposes a `Parser` with:
   - `Parser::load(path) -> crate::Result<Self>`
   - `Parser::parse(&mut self) -> impl Iterator<Item = crate::Result<T>>`
   where `T` is some per-record payload. For `mft`/`json`/`esedb`, `T = serde_json::Value`.
2. `file::Document` gains a variant wrapping `T`; `file::Kind` gains a variant;
   `Kind::extensions()` lists the file extensions.
3. `Reader::load` dispatches on extension to the right `Parser`; `Reader::documents`
   maps the parser's iterator into `Document::<Variant>`; `Reader::kind` reports it.
4. `hunt.rs` converts each `Document` into a `crate::value::Value` (via `From<Json>`),
   then **optionally wraps it** in a per-kind `Document`-trait wrapper that aliases
   awkward field paths (this is exactly what `evtx::Wrapper` does, remapping
   `Event.System.Provider` to `Event.System.Provider_attributes.Name`). The wrapped
   value is handed to `hunt.mapper.mapped(...)` and ultimately to `tau_engine::...solve`.
5. The Sigma **mapping** YAML (`mappings/*.yml`) declares `kind: <filekind>` plus a
   `groups:` block whose `fields:` list remaps Sigma field names (`from`) onto document
   paths (`to`). Fields not listed fall through to a direct `document.find(key)` lookup
   (see `Mapper`/`MapperKind::Fast` in `hunt.rs`), so a document that already emits clean
   dotted paths needs only a thin mapping.
6. Tau/`Value::find` already walks dotted paths into nested objects (that is how the evtx
   wrapper resolves `Event.System.Provider_attributes.Name`). So **nested JSON objects
   with a stable namespace are matched by dotted keys for free** — no flattening needed.

Our pcap kind follows this contract exactly. EVTX/MFT/JSON code paths are untouched.

> Note on `--kind`: upstream `chainsaw hunt --kind` selects the *rule* kind
> (`chainsaw`/`sigma`/`stalker`), **not** the file kind. File kind is auto-detected from
> the extension and declared by the mapping's `kind:` field. We therefore wire pcap in via
> (a) `.pcap`/`.pcapng` extension detection in `Reader::load` + `Kind::extensions`, and
> (b) `kind: pcap` in the mapping. There is intentionally no new file-level `--kind` flag;
> adding one would diverge from the upstream pattern. `--kind pcap` in the task brief maps
> onto the mapping's `kind: pcap` declaration.

## 3. Document schema (the stable contract)

One document is emitted **per dissected application-layer message** (one Kerberos message
= one document). Everything is a nested JSON object under two namespaces:

- `Network.*` — L3/L4 envelope, protocol-independent.
- `Kerberos.*` / `Ldap.*` / `Smb.*` / `Dcerpc.*` — per-application-protocol fields.
  Only `Kerberos.*` is implemented in this first cut.

### 3.1 `Network.*` (emitted for every document)

| Field | Type | Meaning |
|---|---|---|
| `Network.timestamp` | string | Packet capture time, `%Y-%m-%dT%H:%M:%S%.6fZ` (the format `hunt.rs` parses). This is the hunt timestamp. |
| `Network.protocol` | string | App protocol: `kerberos` (future: `ldap`, `smb`, `dcerpc`). |
| `Network.transport` | string | `udp` or `tcp`. |
| `Network.src_ip` / `Network.dst_ip` | string | L3 addresses (v4 or v6 text form). |
| `Network.src_port` / `Network.dst_port` | uint | L4 ports. |
| `Network.length` | uint | Length in bytes of the app-layer message dissected. |
| `Network.frame` | uint | 1-based index of the source packet in the capture (for triage). |

### 3.2 `Kerberos.*` (RFC 4120 wire fields rules key on)

All of these come straight off the wire. Fields that live in encrypted parts
(authenticator contents, PA-ENC-TIMESTAMP plaintext) are **not** decrypted; where the
brief asks for "authenticator sequence bytes where visible" we expose the *ciphertext*
prefix and the sizes, and say so plainly — a rule keyed on a plaintext authenticator value
only fires on traffic where that part is observable (unencrypted test traffic, or a
capture the analyst has pre-decrypted). We never claim to see inside `EncryptedData`.

| Field | Type | Source (RFC 4120) |
|---|---|---|
| `Kerberos.msg_type` | uint | APPLICATION tag → 10 AS-REQ, 11 AS-REP, 12 TGS-REQ, 13 TGS-REP, 14 AP-REQ, 30 KRB-ERROR |
| `Kerberos.msg_type_name` | string | Human name of the above |
| `Kerberos.pvno` | uint | Protocol version (5) |
| `Kerberos.realm` | string | `realm` / `crealm` |
| `Kerberos.cname` | array<string> | client PrincipalName name-string components |
| `Kerberos.cname_string` | string | components joined with `/` |
| `Kerberos.cname_type` | uint | client name-type |
| `Kerberos.sname` | array<string> | service PrincipalName components (req body or ticket) |
| `Kerberos.sname_string` | string | components joined with `/` (e.g. `krbtgt/CONTOSO.COM`) |
| `Kerberos.sname_type` | uint | service name-type |
| `Kerberos.kdc_options` | string | KDCOptions 32-bit flags, hex (`req` only) |
| `Kerberos.kdc_options_flags` | array<string> | decoded flag names (forwardable, renewable, renewable-ok, renew, ...) |
| `Kerberos.ap_options` | string | APOptions 32-bit flags, hex (`AP-REQ` only) |
| `Kerberos.etypes` | array<int> | requested encryption types, **in wire order** |
| `Kerberos.etype_count` | uint | number of etypes offered |
| `Kerberos.etype_first` | int | first (most-preferred) etype — the one the client leads with |
| `Kerberos.nonce` | uint | request nonce |
| `Kerberos.from` / `Kerberos.till` / `Kerberos.rtime` | string | KerberosTime GeneralizedTime (`till` is the ticket-lifetime field Rubeus hard-codes) |
| `Kerberos.renew_till` | string | renew-till where present |
| `Kerberos.cusec` | uint | client microseconds (only when observable in a plaintext structure) |
| `Kerberos.ctime` | string | client time where observable |
| `Kerberos.padata_types` | array<int> | PA-DATA `padata-type` values present, in order |
| `Kerberos.pa_pac_request` | bool | PA-PAC-REQUEST (128) present |
| `Kerberos.pa_pac_options` | string | PA-PAC-OPTIONS (167) value hex, where present |
| `Kerberos.pa_for_user` | bool | PA-FOR-USER (129) present → S4U2self |
| `Kerberos.pa_for_user_name` | string | S4U2self target principal, where parseable |
| `Kerberos.enc_part_etype` | int | enc-part `EncryptedData.etype` |
| `Kerberos.enc_part_kvno` | uint | enc-part key version, where present |
| `Kerberos.enc_part_size` | uint | enc-part cipher length (bytes) |
| `Kerberos.authenticator_etype` | int | AP-REQ authenticator `EncryptedData.etype` |
| `Kerberos.authenticator_size` | uint | AP-REQ authenticator cipher length |
| `Kerberos.authenticator_seq_hex` | string | **ciphertext** prefix (up to 8 bytes) of the AP-REQ authenticator — see caveat above |
| `Kerberos.ticket_sname_string` | string | sname carried inside an AP-REQ `Ticket` |
| `Kerberos.ticket_realm` | string | realm carried inside an AP-REQ `Ticket` |

This namespace is the **stable contract** rules depend on. Adding fields is fine; renaming
or re-typing is a breaking change for the rule pack.

## 4. Mapping onto the Tau engine

Because the document already emits clean dotted paths, `mappings/sigma-network.yml` is
thin:

- `kind: pcap`, `rules: sigma`.
- One group whose `filter: { Network.protocol: "*" }` selects every network document
  (`Network.protocol` exists on all of them).
- `timestamp: Network.timestamp`.
- A short `fields:` block giving friendly Sigma aliases (`MsgType -> Kerberos.msg_type`,
  etc.). Sigma rules may also reference the full `Kerberos.*` path directly, which the
  Mapper's fall-through resolves unchanged.

Sigma modifiers (`|contains`, `|all`, `int(...)`, globbing) work exactly as they do for
EVTX because the same Tau engine evaluates them against the same `Value` tree.

A `pcap::Wrapper` (analogous to `evtx::Wrapper`) is provided and wired into `hunt.rs` /
`cli.rs` / `search.rs`. For the current schema it mostly delegates to the inner value, but
it gives us the same aliasing seam evtx uses — e.g. letting a rule say `Kerberos.cname`
and resolve to `Kerberos.cname_string` without an array-vs-scalar surprise.

## 5. Dissection backend decision

Two honest routes were considered:

### Route A — tshark-backed via the `rtshark` crate
- **Pros:** fastest path to broad, correct coverage; Wireshark already dissects every AD
  protocol; we'd just translate its field tree into `Network.*`/`Kerberos.*`.
- **Cons:** adds a **runtime dependency on a `tshark` binary** on every analyst box. That
  directly contradicts the "one tool, no external pivot" goal — it just moves the second
  tool from Zeek to tshark, and couples us to tshark's field naming and versioning. It
  also spawns a subprocess per capture, which complicates the error model and packaging.

### Route B — native dissection (the real target)
- `pcap-parser` (pure-Rust, rusticata) reads both `.pcap` (legacy) and `.pcapng`; no
  libpcap/system dependency.
- `etherparse` (pure-Rust) parses L2→L4 (Ethernet / IPv4 / IPv6 / UDP / TCP).
- **Kerberos ASN.1:** a small, purpose-built BER/DER TLV reader lives in `pcap.rs`. We
  deliberately did **not** pull in a general ASN.1 crate (`rasn`/`der`) for the first cut:
  (1) Kerberos uses only a tiny slice of BER (low-tag-number application + context tags,
  definite lengths, INTEGER/OCTET STRING/GeneralizedTime/BIT STRING/SEQUENCE), so a ~150
  line reader covers it with full control over exactly the fields rules need; (2) it keeps
  the dependency surface — and the compile-risk — minimal; (3) it avoids dragging a derive
  world and generated Kerberos types we'd only use 10% of. `rasn-kerberos` remains the
  obvious drop-in if we later want the full type set — the `Dissector` trait makes that a
  module swap, not a rewrite.
- **Pros:** self-contained single binary; keeps the one-tool promise.
- **Cons:** we own the dissection and TCP reassembly; more code; more that can be wrong.

### Decision

**Ship Route B (native) for Kerberos-over-88 as the first cut**, behind a `Dissector`
trait. Expose **Route A (tshark) as an optional, feature-gated backend** (`--features
tshark`) for teams that want breadth now and accept the runtime dependency. Default build
is native and self-contained. This honours the one-tool goal in the default build while
leaving tshark as an explicit opt-in.

Rationale: Kerberos is the single highest-value AD-over-the-wire protocol (ticket
abuse, etype downgrade, S4U, PAC anomalies all show up on 88), its request bodies are
largely **plaintext**, and it is small enough to dissect correctly by hand. Breadth
(LDAP/SMB/DCERPC) is better earned incrementally against the trait than bought all at once
by taking a tshark dependency.

## 6. The backend seam

```text
                +------------------------------------+
  packets  -->  |  pcap-parser (pcap / pcapng)       |
                +------------------------------------+
                            | raw L2 frame + ts + frame#
                            v
                +------------------------------------+
                |  etherparse  (Eth/IP/UDP/TCP)      |
                +------------------------------------+
                            | FlowMeta + app payload (TCP reassembled per-flow)
                            v
                +------------------------------------+
                |  trait Dissector (port-claimed)    |
                |   - KerberosDissector   [REAL]     |
                |   - LdapDissector       [STUB]     |
                |   - SmbDissector        [STUB]     |
                |   - DcerpcDissector     [STUB]     |
                +------------------------------------+
                            | serde_json::Value  (Network.* / Kerberos.*)
                            v
                   Document::Pcap  -->  value::Value  -->  pcap::Wrapper
                            |
                            v
                   hunt.mapper.mapped(...)  -->  tau_engine solve
```

`trait Dissector { fn claims(&self, port: u16) -> bool; fn dissect(&self, meta: &FlowMeta,
payload: &[u8]) -> Vec<serde_json::Value>; }`. Adding LDAP/SMB/DCERPC = implement the
trait and register it in the dissector table. tshark, when enabled, is a single alternate
`Dissector` implementation that shells out and maps Wireshark fields into the same schema.

## 7. TCP reassembly (first-cut limitation, stated plainly)

Kerberos over TCP (RFC 4120 §7.2.2) prefixes each message with a 4-byte big-endian length.
UDP carries one bare message per datagram. The first cut:

- UDP/88: parse each datagram directly as one Kerberos message.
- TCP/88: buffer payload **in arrival order** per 4-tuple flow, then repeatedly pull
  `len`-prefixed messages off the front of the buffer.

This is correct for in-order, loss-free captures (the common lab/SOC case) but does **not**
do sequence-number reordering, retransmit de-duplication, or gap detection. That is a
documented TODO; a production version should key on TCP seq and handle holes. We prefer to
ship the honest limited version over a fake-complete one.

## 8. What is real vs stubbed in this branch

- **Real (native):** pcap/pcapng read, Eth/IPv4/IPv6/UDP/TCP parse, in-order TCP/88
  reassembly, Kerberos BER dissection of AS-REQ/REP, TGS-REQ/REP, AP-REQ (+ KRB-ERROR
  envelope), the full `Network.*`/`Kerberos.*` schema above, the `pcap::Wrapper`, the
  mapping, and three Sigma rules.
- **Stubbed (trait impls returning no documents, with TODOs):** LDAP (389/636),
  SMB (445), DCERPC (135/dynamic).
- **Optional/feature-gated, not built by default:** tshark backend via `rtshark`.
- **Everything is compilation-UNVERIFIED** — authored without a Rust toolchain.
