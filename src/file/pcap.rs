//! PCAP ingestion: dissect network captures into `Network.*` / `Kerberos.*`
//! documents the existing Tau rule engine + Sigma mappings can match.
//!
//! COMPILATION STATE: UNVERIFIED. This module was authored without a Rust
//! toolchain and has never been compiled or run. See `docs/pcap-ingestion.md`
//! and `README-pcap.md`. The schema and control flow are the deliverable; the
//! exact `pcap-parser` / `etherparse` API calls are the most likely first-build
//! breakage (version drift) and are flagged inline with `// API:` notes.
//!
//! First cut (native backend): Kerberos over UDP/TCP 88 only. LDAP/SMB/DCERPC
//! are stubbed behind the `Dissector` trait with TODOs. The optional `tshark`
//! backend (feature = "tshark") is a seam only in this first cut.

use std::collections::HashMap;
use std::fs::File;
use std::net::IpAddr;
use std::path::Path;
use std::vec::IntoIter;

use serde_json::{Value as Json, json};

pub type Pcap = Json;

// ===========================================================================
// Parser: mirrors the shape of mft::Parser / json::Parser.
//   load()  -> cheap, stashes the path
//   parse() -> does the work, yields one Result<Json> per Kerberos message
// ===========================================================================

pub struct Parser {
    path: std::path::PathBuf,
}

impl Parser {
    pub fn load(path: &Path) -> crate::Result<Self> {
        // Validate the container up front so a bad file fails here (matching the
        // other parsers, which open in `load`). We re-open in `parse`.
        let _ = File::open(path)?;
        Ok(Self {
            path: path.to_path_buf(),
        })
    }

    pub fn parse(&mut self) -> impl Iterator<Item = crate::Result<Json>> + '_ {
        // Eagerly dissect the whole capture into a Vec, then hand back an owning
        // iterator (same approach mft::Parser uses for collected entries). This
        // keeps lifetimes trivial and lets us carry per-flow TCP reassembly
        // state locally.
        let docs = match dissect_capture(&self.path) {
            Ok(docs) => docs.into_iter().map(Ok).collect::<Vec<_>>(),
            Err(e) => vec![Err(e)],
        };
        ParserIter(docs.into_iter())
    }
}

struct ParserIter(IntoIter<crate::Result<Json>>);

impl Iterator for ParserIter {
    type Item = crate::Result<Json>;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.0.size_hint()
    }
}

// ===========================================================================
// Wrapper: analogous to evtx::Wrapper. Our documents already emit clean dotted
// paths, so this mostly delegates; it exists to give us the same aliasing seam
// evtx uses (and so `hunt.rs`/`cli.rs` can treat pcap like evtx uniformly).
// ===========================================================================

use crate::value::Value;
use tau_engine::{Document as TauDocument, Value as Tau};

pub struct Wrapper<'a>(pub &'a Value);
impl TauDocument for Wrapper<'_> {
    fn find(&self, key: &str) -> Option<Tau<'_>> {
        match key {
            // Convenience aliases: let a rule say `Kerberos.cname` / `Kerberos.sname`
            // and resolve to the joined scalar form without worrying about the
            // array-vs-scalar shape.
            "Kerberos.cname" => self
                .0
                .find("Kerberos.cname_string")
                .or_else(|| self.0.find("Kerberos.cname")),
            "Kerberos.sname" => self
                .0
                .find("Kerberos.sname_string")
                .or_else(|| self.0.find("Kerberos.sname")),
            _ => self.0.find(key),
        }
    }
}

// ===========================================================================
// Flow metadata + the Dissector seam
// ===========================================================================

#[derive(Clone, Debug)]
pub struct FlowMeta {
    pub timestamp: String, // %Y-%m-%dT%H:%M:%S%.6fZ
    pub transport: &'static str, // "udp" | "tcp"
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub frame: u64,
}

impl FlowMeta {
    /// Build the common `Network.*` object shared by every document from this flow.
    fn network_object(&self, protocol: &str, length: usize) -> Json {
        json!({
            "timestamp": self.timestamp,
            "protocol": protocol,
            "transport": self.transport,
            "src_ip": self.src_ip.to_string(),
            "dst_ip": self.dst_ip.to_string(),
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "length": length,
            "frame": self.frame,
        })
    }
}

/// An application-layer dissector. Implementations claim one or more L4 ports
/// and turn a (reassembled) application message buffer into zero or more
/// documents. Adding LDAP/SMB/DCERPC — or a tshark-backed backend — means
/// implementing this trait and registering it, not touching the pipeline.
pub trait Dissector: Send + Sync {
    fn claims(&self, port: u16) -> bool;
    fn dissect(&self, meta: &FlowMeta, payload: &[u8]) -> Vec<Json>;
}

// --- Kerberos (REAL) -------------------------------------------------------

pub struct KerberosDissector;
impl Dissector for KerberosDissector {
    fn claims(&self, port: u16) -> bool {
        port == 88
    }
    fn dissect(&self, meta: &FlowMeta, payload: &[u8]) -> Vec<Json> {
        match dissect_kerberos(meta, payload) {
            Some(doc) => vec![doc],
            None => vec![],
        }
    }
}

// --- LDAP / SMB / DCERPC (STUBS) ------------------------------------------
// Intentionally return nothing. They exist to prove the seam and to hold the
// TODO. Register them in `dissectors()` when implemented.

pub struct LdapDissector;
impl Dissector for LdapDissector {
    fn claims(&self, port: u16) -> bool {
        port == 389 || port == 636
    }
    fn dissect(&self, _meta: &FlowMeta, _payload: &[u8]) -> Vec<Json> {
        // TODO: dissect LDAP (bind, search) into `Ldap.*`. LDAP is BER like
        // Kerberos, so the TLV reader below is largely reusable.
        vec![]
    }
}

pub struct SmbDissector;
impl Dissector for SmbDissector {
    fn claims(&self, port: u16) -> bool {
        port == 445
    }
    fn dissect(&self, _meta: &FlowMeta, _payload: &[u8]) -> Vec<Json> {
        // TODO: dissect SMB2 header + a few commands into `Smb.*`.
        vec![]
    }
}

pub struct DcerpcDissector;
impl Dissector for DcerpcDissector {
    fn claims(&self, port: u16) -> bool {
        port == 135
    }
    fn dissect(&self, _meta: &FlowMeta, _payload: &[u8]) -> Vec<Json> {
        // TODO: dissect DCERPC bind/request into `Dcerpc.*` (endpoint mapper +
        // dynamic ports need an epmap-tracking layer).
        vec![]
    }
}

/// The active dissector table. Kerberos is real; the rest are stubs.
fn dissectors() -> Vec<Box<dyn Dissector>> {
    vec![
        Box::new(KerberosDissector),
        Box::new(LdapDissector),
        Box::new(SmbDissector),
        Box::new(DcerpcDissector),
    ]
}

// ===========================================================================
// Capture iteration: pcap-parser -> etherparse -> reassembly -> dissectors
// ===========================================================================

#[derive(Hash, PartialEq, Eq, Clone)]
struct FlowKey {
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
}

/// Parsed L3/L4 view of a single frame.
struct Segment {
    meta: FlowMeta,
    payload: Vec<u8>,
    is_tcp: bool,
}

fn dissect_capture(path: &Path) -> crate::Result<Vec<Json>> {
    use pcap_parser::traits::PcapReaderIterator;
    use pcap_parser::{Linktype, PcapBlockOwned, PcapError, create_reader};

    let file = File::open(path)?;
    // API: create_reader auto-detects legacy pcap vs pcapng.
    let mut reader =
        create_reader(65536, file).map_err(|e| anyhow!("failed to open capture: {:?}", e))?;

    let table = dissectors();
    let mut out: Vec<Json> = Vec::new();
    // Per-flow TCP reassembly buffers (arrival order; see ADR §7 for limits).
    let mut tcp_buffers: HashMap<FlowKey, Vec<u8>> = HashMap::new();

    // Current link-layer type; updated by section/interface headers.
    let mut linktype = Linktype::ETHERNET;
    let mut frame: u64 = 0;

    loop {
        match reader.next() {
            Ok((offset, block)) => {
                match block {
                    // Legacy pcap global header carries the single linktype.
                    PcapBlockOwned::LegacyHeader(hdr) => {
                        linktype = hdr.network;
                    }
                    PcapBlockOwned::Legacy(b) => {
                        frame += 1;
                        // API: b.data = captured bytes, b.ts_sec/b.ts_usec (u32).
                        let ts = format_ts(b.ts_sec as i64, b.ts_usec.saturating_mul(1000));
                        handle_frame(
                            linktype,
                            b.data,
                            ts,
                            frame,
                            &table,
                            &mut tcp_buffers,
                            &mut out,
                        );
                    }
                    // pcapng: interface description block carries the linktype.
                    PcapBlockOwned::NG(block) => {
                        use pcap_parser::Block;
                        match block {
                            Block::SectionHeader(_) => {}
                            Block::InterfaceDescription(idb) => {
                                linktype = idb.linktype;
                            }
                            Block::EnhancedPacket(epb) => {
                                frame += 1;
                                // API: pcapng timestamps are (ts_high<<32|ts_low)
                                // in units of if_tsresol (default 1us). We assume
                                // the 1us default here; a production version must
                                // read if_tsresol from the IDB. Documented in ADR.
                                let raw = ((epb.ts_high as u64) << 32) | epb.ts_low as u64;
                                let secs = (raw / 1_000_000) as i64;
                                let nanos = ((raw % 1_000_000) * 1000) as u32;
                                let ts = format_ts(secs, nanos);
                                handle_frame(
                                    linktype,
                                    epb.data,
                                    ts,
                                    frame,
                                    &table,
                                    &mut tcp_buffers,
                                    &mut out,
                                );
                            }
                            Block::SimplePacket(spb) => {
                                frame += 1;
                                // SimplePacket has no timestamp.
                                let ts = format_ts(0, 0);
                                handle_frame(
                                    linktype,
                                    spb.data,
                                    ts,
                                    frame,
                                    &table,
                                    &mut tcp_buffers,
                                    &mut out,
                                );
                            }
                            _ => {}
                        }
                    }
                    _ => {}
                }
                reader.consume(offset);
            }
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete(_)) => {
                // API: refill the internal buffer and retry.
                if reader.refill().is_err() {
                    break;
                }
            }
            Err(e) => {
                return Err(anyhow!("pcap read error: {:?}", e));
            }
        }
    }

    Ok(out)
}

#[allow(clippy::too_many_arguments)]
fn handle_frame(
    linktype: pcap_parser::Linktype,
    data: &[u8],
    timestamp: String,
    frame: u64,
    table: &[Box<dyn Dissector>],
    tcp_buffers: &mut HashMap<FlowKey, Vec<u8>>,
    out: &mut Vec<Json>,
) {
    let seg = match parse_l2_l4(linktype, data, timestamp, frame) {
        Some(s) => s,
        None => return,
    };

    // Only bother with flows some dissector claims (either direction).
    let claimed = table
        .iter()
        .any(|d| d.claims(seg.meta.src_port) || d.claims(seg.meta.dst_port));
    if !claimed {
        return;
    }

    if seg.is_tcp {
        // Reassemble in arrival order, then peel length-prefixed Kerberos msgs.
        let key = FlowKey {
            src_ip: seg.meta.src_ip,
            dst_ip: seg.meta.dst_ip,
            src_port: seg.meta.src_port,
            dst_port: seg.meta.dst_port,
        };
        let buf = tcp_buffers.entry(key).or_default();
        buf.extend_from_slice(&seg.payload);

        // RFC 4120 §7.2.2: each message is prefixed with a 4-byte big-endian
        // length. Pull as many complete messages as the buffer holds.
        loop {
            if buf.len() < 4 {
                break;
            }
            let msg_len =
                u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
            if msg_len == 0 || msg_len > 10 * 1024 * 1024 {
                // Guard against garbage / desync: drop the flow buffer.
                buf.clear();
                break;
            }
            if buf.len() < 4 + msg_len {
                break; // wait for more segments
            }
            let msg: Vec<u8> = buf[4..4 + msg_len].to_vec();
            buf.drain(0..4 + msg_len);
            dispatch(table, &seg.meta, &msg, out);
        }
    } else {
        // UDP: one bare Kerberos message per datagram.
        dispatch(table, &seg.meta, &seg.payload, out);
    }
}

fn dispatch(table: &[Box<dyn Dissector>], meta: &FlowMeta, payload: &[u8], out: &mut Vec<Json>) {
    for d in table {
        if d.claims(meta.src_port) || d.claims(meta.dst_port) {
            out.extend(d.dissect(meta, payload));
        }
    }
}

/// Parse L2..L4 with etherparse and return a `Segment` for UDP/TCP packets.
fn parse_l2_l4(
    linktype: pcap_parser::Linktype,
    data: &[u8],
    timestamp: String,
    frame: u64,
) -> Option<Segment> {
    use etherparse::{NetSlice, SlicedPacket, TransportSlice};

    // API: dispatch on linktype. 1 = Ethernet, 101 = raw IP, 0 = BSD loopback
    // (4-byte address-family header), 12 = raw (some tools). Others skipped.
    let sliced = match linktype.0 {
        1 => SlicedPacket::from_ethernet(data).ok()?,
        101 | 12 => SlicedPacket::from_ip(data).ok()?,
        0 => {
            // BSD loopback / null: 4-byte host-order address family, then IP.
            if data.len() < 4 {
                return None;
            }
            SlicedPacket::from_ip(&data[4..]).ok()?
        }
        _ => return None,
    };

    // L3 addresses.
    let (src_ip, dst_ip): (IpAddr, IpAddr) = match sliced.net? {
        NetSlice::Ipv4(ip) => {
            let h = ip.header();
            (
                IpAddr::from(h.source()),
                IpAddr::from(h.destination()),
            )
        }
        NetSlice::Ipv6(ip) => {
            let h = ip.header();
            (
                IpAddr::from(h.source()),
                IpAddr::from(h.destination()),
            )
        }
        _ => return None,
    };

    // L4 transport + payload.
    let (transport, is_tcp, src_port, dst_port, payload): (&'static str, bool, u16, u16, Vec<u8>) =
        match sliced.transport? {
            TransportSlice::Udp(udp) => (
                "udp",
                false,
                udp.source_port(),
                udp.destination_port(),
                udp.payload().to_vec(),
            ),
            TransportSlice::Tcp(tcp) => (
                "tcp",
                true,
                tcp.source_port(),
                tcp.destination_port(),
                tcp.payload().to_vec(),
            ),
            _ => return None,
        };

    if payload.is_empty() {
        return None;
    }

    Some(Segment {
        meta: FlowMeta {
            timestamp,
            transport,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            frame,
        },
        payload,
        is_tcp,
    })
}

fn format_ts(secs: i64, nanos: u32) -> String {
    use chrono::{DateTime, Utc};
    match DateTime::<Utc>::from_timestamp(secs, nanos) {
        // Matches the format hunt.rs parses: "%Y-%m-%dT%H:%M:%S%.fZ".
        Some(dt) => dt.format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string(),
        None => "1970-01-01T00:00:00.000000Z".to_string(),
    }
}

// ===========================================================================
// Minimal BER/DER reader — only what Kerberos (RFC 4120) uses.
//   definite lengths, low-tag-number application + context tags,
//   INTEGER / OCTET STRING / GeneralizedTime / BIT STRING / SEQUENCE.
// ===========================================================================

const CLASS_UNIVERSAL: u8 = 0;
const CLASS_APPLICATION: u8 = 1;
const CLASS_CONTEXT: u8 = 2;

const UT_INTEGER: u32 = 2;
const UT_BIT_STRING: u32 = 3;
const UT_OCTET_STRING: u32 = 4;
const UT_SEQUENCE: u32 = 16;

struct Tlv<'a> {
    class: u8,
    #[allow(dead_code)]
    constructed: bool,
    tag: u32,
    content: &'a [u8],
}

/// Read one TLV from the front of `buf`. Returns the TLV and the number of
/// bytes consumed, or None on malformed/truncated input.
fn read_tlv(buf: &[u8]) -> Option<(Tlv<'_>, usize)> {
    if buf.is_empty() {
        return None;
    }
    let first = buf[0];
    let class = first >> 6;
    let constructed = first & 0x20 != 0;
    let mut tag = (first & 0x1f) as u32;
    let mut idx = 1;
    if tag == 0x1f {
        // high-tag-number form (not used by Kerberos, handled for safety).
        tag = 0;
        loop {
            let b = *buf.get(idx)?;
            idx += 1;
            tag = (tag << 7) | (b & 0x7f) as u32;
            if b & 0x80 == 0 {
                break;
            }
        }
    }
    let len_byte = *buf.get(idx)?;
    idx += 1;
    let length = if len_byte & 0x80 == 0 {
        (len_byte & 0x7f) as usize
    } else {
        let num = (len_byte & 0x7f) as usize;
        if num == 0 || num > 4 {
            return None; // indefinite or implausibly long
        }
        let mut l = 0usize;
        for _ in 0..num {
            let b = *buf.get(idx)?;
            idx += 1;
            l = (l << 8) | b as usize;
        }
        l
    };
    let end = idx.checked_add(length)?;
    if end > buf.len() {
        return None;
    }
    Some((
        Tlv {
            class,
            constructed,
            tag,
            content: &buf[idx..end],
        },
        end,
    ))
}

/// Children of a constructed TLV content buffer.
fn children(content: &[u8]) -> Vec<Tlv<'_>> {
    let mut v = Vec::new();
    let mut rest = content;
    while !rest.is_empty() {
        match read_tlv(rest) {
            Some((tlv, consumed)) => {
                v.push(tlv);
                rest = &rest[consumed..];
            }
            None => break,
        }
    }
    v
}

/// Find a context-tagged `[n]` child among `kids`.
fn ctx<'a, 'b>(kids: &'a [Tlv<'b>], n: u32) -> Option<&'a Tlv<'b>> {
    kids.iter().find(|t| t.class == CLASS_CONTEXT && t.tag == n)
}

/// Unwrap an explicitly tagged context element to its single inner TLV.
/// The returned TLV borrows the *data* (lifetime `'a`), not the `&tlv` ref, so
/// callers can drop the reference and keep the inner TLV.
fn inner<'a>(tlv: &Tlv<'a>) -> Option<Tlv<'a>> {
    read_tlv(tlv.content).map(|(t, _)| t)
}

fn read_integer(content: &[u8]) -> Option<i64> {
    if content.is_empty() || content.len() > 8 {
        return None;
    }
    let mut v: i64 = if content[0] & 0x80 != 0 { -1 } else { 0 };
    for &b in content {
        v = (v << 8) | b as i64;
    }
    Some(v)
}

/// Read an INTEGER that lives behind an explicit context tag `[n]`.
fn read_ctx_int(kids: &[Tlv<'_>], n: u32) -> Option<i64> {
    let el = ctx(kids, n)?;
    let prim = inner(el)?;
    if prim.class == CLASS_UNIVERSAL && prim.tag == UT_INTEGER {
        read_integer(prim.content)
    } else {
        None
    }
}

/// Read a string (GeneralizedTime / GeneralString / IA5 etc.) behind `[n]`.
fn read_ctx_string(kids: &[Tlv<'_>], n: u32) -> Option<String> {
    let el = ctx(kids, n)?;
    let prim = inner(el)?;
    Some(String::from_utf8_lossy(prim.content).to_string())
}

/// PrincipalName ::= SEQUENCE { name-type[0] Int32, name-string[1] SEQ OF String }
/// Returns (name-type, components).
fn read_principal(el: &Tlv<'_>) -> Option<(i64, Vec<String>)> {
    let seq = inner(el)?; // SEQUENCE
    let kids = children(seq.content);
    let ntype = read_ctx_int(&kids, 0).unwrap_or(0);
    let names_el = ctx(&kids, 1)?;
    let names_seq = inner(names_el)?; // SEQUENCE OF
    let mut names = Vec::new();
    for k in children(names_seq.content) {
        names.push(String::from_utf8_lossy(k.content).to_string());
    }
    Some((ntype, names))
}

/// KDCOptions / APOptions bit-string flag names (bit 0 = MSB).
fn decode_kdc_flags(bits: u32) -> Vec<&'static str> {
    const FLAGS: &[(u32, &str)] = &[
        (1, "forwardable"),
        (2, "forwarded"),
        (3, "proxiable"),
        (4, "proxy"),
        (5, "allow-postdate"),
        (6, "postdated"),
        (8, "renewable"),
        (9, "opt-hardware-auth"),
        (14, "constrained-delegation"),
        (15, "canonicalize"),
        (26, "disable-transited-check"),
        (27, "renewable-ok"),
        (28, "enc-tkt-in-skey"),
        (30, "renew"),
        (31, "validate"),
    ];
    FLAGS
        .iter()
        .filter(|(bit, _)| bits & (0x8000_0000u32 >> bit) != 0)
        .map(|(_, name)| *name)
        .collect()
}

/// A BIT STRING carrying 32 option bits: content = [unused-bits][4 bytes].
fn read_option_bits(el: &Tlv<'_>) -> Option<u32> {
    let prim = inner(el)?;
    if prim.class != CLASS_UNIVERSAL || prim.tag != UT_BIT_STRING {
        return None;
    }
    let c = prim.content;
    if c.len() < 5 {
        return None;
    }
    // c[0] = unused bits; c[1..5] = the 32 option bits, big-endian.
    Some(u32::from_be_bytes([c[1], c[2], c[3], c[4]]))
}

fn msg_type_name(t: i64) -> &'static str {
    match t {
        10 => "AS-REQ",
        11 => "AS-REP",
        12 => "TGS-REQ",
        13 => "TGS-REP",
        14 => "AP-REQ",
        15 => "AP-REP",
        30 => "KRB-ERROR",
        _ => "UNKNOWN",
    }
}

// ===========================================================================
// Kerberos dissection
// ===========================================================================

fn dissect_kerberos(meta: &FlowMeta, msg: &[u8]) -> Option<Json> {
    let (app, _) = read_tlv(msg)?;
    if app.class != CLASS_APPLICATION {
        return None;
    }
    let app_tag = app.tag;

    let mut k = serde_json::Map::new();
    k.insert("msg_type".into(), json!(app_tag));
    k.insert("msg_type_name".into(), json!(msg_type_name(app_tag as i64)));

    // The APPLICATION tag wraps a universal SEQUENCE.
    let seq = inner(&app)?;
    if seq.class != CLASS_UNIVERSAL || seq.tag != UT_SEQUENCE {
        return None;
    }
    let kids = children(seq.content);

    match app_tag {
        10 | 12 => parse_kdc_req(&kids, &mut k),
        11 | 13 => parse_kdc_rep(&kids, &mut k),
        14 => parse_ap_req(&kids, &mut k),
        30 => parse_krb_error(&kids, &mut k),
        _ => return None,
    }

    let network = meta.network_object("kerberos", msg.len());
    Some(json!({ "Network": network, "Kerberos": Json::Object(k) }))
}

/// KDC-REQ ::= SEQUENCE { pvno[1], msg-type[2], padata[3] OPT, req-body[4] }
fn parse_kdc_req(kids: &[Tlv<'_>], k: &mut serde_json::Map<String, Json>) {
    if let Some(p) = read_ctx_int(kids, 1) {
        k.insert("pvno".into(), json!(p));
    }
    if let Some(mt) = read_ctx_int(kids, 2) {
        // Prefer the inner msg-type (authoritative) over the APPLICATION tag.
        k.insert("msg_type".into(), json!(mt));
        k.insert("msg_type_name".into(), json!(msg_type_name(mt)));
    }
    if let Some(pd) = ctx(kids, 3) {
        parse_padata(pd, k);
    }
    if let Some(body_el) = ctx(kids, 4) {
        parse_req_body(body_el, k);
    }
}

/// KDC-REQ-BODY ::= SEQUENCE {
///   kdc-options[0], cname[1] OPT, realm[2], sname[3] OPT, from[4] OPT,
///   till[5], rtime[6] OPT, nonce[7], etype[8] SEQ OF Int32, ... }
fn parse_req_body(body_el: &Tlv<'_>, k: &mut serde_json::Map<String, Json>) {
    let body = match inner(body_el) {
        Some(b) => b,
        None => return,
    };
    let kids = children(body.content);

    if let Some(opts_el) = ctx(&kids, 0)
        && let Some(bits) = read_option_bits(opts_el)
    {
        k.insert("kdc_options".into(), json!(format!("{:08x}", bits)));
        k.insert("kdc_options_flags".into(), json!(decode_kdc_flags(bits)));
    }
    if let Some(cn) = ctx(&kids, 1)
        && let Some((ntype, names)) = read_principal(cn)
    {
        k.insert("cname_type".into(), json!(ntype));
        k.insert("cname_string".into(), json!(names.join("/")));
        k.insert("cname".into(), json!(names));
    }
    if let Some(r) = read_ctx_string(&kids, 2) {
        k.insert("realm".into(), json!(r));
    }
    if let Some(sn) = ctx(&kids, 3)
        && let Some((ntype, names)) = read_principal(sn)
    {
        k.insert("sname_type".into(), json!(ntype));
        k.insert("sname_string".into(), json!(names.join("/")));
        k.insert("sname".into(), json!(names));
    }
    if let Some(s) = read_ctx_string(&kids, 4) {
        k.insert("from".into(), json!(s));
    }
    if let Some(s) = read_ctx_string(&kids, 5) {
        k.insert("till".into(), json!(s));
    }
    if let Some(s) = read_ctx_string(&kids, 6) {
        k.insert("rtime".into(), json!(s));
    }
    if let Some(n) = read_ctx_int(&kids, 7) {
        // nonce is a UInt32; expose unsigned.
        k.insert("nonce".into(), json!(n as u32));
    }
    if let Some(etype_el) = ctx(&kids, 8)
        && let Some(seq) = inner(etype_el)
    {
        let mut etypes: Vec<i64> = Vec::new();
        for c in children(seq.content) {
            if c.class == CLASS_UNIVERSAL && c.tag == UT_INTEGER {
                if let Some(v) = read_integer(c.content) {
                    etypes.push(v);
                }
            }
        }
        if let Some(first) = etypes.first() {
            k.insert("etype_first".into(), json!(first));
        }
        k.insert("etype_count".into(), json!(etypes.len()));
        k.insert("etypes".into(), json!(etypes));
    }
}

/// KDC-REP ::= SEQUENCE {
///   pvno[0], msg-type[1], padata[2] OPT, crealm[3], cname[4], ticket[5],
///   enc-part[6] EncryptedData }
fn parse_kdc_rep(kids: &[Tlv<'_>], k: &mut serde_json::Map<String, Json>) {
    if let Some(p) = read_ctx_int(kids, 0) {
        k.insert("pvno".into(), json!(p));
    }
    if let Some(mt) = read_ctx_int(kids, 1) {
        k.insert("msg_type".into(), json!(mt));
        k.insert("msg_type_name".into(), json!(msg_type_name(mt)));
    }
    if let Some(pd) = ctx(kids, 2) {
        parse_padata(pd, k);
    }
    if let Some(r) = read_ctx_string(kids, 3) {
        k.insert("realm".into(), json!(r));
    }
    if let Some(cn) = ctx(kids, 4)
        && let Some((ntype, names)) = read_principal(cn)
    {
        k.insert("cname_type".into(), json!(ntype));
        k.insert("cname_string".into(), json!(names.join("/")));
        k.insert("cname".into(), json!(names));
    }
    if let Some(tk) = ctx(kids, 5) {
        parse_ticket(tk, k);
    }
    if let Some(ep) = ctx(kids, 6) {
        parse_enc_part(ep, "enc_part", k);
    }
}

/// AP-REQ ::= SEQUENCE { pvno[0], msg-type[1], ap-options[2], ticket[3],
///   authenticator[4] EncryptedData }
fn parse_ap_req(kids: &[Tlv<'_>], k: &mut serde_json::Map<String, Json>) {
    if let Some(p) = read_ctx_int(kids, 0) {
        k.insert("pvno".into(), json!(p));
    }
    if let Some(mt) = read_ctx_int(kids, 1) {
        k.insert("msg_type".into(), json!(mt));
        k.insert("msg_type_name".into(), json!(msg_type_name(mt)));
    }
    if let Some(opts_el) = ctx(kids, 2)
        && let Some(bits) = read_option_bits(opts_el)
    {
        k.insert("ap_options".into(), json!(format!("{:08x}", bits)));
    }
    if let Some(tk) = ctx(kids, 3) {
        parse_ticket(tk, k);
    }
    if let Some(auth) = ctx(kids, 4) {
        // authenticator is EncryptedData; its cipher is the ENCRYPTED
        // authenticator. We expose etype, size and a ciphertext prefix only.
        parse_enc_part(auth, "authenticator", k);
        if let Some(ed) = inner(auth) {
            let ekids = children(ed.content);
            if let Some(cipher_el) = ctx(&ekids, 2)
                && let Some(prim) = inner(cipher_el)
            {
                let n = prim.content.len().min(8);
                let prefix: String =
                    prim.content[..n].iter().map(|b| format!("{:02x}", b)).collect();
                // NB: this is CIPHERTEXT (see ADR §3.2 caveat), exposed because
                // the brief asks for the authenticator sequence "where visible".
                k.insert("authenticator_seq_hex".into(), json!(prefix));
            }
        }
    }
}

/// KRB-ERROR ::= SEQUENCE { pvno[0], msg-type[1], ... error-code[6], ... }
fn parse_krb_error(kids: &[Tlv<'_>], k: &mut serde_json::Map<String, Json>) {
    if let Some(p) = read_ctx_int(kids, 0) {
        k.insert("pvno".into(), json!(p));
    }
    if let Some(mt) = read_ctx_int(kids, 1) {
        k.insert("msg_type".into(), json!(mt));
        k.insert("msg_type_name".into(), json!(msg_type_name(mt)));
    }
    if let Some(ec) = read_ctx_int(kids, 6) {
        k.insert("error_code".into(), json!(ec));
    }
    if let Some(r) = read_ctx_string(kids, 9) {
        k.insert("realm".into(), json!(r));
    }
    if let Some(sn) = ctx(kids, 10)
        && let Some((ntype, names)) = read_principal(sn)
    {
        k.insert("sname_type".into(), json!(ntype));
        k.insert("sname_string".into(), json!(names.join("/")));
        k.insert("sname".into(), json!(names));
    }
}

/// Ticket ::= [APPLICATION 1] SEQUENCE { tkt-vno[0], realm[1], sname[2],
///   enc-part[3] }. We only lift realm + sname (the service the ticket is for).
fn parse_ticket(ticket_ctx: &Tlv<'_>, k: &mut serde_json::Map<String, Json>) {
    let app = match inner(ticket_ctx) {
        Some(a) => a,
        None => return,
    };
    if app.class != CLASS_APPLICATION || app.tag != 1 {
        return;
    }
    let seq = match inner(&app) {
        Some(s) => s,
        None => return,
    };
    let kids = children(seq.content);
    if let Some(r) = read_ctx_string(&kids, 1) {
        k.insert("ticket_realm".into(), json!(r));
    }
    if let Some(sn) = ctx(&kids, 2)
        && let Some((_ntype, names)) = read_principal(sn)
    {
        k.insert("ticket_sname_string".into(), json!(names.join("/")));
    }
}

/// EncryptedData ::= SEQUENCE { etype[0], kvno[1] OPT, cipher[2] OCTET STRING }
fn parse_enc_part(el: &Tlv<'_>, prefix: &str, k: &mut serde_json::Map<String, Json>) {
    let ed = match inner(el) {
        Some(e) => e,
        None => return,
    };
    let kids = children(ed.content);
    if let Some(etype) = read_ctx_int(&kids, 0) {
        k.insert(format!("{}_etype", prefix), json!(etype));
    }
    if let Some(kvno) = read_ctx_int(&kids, 1) {
        k.insert(format!("{}_kvno", prefix), json!(kvno as u32));
    }
    if let Some(cipher_el) = ctx(&kids, 2)
        && let Some(prim) = inner(cipher_el)
    {
        k.insert(format!("{}_size", prefix), json!(prim.content.len()));
    }
}

/// padata [n] -> SEQUENCE OF PA-DATA { padata-type[1], padata-value[2] OCTET }
fn parse_padata(pd_ctx: &Tlv<'_>, k: &mut serde_json::Map<String, Json>) {
    let seq = match inner(pd_ctx) {
        Some(s) => s,
        None => return,
    };
    let mut types: Vec<i64> = Vec::new();
    for pa in children(seq.content) {
        // each PA-DATA is a SEQUENCE
        let pakids = children(pa.content);
        let ptype = match read_ctx_int(&pakids, 1) {
            Some(t) => t,
            None => continue,
        };
        types.push(ptype);
        match ptype {
            128 => {
                k.insert("pa_pac_request".into(), json!(true));
            }
            167 => {
                // PA-PAC-OPTIONS: expose the raw value hex.
                if let Some(v_el) = ctx(&pakids, 2)
                    && let Some(prim) = inner(v_el)
                {
                    let hex: String =
                        prim.content.iter().map(|b| format!("{:02x}", b)).collect();
                    k.insert("pa_pac_options".into(), json!(hex));
                }
            }
            129 => {
                k.insert("pa_for_user".into(), json!(true));
                // Best-effort: pull the S4U2self target principal name.
                if let Some(name) = parse_pa_for_user_name(&pakids) {
                    k.insert("pa_for_user_name".into(), json!(name));
                }
            }
            _ => {}
        }
    }
    k.insert("padata_types".into(), json!(types));
}

/// PA-FOR-USER ::= SEQUENCE { userName[0] PrincipalName, userRealm[1] Realm, ...}
fn parse_pa_for_user_name(pakids: &[Tlv<'_>]) -> Option<String> {
    let v_el = ctx(pakids, 2)?;
    let octet = inner(v_el)?; // OCTET STRING wrapping PA-FOR-USER-ENC
    if octet.class != CLASS_UNIVERSAL || octet.tag != UT_OCTET_STRING {
        return None;
    }
    let (seq, _) = read_tlv(octet.content)?; // SEQUENCE
    let kids = children(seq.content);
    let name_el = ctx(&kids, 0)?; // userName PrincipalName
    let (_ntype, names) = read_principal(name_el)?;
    Some(names.join("/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tlv_short_form() {
        // INTEGER 5 : 02 01 05
        let (t, n) = read_tlv(&[0x02, 0x01, 0x05]).unwrap();
        assert_eq!(n, 3);
        assert_eq!(t.class, CLASS_UNIVERSAL);
        assert_eq!(t.tag, UT_INTEGER);
        assert_eq!(read_integer(t.content), Some(5));
    }

    #[test]
    fn tlv_long_form_length() {
        // OCTET STRING, length 0x81 0x80 (=128), 128 bytes of 0x00
        let mut buf = vec![0x04, 0x81, 0x80];
        buf.extend(std::iter::repeat(0u8).take(128));
        let (t, n) = read_tlv(&buf).unwrap();
        assert_eq!(n, 3 + 128);
        assert_eq!(t.content.len(), 128);
    }

    #[test]
    fn kdc_option_flag_decode() {
        // forwardable (bit 1) + renewable (bit 8) + renewable-ok (bit 27)
        let bits = (0x8000_0000u32 >> 1) | (0x8000_0000u32 >> 8) | (0x8000_0000u32 >> 27);
        let flags = decode_kdc_flags(bits);
        assert!(flags.contains(&"forwardable"));
        assert!(flags.contains(&"renewable"));
        assert!(flags.contains(&"renewable-ok"));
    }

    #[test]
    fn truncated_is_none() {
        assert!(read_tlv(&[0x02, 0x05, 0x01]).is_none()); // claims 5 bytes, has 1
    }
}
