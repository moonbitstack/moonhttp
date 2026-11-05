// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// The HTTP/3 SETTINGS an endpoint advertises on its control stream (RFC 9114 §7.2.4): the QPACK
// dynamic-table capacity and blocked-stream limit the peer may use when encoding header fields,
// and the largest header section this endpoint will accept. A control stream must open with a
// SETTINGS frame; this names those settings and reads them off the control stream a peer sends —
// the negotiation curl performs before any request.

///|
/// SETTINGS_QPACK_MAX_TABLE_CAPACITY (RFC 9204 §5).
pub let qpack_capacity : UInt64 = 0x01

///|
/// SETTINGS_MAX_FIELD_SECTION_SIZE (RFC 9114 §7.2.4.1).
pub let max_field_section : UInt64 = 0x06

///|
/// SETTINGS_QPACK_BLOCKED_STREAMS (RFC 9204 §5).
pub let blocked_streams : UInt64 = 0x07

///|
/// SETTINGS_ENABLE_CONNECT_PROTOCOL (RFC 9220 §5): a server sends it as 1 to let a
/// client send `:protocol` on an extended CONNECT, which is how a WebSocket is
/// bootstrapped over HTTP/3. It defaults to 0, so an endpoint that says nothing has
/// not enabled the method.
pub let enable_connect : UInt64 = 0x08

///|
/// An endpoint's HTTP/3 settings.
#derive(Eq, Debug)
pub(all) struct Settings {
  qpack_max_table_capacity : UInt64
  max_field_section_size : UInt64
  qpack_blocked_streams : UInt64
  /// Whether this endpoint lets a peer send `:protocol` (RFC 9220 §5).
  enable_connect_protocol : Bool
}

///|
/// Settings with the given QPACK table capacity, maximum field section size, and blocked-stream
/// limit, and — for a server that will take an extended CONNECT — the connect-protocol switch.
pub fn Settings::new(
  qpack_max_table_capacity : UInt64,
  max_field_section_size : UInt64,
  qpack_blocked_streams : UInt64,
  enable_connect_protocol~ : Bool = false,
) -> Settings {
  {
    qpack_max_table_capacity,
    max_field_section_size,
    qpack_blocked_streams,
    enable_connect_protocol,
  }
}

///|
/// The `(identifier, value)` pairs to carry in a SETTINGS frame.
///
/// The connect switch is written only when it is on: its registry default is 0, so
/// leaving it out says the same thing, and a settings list that carries only what it
/// changed stays the three QPACK values.
pub fn Settings::pairs(self : Settings) -> Array[(UInt64, UInt64)] {
  let out : Array[(UInt64, UInt64)] = [
    (qpack_capacity, self.qpack_max_table_capacity),
    (max_field_section, self.max_field_section_size),
    (blocked_streams, self.qpack_blocked_streams),
  ]
  if self.enable_connect_protocol {
    out.push((enable_connect, 1))
  }
  out
}

///|
/// Read settings from received `(identifier, value)` pairs, taking the value for each known
/// identifier (0 when absent) and ignoring unknown ones (RFC 9114 §7.2.4.1 grease tolerance).
pub fn Settings::of_pairs(pairs : Array[(UInt64, UInt64)]) -> Settings {
  let mut qmtc = 0UL
  let mut mfss = 0UL
  let mut qbs = 0UL
  let mut ecp = false
  for p in pairs {
    if p.0 == qpack_capacity {
      qmtc = p.1
    } else if p.0 == max_field_section {
      mfss = p.1
    } else if p.0 == blocked_streams {
      qbs = p.1
    } else if p.0 == enable_connect {
      // §5: only 1 turns it on; any other value is not one this reader acts on.
      ecp = p.1 == 1
    }
  }
  {
    qpack_max_table_capacity: qmtc,
    max_field_section_size: mfss,
    qpack_blocked_streams: qbs,
    enable_connect_protocol: ecp,
  }
}

///|
/// Whether `id` is one of the HTTP/2 settings that HTTP/3 reserves and refuses
/// (RFC 9114 §7.2.4.1, §11.2.2): ENABLE_PUSH, MAX_CONCURRENT_STREAMS, INITIAL_WINDOW_SIZE and
/// MAX_FRAME_SIZE. The other two HTTP/2 identifiers — HEADER_TABLE_SIZE (0x1) and
/// MAX_HEADER_LIST_SIZE (0x6) — are QPACK's capacity and this protocol's field section size.
fn is_http2_setting(id : UInt64) -> Bool {
  id == 0x02 || id == 0x03 || id == 0x04 || id == 0x05
}

///|
/// Decode a SETTINGS payload into its `(identifier, value)` pairs.
///
/// Three things in §7.2.4.1 end the connection: a payload that stops between an identifier and
/// its value (H3_FRAME_ERROR, §7.1), an identifier HTTP/2 defined and HTTP/3 has no use for, and
/// the same identifier twice (both H3_SETTINGS_ERROR). Reading does not stop at an identifier
/// this endpoint does not know — §7.2.4.1 reserves ranges for a peer to exercise, and whatever
/// follows one is read as usual.
pub fn read_settings(payload : Bytes) -> Array[(UInt64, UInt64)] raise Refused {
  let pairs : Array[(UInt64, UInt64)] = []
  let seen : Array[UInt64] = []
  let view = payload[:]
  let mut off = 0
  let n = view.length()
  while off < n {
    let (id, id_len) = match @quic.decode(view[off:]) {
      Some(v) => v
      None =>
        raise fault(
          FrameError,
          "a SETTINGS frame ending between an identifier and its value",
        )
    }
    off += id_len
    let (value, val_len) = match @quic.decode(view[off:]) {
      Some(v) => v
      None =>
        raise fault(
          FrameError,
          "a SETTINGS frame ending between an identifier and its value",
        )
    }
    off += val_len
    if is_http2_setting(id) {
      raise fault(
        SettingsError,
        "the HTTP/2 setting 0x\{id}, which HTTP/3 reserves (RFC 9114 §7.2.4.1)",
      )
    }
    if seen.contains(id) {
      raise fault(
        SettingsError,
        "the setting 0x\{id} sent twice (RFC 9114 §7.2.4.1)",
      )
    }
    seen.push(id)
    pairs.push((id, value))
  }
  pairs
}

///|
/// Decode an endpoint's control stream (RFC 9114 §6.2.1): its type prefix must be the control
/// stream, and its first frame a SETTINGS frame, whose settings are returned. `None` if the
/// stream is not a control stream or does not open with SETTINGS. Raises on a malformed frame.
pub fn read_control(input : BytesView) -> Settings? raise Refused {
  match Stream::decode(input) {
    Some((ControlKind, consumed)) => {
      let (frames, _) = decode_all(input[consumed:].to_owned())
      if frames.length() > 0 {
        match frames[0] {
          Settings(pairs) => Some(Settings::of_pairs(pairs))
          _ => None
        }
      } else {
        None
      }
    }
    _ => None
  }
}

///|
pub extend Settings with Debug::{to_repr}

///|
pub extend Settings with Eq::{not_equal, equal}
