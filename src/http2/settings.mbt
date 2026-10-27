// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// An endpoint's settings (RFC 9113 §6.5.2, RFC 8441 §3).
///
/// `None` is the RFC's "unlimited". The preset is [`settings`]; [`initial`] is what
/// both ends assume before any SETTINGS frame, and so what the peer's settings start
/// from. Build others with [`Settings::new`] or `{ ..settings, max_frame_size: n }`.
pub(all) struct Settings {
  header_table_size : Int32
  enable_push : Bool
  max_concurrent_streams : Int32?
  initial_window_size : Int32
  max_frame_size : Int32
  max_header_list_size : Int32?
  enable_connect_protocol : Bool
} derive(Eq, Debug)

///|
pub extend Settings with Eq::{not_equal, equal}

///|
pub extend Settings with Debug::{to_repr}

///|
/// The value RFC 9113 §6.5.2 gives every setting before an endpoint has said
/// otherwise.
pub let initial : Settings = {
  header_table_size: 4096,
  enable_push: true,
  max_concurrent_streams: None,
  initial_window_size: 65535,
  max_frame_size: 16384,
  max_header_list_size: None,
  enable_connect_protocol: false,
}

///|
/// What a connection advertises unless told otherwise: the RFC's values, with a
/// hundred concurrent streams and 64 KiB of header list.
///
/// Those two are python-hyper h2's own defaults, and a hundred streams is also where
/// nghttp2 and gRPC settle. Left unlimited, every stream a peer opens and never
/// finishes holds memory, and a few octets of HPACK can name one large table entry
/// thousands of times.
pub let settings : Settings = {
  ..initial,
  max_concurrent_streams: Some(100),
  max_header_list_size: Some(65536),
}

///|
/// Settings by name, every one with the preset's value.
pub fn Settings::new(
  header_table_size~ : Int32 = settings.header_table_size,
  enable_push~ : Bool = settings.enable_push,
  max_concurrent_streams~ : Int32? = settings.max_concurrent_streams,
  initial_window_size~ : Int32 = settings.initial_window_size,
  max_frame_size~ : Int32 = settings.max_frame_size,
  max_header_list_size~ : Int32? = settings.max_header_list_size,
  enable_connect_protocol~ : Bool = settings.enable_connect_protocol,
) -> Settings {
  {
    header_table_size,
    enable_push,
    max_concurrent_streams,
    initial_window_size,
    max_frame_size,
    max_header_list_size,
    enable_connect_protocol,
  }
}

///|
/// Why these settings cannot be sent, or `None` (RFC 9113 §6.5.2).
fn Settings::fault(self : Settings) -> String? {
  if self.header_table_size < 0 {
    Some("a negative header_table_size")
  } else if self.initial_window_size < 0 {
    Some("an initial_window_size past 2^31 - 1")
  } else if self.max_frame_size < 16384 || self.max_frame_size > 16777215 {
    Some("a max_frame_size outside 16384..16777215")
  } else if self.max_concurrent_streams is Some(n) && n < 0 {
    Some("a negative max_concurrent_streams")
  } else if self.max_header_list_size is Some(n) && n < 0 {
    Some("a negative max_header_list_size")
  } else {
    None
  }
}

///|
/// The parameters of a SETTINGS frame that moves the peer from `base` to `self`.
///
/// A server only ever says `0` for push (§6.5.2), so a server's `enable_push` is
/// sent when it is off and never when it is on. "Unlimited" has no encoding of its
/// own, so going back to it is sent as the largest value the field holds.
fn Settings::pairs(
  self : Settings,
  base : Settings,
  role : Role,
) -> Array[(Int32, Int32)] {
  let out = []
  let unset = (v : Int32?) => v.unwrap_or(-1)
  if self.header_table_size != base.header_table_size {
    out.push((settings_header_table_size, self.header_table_size))
  }
  if self.enable_push != base.enable_push &&
    (role is Client || !self.enable_push) {
    out.push((settings_enable_push, if self.enable_push { 1 } else { 0 }))
  }
  if self.max_concurrent_streams != base.max_concurrent_streams {
    out.push(
      (settings_max_concurrent_streams, unset(self.max_concurrent_streams)),
    )
  }
  if self.initial_window_size != base.initial_window_size {
    out.push((settings_initial_window_size, self.initial_window_size))
  }
  if self.max_frame_size != base.max_frame_size {
    out.push((settings_max_frame_size, self.max_frame_size))
  }
  if self.max_header_list_size != base.max_header_list_size {
    out.push((settings_max_header_list_size, unset(self.max_header_list_size)))
  }
  if self.enable_connect_protocol != base.enable_connect_protocol {
    out.push(
      (
        settings_enable_connect_protocol,
        if self.enable_connect_protocol {
          1
        } else {
          0
        },
      ),
    )
  }
  out
}

///|
/// `self` with the parameters of a received SETTINGS frame applied, or why they
/// break the connection, with the error code to say so in (RFC 9113 §6.5.2).
///
/// Values arrive as 32 bits; one past 2^31 - 1 reads negative here, which for a
/// limit means as good as unlimited. Unknown identifiers are ignored (§6.5.2).
fn Settings::merge(
  self : Settings,
  params : Array[(Int32, Int32)],
  role : Role,
) -> Result[Settings, (Int32, String)] {
  let mut s = self
  let limit = (v : Int32) => if v < 0 { None } else { Some(v) }
  for p in params {
    let (id, v) = p
    if id == settings_header_table_size {
      s = { ..s, header_table_size: if v < 0 { 0x7FFFFFFF } else { v }, }
    } else if id == settings_enable_push {
      if v != 0 && v != 1 {
        return Err((error_protocol_error, "SETTINGS_ENABLE_PUSH is 0 or 1"))
      }
      if v == 1 && role is Client {
        return Err((error_protocol_error, "a server may not enable push"))
      }
      s = { ..s, enable_push: v == 1, }
    } else if id == settings_max_concurrent_streams {
      s = { ..s, max_concurrent_streams: limit(v), }
    } else if id == settings_initial_window_size {
      if v < 0 {
        return Err(
          (
            error_flow_control_error, "SETTINGS_INITIAL_WINDOW_SIZE past 2^31 - 1",
          ),
        )
      }
      s = { ..s, initial_window_size: v, }
    } else if id == settings_max_frame_size {
      if v < 16384 || v > 16777215 {
        return Err(
          (
            error_protocol_error, "SETTINGS_MAX_FRAME_SIZE outside 16384..16777215",
          ),
        )
      }
      s = { ..s, max_frame_size: v, }
    } else if id == settings_max_header_list_size {
      s = { ..s, max_header_list_size: limit(v), }
    } else if id == settings_enable_connect_protocol {
      if v != 0 && v != 1 {
        return Err(
          (error_protocol_error, "SETTINGS_ENABLE_CONNECT_PROTOCOL is 0 or 1"),
        )
      }
      // RFC 8441 §3: once on, it stays on.
      if v == 0 && s.enable_connect_protocol {
        return Err(
          (error_protocol_error, "SETTINGS_ENABLE_CONNECT_PROTOCOL turned off"),
        )
      }
      s = { ..s, enable_connect_protocol: v == 1, }
    }
  }
  Ok(s)
}
