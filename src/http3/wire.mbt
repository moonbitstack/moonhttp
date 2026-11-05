// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// The three unidirectional streams a connection reads from its peer, each a state machine over the
// bytes that arrive (RFC 9114 §6.2.1, RFC 9204 §4.2, §4.3, §4.4). They are separate types because
// what may appear on each is different and none of them may ever be closed: the control stream
// opens with the peer's SETTINGS and then carries the connection frames; the encoder stream
// carries the dynamic table's instructions and is the one place a table capacity may be set; the
// decoder stream carries the acknowledgements that let this endpoint reclaim table space, and
// nothing else.
//
// Each reader holds the tail of an instruction whose end has not arrived, and answers with the
// fault the stream's own rules name — QPACK_ENCODER_STREAM_ERROR on the encoder stream,
// QPACK_DECODER_STREAM_ERROR on the decoder stream — so that the caller only has to close the
// connection with the code it is handed.

///|
/// A peer's control stream (RFC 9114 §6.2.1).
pub struct Control {
  mut held : Bytes
  mut settings : Settings?
  limit : UInt64
}

///|
/// A reader for a control stream whose frames may not exceed `limit` octets.
pub fn Control::new(limit~ : UInt64 = 16384UL) -> Control {
  { held: b"", settings: None, limit, }
}

///|
/// Take the bytes that just arrived and return the peer's settings once its SETTINGS frame has.
///
/// The first frame must be SETTINGS (H3_MISSING_SETTINGS), and afterwards a second SETTINGS or a
/// frame only a request stream carries is H3_FRAME_UNEXPECTED (§7.2). A frame type this endpoint
/// does not know is ignored wherever it comes, §9 reserving types for a peer to exercise.
pub fn Control::feed(self : Control, bytes : Bytes) -> Settings? raise Refused {
  if bytes.length() > 0 {
    self.held = joined(self.held, bytes)
  }
  for ;; {
    let (frame, used) = match decode(self.held[:], limit=self.limit) {
      Some(v) => v
      None => break
    }
    self.held = self.held[used:].to_owned()
    if self.settings is None {
      match frame {
        Settings(pairs) => self.settings = Some(Settings::of_pairs(pairs))
        Reserved(_, _) => () // §9: a reserved type before SETTINGS says nothing either way
        _ =>
          raise fault(
            MissingSettings,
            "a control stream opening with \{name_of(frame)} (RFC 9114 §6.2.1)",
          )
      }
    } else {
      match frame {
        Settings(_) =>
          raise fault(
            FrameUnexpected,
            "a second SETTINGS frame (RFC 9114 §7.2.4)",
          )
        Data(_) | Headers(_) =>
          raise fault(
            FrameUnexpected,
            "\{name_of(frame)} on the control stream (RFC 9114 §7.2)",
          )
        PushPromise(_, _) =>
          raise fault(
            FrameUnexpected,
            "PUSH_PROMISE on the control stream (RFC 9114 §7.2)",
          )
        _ => ()
      }
    }
  }
  self.settings
}

///|
/// The peer's settings, once its control stream has carried them.
pub fn Control::settings(self : Control) -> Settings? {
  self.settings
}

///|
/// The peer ended its control stream, which §6.2.1 does not allow: the connection has no way to
/// carry GOAWAY or MAX_PUSH_ID afterwards.
pub fn Control::end(_self : Control) -> Unit raise Refused {
  raise fault(
    ClosedCriticalStream,
    "the control stream closed (RFC 9114 §6.2.1)",
  )
}

///|
/// A peer's QPACK encoder stream (RFC 9204 §4.2): the instructions that fill this endpoint's
/// dynamic table.
pub struct Encoder {
  mut held : Bytes
  table : @qpack.Table
  limit : Int32
}

///|
/// A reader for a peer's encoder stream, which may not grow the table past `limit` — the
/// SETTINGS_QPACK_MAX_TABLE_CAPACITY this endpoint advertised.
pub fn Encoder::new(limit~ : Int32 = 0) -> Encoder {
  { held: b"", table: @qpack.Table::new(limit), limit, }
}

///|
/// Take the bytes that just arrived, apply the instructions they complete, and raise
/// QPACK_ENCODER_STREAM_ERROR for anything §4.3 does not allow: a capacity this endpoint did not
/// offer (§4.1.3), or a name index that names no entry.
pub fn Encoder::feed(self : Encoder, bytes : Bytes) -> Unit raise Refused {
  if bytes.length() > 0 {
    self.held = joined(self.held, bytes)
  }
  for ;; {
    let next = Ok(@qpack.Change::decode(self.held[:])) catch { e => Err(e) }
    let (inst, used) = match next {
      Ok(Some(v)) => v
      Ok(None) => break
      Err(e) =>
        raise fault(
          QpackEncoderStreamError,
          "an encoder-stream instruction: \{e.detail()}",
        )
    }
    self.held = self.held[used:].to_owned()
    match inst {
      SetCapacity(capacity) =>
        if capacity > self.limit {
          raise fault(
            QpackEncoderStreamError,
            "a table capacity of \{capacity} over the \{self.limit} advertised (RFC 9204 §4.1.3)",
          )
        }
      _ => ()
    }
    let applied = Ok(self.table.apply(inst)) catch { e => Err(e) }
    match applied {
      Ok(_) => ()
      Err(e) =>
        raise fault(
          QpackEncoderStreamError,
          "an encoder-stream instruction: \{e.detail()}",
        )
    }
  }
}

///|
/// The dynamic table the peer's encoder stream has filled.
pub fn Encoder::table(self : Encoder) -> @qpack.Table {
  self.table
}

///|
/// The peer ended its encoder stream, which §4.2 does not allow — whether or not it stopped in the
/// middle of an instruction.
pub fn Encoder::end(_self : Encoder) -> Unit raise Refused {
  raise fault(
    ClosedCriticalStream,
    "the QPACK encoder stream closed (RFC 9204 §4.2)",
  )
}

///|
/// A peer's QPACK decoder stream (RFC 9204 §4.2): the acknowledgements of the field sections this
/// endpoint encoded.
pub struct Decoder {
  mut held : Bytes
}

///|
/// A reader for a peer's decoder stream.
pub fn Decoder::new() -> Decoder {
  { held: b"", }
}

///|
/// Take the bytes that just arrived and read the acknowledgements they complete. An Insert Count
/// Increment of 0 is QPACK_DECODER_STREAM_ERROR (§4.4.3): it says the section it acknowledges
/// added nothing, which cannot be.
pub fn Decoder::feed(self : Decoder, bytes : Bytes) -> Unit raise Refused {
  if bytes.length() > 0 {
    self.held = joined(self.held, bytes)
  }
  for ;; {
    let next = Ok(@qpack.Ack::decode(self.held[:])) catch { e => Err(e) }
    let (ack, used) = match next {
      Ok(Some(v)) => v
      Ok(None) => break
      Err(e) =>
        raise fault(
          QpackDecoderStreamError,
          "a decoder-stream instruction: \{e.detail()}",
        )
    }
    self.held = self.held[used:].to_owned()
    match ack {
      Increment(increment~) =>
        if increment <= 0 {
          raise fault(
            QpackDecoderStreamError,
            "an Insert Count Increment of \{increment} (RFC 9204 §4.4.3)",
          )
        }
      _ => ()
    }
  }
}

///|
/// The peer ended its decoder stream, which §4.2 does not allow.
pub fn Decoder::end(_self : Decoder) -> Unit raise Refused {
  raise fault(
    ClosedCriticalStream,
    "the QPACK decoder stream closed (RFC 9204 §4.2)",
  )
}
