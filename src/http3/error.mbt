// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// The errors that end a connection (RFC 9114 §8.1) or a QPACK stream (RFC 9204 §6). All of
// them are connection errors: after one, the two ends disagree about what the streams mean, and
// dropping a single stream cannot put them back in step. So every refusal carries the code the
// peer is to be told, and the caller closes the connection with it.

///|
/// The code a connection is closed with (RFC 9114 §8.1, RFC 9204 §6).
///
/// The numbers are the registries' own, so what this package names in a refusal is what a peer
/// reads off the wire.
#derive(Eq, Debug)
pub(all) enum Code {
  /// No error; a connection that simply ends.
  NoError
  /// A fault no other code names, and the one an unprejudiced refusal carries.
  GeneralProtocolError
  /// The endpoint hit a fault of its own.
  InternalError
  /// A unidirectional stream that may exist only once was opened again, or a stream
  /// that may not exist at all was opened.
  StreamCreationError
  /// A stream the connection needs for as long as it lasts was closed.
  ClosedCriticalStream
  /// A frame arrived on a stream that does not carry it, or in an order it may not take.
  FrameUnexpected
  /// A frame could not be read: an incomplete field, a length that does not add up.
  FrameError
  /// A peer asked this endpoint to hold more than it is willing to.
  ExcessiveLoad
  /// A push id that was never promised, or one used twice.
  IdError
  /// A SETTINGS frame is not what the protocol allows.
  SettingsError
  /// A control stream opened with something other than SETTINGS.
  MissingSettings
  /// A request this endpoint will not serve.
  RequestRejected
  /// A request the client abandoned.
  RequestCancelled
  /// A request stream ended before the request did.
  RequestIncomplete
  /// A request or response is malformed (RFC 9114 §4.1.2).
  MessageError
  /// The CONNECT method or its extended form was misused (RFC 9220 §5).
  ConnectError
  /// The version asked for is not one this endpoint serves.
  VersionFallback
  /// A field section could not be decoded (RFC 9204 §6).
  QpackDecompressionFailed
  /// The peer's encoder stream is not what QPACK allows.
  QpackEncoderStreamError
  /// The peer's decoder stream is not what QPACK allows.
  QpackDecoderStreamError
}

///|
/// The number this code is written with on the wire.
pub fn Code::code(self : Code) -> UInt64 {
  match self {
    NoError => 0x100UL
    GeneralProtocolError => 0x101UL
    InternalError => 0x102UL
    StreamCreationError => 0x103UL
    ClosedCriticalStream => 0x104UL
    FrameUnexpected => 0x105UL
    FrameError => 0x106UL
    ExcessiveLoad => 0x107UL
    IdError => 0x108UL
    SettingsError => 0x109UL
    MissingSettings => 0x10aUL
    RequestRejected => 0x10bUL
    RequestCancelled => 0x10cUL
    RequestIncomplete => 0x10dUL
    MessageError => 0x10eUL
    ConnectError => 0x10fUL
    VersionFallback => 0x110UL
    QpackDecompressionFailed => 0x200UL
    QpackEncoderStreamError => 0x201UL
    QpackDecoderStreamError => 0x202UL
  }
}

///|
/// The name the RFC registers this code under, for a refusal's message.
pub fn Code::label(self : Code) -> String {
  match self {
    NoError => "H3_NO_ERROR"
    GeneralProtocolError => "H3_GENERAL_PROTOCOL_ERROR"
    InternalError => "H3_INTERNAL_ERROR"
    StreamCreationError => "H3_STREAM_CREATION_ERROR"
    ClosedCriticalStream => "H3_CLOSED_CRITICAL_STREAM"
    FrameUnexpected => "H3_FRAME_UNEXPECTED"
    FrameError => "H3_FRAME_ERROR"
    ExcessiveLoad => "H3_EXCESSIVE_LOAD"
    IdError => "H3_ID_ERROR"
    SettingsError => "H3_SETTINGS_ERROR"
    MissingSettings => "H3_MISSING_SETTINGS"
    RequestRejected => "H3_REQUEST_REJECTED"
    RequestCancelled => "H3_REQUEST_CANCELLED"
    RequestIncomplete => "H3_REQUEST_INCOMPLETE"
    MessageError => "H3_MESSAGE_ERROR"
    ConnectError => "H3_CONNECT_ERROR"
    VersionFallback => "H3_VERSION_FALLBACK"
    QpackDecompressionFailed => "QPACK_DECOMPRESSION_FAILED"
    QpackEncoderStreamError => "QPACK_ENCODER_STREAM_ERROR"
    QpackDecoderStreamError => "QPACK_DECODER_STREAM_ERROR"
  }
}

///|
/// Why a frame, a stream or a connection was refused.
///
/// One type for every case because the answer to every one of them is the same — close the
/// connection — and the code says which it was.
#derive(Eq, Debug)
pub(all) suberror Refused {
  /// A fault whose code the caller decides, for what the protocol leaves open.
  Malformed(String)
  /// A fault with the connection error the protocol names for it.
  Fault(code~ : Code, detail~ : String)
}

///|
/// The code this refusal closes the connection with. An unprejudiced refusal is
/// `GeneralProtocolError`, the code RFC 9114 §8.1 keeps for what no other names.
pub fn Refused::code(self : Refused) -> Code {
  match self {
    Malformed(_) => GeneralProtocolError
    Fault(code~, ..) => code
  }
}

///|
/// A refusal prints as the code it closes with and why.
pub impl Show for Refused with fn output(self, logger) {
  match self {
    Malformed(m) => logger.write_string("Malformed(" + m + ")")
    Fault(code~, detail~) =>
      logger.write_string(code.label() + "(" + detail + ")")
  }
}

///|
pub extend Code with Debug::{to_repr}

///|
pub extend Code with Eq::{not_equal, equal}

///|
pub extend Refused with Debug::{to_repr}

///|
pub extend Refused with Show::{to_string, output}

///|
pub extend Refused with Eq::{not_equal, equal}

///|
/// A refusal of `code` with `detail` saying which rule it broke.
fn fault(code : Code, detail : String) -> Refused {
  Fault(code~, detail~)
}
