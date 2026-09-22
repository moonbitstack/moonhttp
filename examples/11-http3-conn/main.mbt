///|
/// HTTP/3 connection setup (RFC 9114 §6.2, §7.2.4): the named SETTINGS map to
/// their identifiers and round-trip on the control stream, an `Http3Conn`
/// demultiplexes the peer's unidirectional streams (establishing its SETTINGS
/// from the peer control stream, classifying the QPACK encoder stream), and the
/// SETTINGS identifier constants are the RFC assignments.
///
///     moon run examples/32-http3-conn --target native
#coverage.skip
fn main {
  run() catch {
    e => println("http3 conn error: \{e}")
  }
}

///|
fn run() -> Unit raise {
  let s = @http3.Settings::new(4096UL, 16384UL, 100UL)
  let ctrl = @http3.control(s.pairs())
  println("control stream type byte = \{ctrl[0].to_int()} (0 = control)")
  match @http3.read_control(ctrl[:]) {
    Some(back) =>
      println(
        "settings: table=\{back.qpack_max_table_capacity.to_string()} max_field=\{back.max_field_section_size.to_string()} blocked=\{back.qpack_blocked_streams.to_string()}",
      )
    None => println("no settings")
  }
  let conn = @http3.Conn::new(
    Server,
    @http3.Settings::new(4096UL, 16384UL, 100UL),
  )
  println("settings established (before peer) = \{conn.settings_established()}")
  let peer = @http3.Settings::new(8192UL, 65536UL, 32UL)
  let ev = conn.accept_uni_stream(@http3.control(peer.pairs()))
  println(
    "peer control stream event = \{uev(ev)}, established now = \{conn.settings_established()}",
  )
  let ev2 = conn.accept_uni_stream((EncoderKind : @http3.Stream).encode())
  println("qpack encoder stream event = \{uev(ev2)}")
  println(
    "settings ids: table=\{@http3.qpack_capacity.to_string()} maxfield=\{@http3.max_field_section.to_string()} blocked=\{@http3.blocked_streams.to_string()}",
  )
}

///|
fn uev(e : @http3.Event) -> String {
  match e {
    ControlEstablished(_) => "control-established"
    QpackEncoder => "qpack-encoder"
    QpackDecoder => "qpack-decoder"
    Push(_) => "push"
    Reserved(_) => "reserved"
  }
}
