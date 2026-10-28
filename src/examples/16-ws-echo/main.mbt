// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// A WebSocket echo endpoint, which is the only shape Autobahn's fuzzingclient
/// knows how to test: it sends a message and expects the same one back, and where
/// a message is not allowed it expects the connection to fail with a status.
///
///     moon run src/examples/16-ws-echo            # listening on 127.0.0.1:9001
///     scripts/autobahn/run.sh                     # and Autobahn against it
///
/// Everything a protocol decides is decided by this library: the handshake is
/// `upgrade`, the frames are `ws`, and the compression is `pmd`. The socket is
/// `moonbitlang/async`, which is where a connection belongs — there is none in the
/// library, and that is the point of it.
async fn main {
  let addr = @socket.Addr::parse("127.0.0.1:9001") catch {
    _ => {
      println("not an address: 127.0.0.1:9001")
      return
    }
  }
  let server = @socket.TcpServer(addr, reuse_addr=true)
  println("listening on " + addr.to_string())
  server.run_forever((conn, _) => serve(conn))
}

///|
/// One connection, from the opening handshake to the close.
async fn serve(conn : @socket.Tcp) -> Unit {
  let inbox = Buffer()
  let at = match read_head(conn, inbox) {
    Some(at) => at
    None => {
      conn.close()
      return
    }
  }
  let request = @http1.request(inbox.to_bytes()[:at]).0 catch {
      _ => {
        let _ = conn.write(reject())
        conn.close()
        return
      }
    }
  let fields : Array[(String, String)] = []
  for field in request.fields {
    fields.push(field.ascii())
  }
  let (key, offered) = @upgrade.read_request(fields[:]) catch {
    _ => {
      let _ = conn.write(reject())
      conn.close()
      return
    }
  }
  // The client's extension offer, and the terms this server answers with. No
  // offer means no compression rather than no connection.
  let offers = match header(fields, "sec-websocket-extensions") {
    Some(value) => @pmd.offers(value[:])
    None => []
  }
  let agreed = @pmd.Extension::agree(offers[:])
  let extra : Array[(String, String)] = match agreed {
    Some(terms) =>
      [("Sec-WebSocket-Extensions", terms.encode(role=@pmd.Role::Server))]
    None => []
  }
  // The handshake's octets are not the first frame's: whatever arrived with them
  // belongs to the first frame, and the head itself belongs to `http1`.
  let rest = inbox.to_bytes()[at:].to_owned()
  inbox.reset()
  inbox.write_bytes(rest[:])
  let protocol = @upgrade.subprotocol(offered[:], ["echo"])
  let response = match protocol {
    Some(name) => @upgrade.response(key, protocol=name, extra~)
    None => @upgrade.response(key, extra~)
  }
  let _ = conn.write(response)
  echo(conn, inbox, agreed)
  conn.close()
}

///|
/// The message loop: frames in, the same messages out, until the connection is
/// closed or fails.
async fn echo(
  conn : @socket.Tcp,
  inbox : Buffer,
  agreed : @pmd.Extension?,
) -> Unit {
  let reader = match agreed {
    Some(terms) => @pmd.Reader::new(extension=terms)
    None => @pmd.Reader::new()
  }
  let writer = match agreed {
    Some(terms) => @pmd.Writer::new(extension=terms)
    None => @pmd.Writer::new()
  }
  // Bytes that arrived with the handshake belong to the first frame.
  let mut buffer = inbox.to_bytes()
  let mut status : Int32? = None
  let mut running = true
  while running && status is None {
    let mut progressed = true
    while progressed && status is None {
      progressed = false
      let decoded = @ws.decode_extension(buffer[:], client=true) catch {
        e => {
          status = Some(e.status())
          None
        }
      }
      match decoded {
        None => ()
        Some((frame, used, compressed)) => {
          progressed = true
          buffer = buffer[used:].to_owned()
          let step = reader.feed(frame, compressed~) catch {
            e => {
              status = Some(e.status())
              { message: None, reply: None, }
            }
          }
          let out = Buffer()
          match step.reply {
            Some(reply) => out.write_bytes(reply.encode())
            None => ()
          }
          match step.message {
            Some(@ws.Message::Text(text)) => {
              let (frame, compressed) = writer.frame(
                @ws.Opcode::Text,
                @utf8.encode(text)[:],
              )
              out.write_bytes(frame.encode_extension(rsv1=compressed))
            }
            Some(@ws.Message::Binary(data)) => {
              let (frame, compressed) = writer.frame(
                @ws.Opcode::Binary,
                data[:],
              )
              out.write_bytes(frame.encode_extension(rsv1=compressed))
            }
            Some(@ws.Message::Close(..)) => running = false
            None => ()
          }
          if out.length() > 0 {
            let _ = conn.write(out.to_bytes())
          }
        }
      }
    }
    if status is None && running {
      match conn.read_some(max_len=65536) {
        None => running = false
        Some(bytes) => buffer = buffer + bytes
      }
    }
  }
  // A connection that broke is failed with the status the break earns, and then
  // closed: RFC 6455 §7.1.7.
  match status {
    Some(code) => {
      let frame : @ws.Frame = {
        fin: true,
        opcode: @ws.Opcode::Close,
        payload: @ws.close(code),
      }
      let _ = conn.write(frame.encode())
    }
    None => ()
  }
}

///|
/// Read until the request head ends, answering how many octets it took.
///
/// The opening handshake has no body, so the head is the whole message and
/// whatever follows it in `inbox` belongs to the first frame.
async fn read_head(conn : @socket.Tcp, inbox : Buffer) -> Int32? {
  while true {
    match end_of_head(inbox.to_bytes()) {
      Some(at) => return Some(at)
      None => ()
    }
    match conn.read_some(max_len=8192) {
      None => return None
      Some(more) => inbox.write_bytes(more[:])
    }
  }
  None
}

///|
/// A 400, which is what a request that is not a WebSocket handshake earns.
fn reject() -> Bytes {
  @http1.Response::of(
    400,
    fields=[@header.Header::of("Content-Length", "0")],
    reason="Bad Request",
  ).encode()
}

///|
/// Where `\r\n\r\n` ends, which is where a request head ends.
fn end_of_head(bytes : Bytes) -> Int32? {
  let mut i = 0
  while i + 4 <= bytes.length() {
    if bytes[i] == b'\r' &&
      bytes[i + 1] == b'\n' &&
      bytes[i + 2] == b'\r' &&
      bytes[i + 3] == b'\n' {
      return Some(i + 4)
    }
    i += 1
  }
  None
}

///|
/// The first field of that name, matched without regard to case.
fn header(fields : Array[(String, String)], name : String) -> String? {
  for (field, value) in fields {
    if lower(field) == name {
      return Some(value)
    }
  }
  None
}

///|
fn lower(text : String) -> String {
  let out = StringBuilder()
  for c in text {
    let n = c.to_int()
    out.write_char(
      if n >= 0x41 && n <= 0x5a {
        (n + 32).unsafe_to_char()
      } else {
        c
      },
    )
  }
  out.to_string()
}
