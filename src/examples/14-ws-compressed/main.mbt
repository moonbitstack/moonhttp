// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// Negotiating permessage-deflate, compressing a message, and reading it back —
/// which is the whole of what the extension does to a connection.
///
///     moon run src/examples/14-ws-compressed
#coverage.skip
fn main raise {
  // The client offers it twice, once naming the parameter it understands. The
  // server takes the first offer it can accept, which is the client's preference.
  let offer = "permessage-deflate; client_max_window_bits=9, permessage-deflate"
  let offers = @pmd.offers(offer[:])
  println("offer      -> " + offer)
  let agreed = match @pmd.Extension::agree(offers[:]) {
    Some(terms) => terms
    None => {
      println("declined   -> nothing in common")
      return
    }
  }
  println("answer     -> " + agreed.encode(role=@pmd.Role::Server))
  println(
    "windows    -> server \{agreed.server_window} bits, client \{agreed.client_window} bits",
  )

  // A server's message, compressed with the window it agreed to.
  let writer = @pmd.Writer::new(extension=agreed, role=@pmd.Role::Server)
  let payload = text(400)
  let (frame, compressed) = writer.frame(@ws.Opcode::Text, payload[:])
  let wire = frame.encode_extension(rsv1=compressed)
  println("message    -> \{payload.length()} octets")
  println(
    "frame      -> \{frame.payload.length()} octets, RSV1 \{if compressed { "set" } else { "clear" }}, \{wire.length()} on the wire",
  )

  // And the client reading it: the frame comes off the wire, the bit comes with
  // it, and the reader turns it back into the message that was sent.
  let (decoded, _, rsv1) = match @ws.decode_extension(wire[:], client=false) {
    Some(triple) => triple
    None => {
      println("incomplete -> the frame has not all arrived")
      return
    }
  }
  let reader = @pmd.Reader::new(extension=agreed, role=@pmd.Role::Client)
  let step = reader.feed(decoded, compressed=rsv1)
  match step.message {
    Some(@ws.Message::Text(back)) =>
      println("read back  -> \{back == @utf8.decode(payload[:])} the same text")
    Some(_) => println("read back  -> something else")
    None => println("read back  -> not a whole message")
  }
}

///|
/// Text that repeats, which is what a compressor is for.
fn text(n : Int32) -> Bytes {
  let buf = Buffer()
  let words : Array[Bytes] = [b"alpha ", b"bravo ", b"charlie ", b"delta "]
  let mut i = 0
  while buf.length() < n {
    buf.write_bytes(words[i % 4][:])
    i += 1
  }
  buf.to_bytes()[:n].to_owned()
}
