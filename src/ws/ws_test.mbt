///|
test "a close with a status that may not be sent fails the connection with 1002, as RFC 6455 §7.4.1 has it" {
  for status in [0, 999, 1004, 1005, 1006, 1015, 1016, 1100, 2000, 2999, 5000] {
    let reader = @ws.Reader::new()
    let frame : @ws.Frame = {
      fin: true,
      opcode: Close,
      payload: Bytes::from_array([
        (status >> 8).to_byte(),
        (status & 0xff).to_byte(),
      ]),
    }
    let code = try {
      reader.feed(frame) |> ignore
      0
    } catch {
      e => e.status()
    }
    assert_eq(code, 1002)
  }
}

///|
test "the one message ceiling is reached on the reassembled message, with 1009" {
  // `ws` is the single place the ceiling lives. A message split into fragments
  // each well under it would clear every per-frame check and still exhaust
  // memory, so the bound guards the whole message. Remove the check in
  // `Reader::add` and this test goes red — that is the mutation proof the
  // unification asks for.
  let reader = @ws.Reader::new(limit=4)
  let code = try {
    reader.feed({ fin: false, opcode: Text, payload: b"he", }) |> ignore
    reader.feed({ fin: true, opcode: Continuation, payload: b"llo", }) |> ignore
    0
  } catch {
    e => e.status()
  }
  assert_eq(code, 1009)
  // Within the ceiling the fragments reassemble to what was sent.
  let roomy = @ws.Reader::new(limit=100)
  let step = {
    roomy.feed({ fin: false, opcode: Binary, payload: b"he", }) |> ignore
    roomy.feed({ fin: true, opcode: Continuation, payload: b"llo", })
  }
  match step.message {
    Some(Binary(got)) => assert_eq(got, b"hello")
    Some(_) => fail("a binary message came back as something else")
    None => fail("a whole message was not reported")
  }
}
