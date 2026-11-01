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
