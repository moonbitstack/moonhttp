// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// What the encoder costs per octet, on the three shapes a compressed WebSocket
/// message actually has: text that repeats with a short period, English prose,
/// and octets with no structure to find.
///
///     moon run src/examples/17-deflate-throughput --target native --release
///
/// A debug build is an order of magnitude slower and says nothing about the
/// encoder, so the numbers here are worth reading only from a release build.
///
/// Each payload is a hundred and twenty-eight kilobytes, the size Autobahn's
/// 12.2.10 compresses a thousand of, and each is compressed several times with a
/// fresh window; the fastest run is reported, because the slower ones are the
/// machine's other work.
#coverage.skip
fn main {
  let payloads = [
    ("periodic", periodic(131072)),
    ("english", english(131072)),
    ("noise", noise(131072)),
  ]
  println("payload      octets  compressed   throughput")
  for payload in payloads {
    let (name, bytes) = payload
    let (size, took) = measure(bytes)
    let rate = bytes.length().to_double() / took
    println(
      "\{pad(name, 12)}\{align(bytes.length().to_string(), 8)}\{align(size.to_string(), 10)}\{align(tenths(rate), 8)} MB/s",
    )
  }
}

///|
/// One compression, for its output size and its fastest time in microseconds.
fn measure(payload : Bytes) -> (Int32, Double) {
  let mut best = 1.0e18
  let mut size = 0
  for run in 0..<7 {
    let deflater = @deflate.Deflater::new(takeover=false)
    let start = @bench.monotonic_clock_start()
    let wire = deflater.compress(payload[:])
    let took = @bench.monotonic_clock_end(start)
    size = wire.length()
    // The first two runs pay for whatever the machine has not warmed up yet.
    if run >= 2 && took < best {
      best = took
    }
  }
  (size, best)
}

///|
/// The rate to one decimal place. A double prints every digit it has, which makes a
/// column of them as wide as the slowest machine is precise.
fn tenths(rate : Double) -> String {
  let scaled = (rate * 10.0).to_int()
  "\{scaled / 10}.\{scaled % 10}"
}

///|
/// A string in a column of its own, right aligned.
fn align(text : String, width : Int32) -> String {
  let mut out = text
  while out.length() < width {
    out = " " + out
  }
  out
}

///|
fn pad(text : String, width : Int32) -> String {
  let mut out = text
  while out.length() < width {
    out = out + " "
  }
  out
}

///|
/// Text with a thirteen-octet period, which is what RFC 7692 §7.2.3.1's example
/// message repeats: short matches at one distance, and the longest runs the
/// encoder can find.
fn periodic(n : Int32) -> Bytes {
  let unit = b"Hello World! "
  let out = Buffer()
  while out.length() < n {
    out.write_bytes(unit[:])
  }
  out.to_bytes()[:n].to_owned()
}

///|
/// English prose with its own word frequencies, repeated with a period of a few
/// kilobytes: what a text frame on a real connection looks like.
fn english(n : Int32) -> Bytes {
  let prose = b"WE THE PEOPLE of the United States, in Order to form a more perfect Union, establish Justice, insure domestic Tranquility, provide for the common defence, promote the general Welfare, and secure the Blessings of Liberty to ourselves and our Posterity, do ordain and establish this Constitution for the United States of America. Article I. Section 1. All legislative Powers herein granted shall be vested in a Congress of the United States, which shall consist of a Senate and House of Representatives. Section 2. The House of Representatives shall be composed of Members chosen every second Year by the People of the several States, and the Electors in each State shall have the Qualifications requisite for Electors of the most numerous Branch of the State Legislature. No Person shall be a Representative who shall not have attained to the Age of twenty five Years, and been seven Years a Citizen of the United States, and who shall not, when elected, be an Inhabitant of that State in which he shall be chosen."
  let out = Buffer()
  while out.length() < n {
    out.write_bytes(prose[:])
  }
  out.to_bytes()[:n].to_owned()
}

///|
/// Octets from a linear congruential generator, which repeat only by accident.
fn noise(n : Int32) -> Bytes {
  let out : Array[Byte] = []
  let mut x : UInt32 = 12345U
  for _ in 0..<n {
    x = x * 1103515245U + 12345U
    out.push(((x >> 16) & 0xFFU).reinterpret_as_int().to_byte())
  }
  Bytes::from_array(out)
}
