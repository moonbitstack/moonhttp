// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// One receive window, connection or stream (RFC 9113 §6.9): how much the peer may
/// still send, and how much of what it sent has been handed back.
priv struct Window {
  mut max : Int32
  mut now : Int32
  mut processed : Int32
}

///|
fn Window::new(size : Int32) -> Window {
  { max: size, now: size, processed: 0, }
}

///|
/// Take `n` octets out of the window; `false` when the peer sent more than it may.
fn Window::consume(self : Window, n : Int32) -> Bool {
  if n > self.now {
    return false
  }
  self.now = self.now - n
  true
}

///|
/// Hand `n` processed octets back, and the WINDOW_UPDATE increment that is due,
/// zero when none is.
///
/// The rule is h2's `WindowManager`: wait until half the window has been processed,
/// or, when the window is shut, until a quarter of it or a kibibyte has. One update
/// per octet read would double the frames on the wire.
fn Window::process(self : Window, n : Int32) -> Int32 {
  self.processed = self.processed + n
  if self.processed == 0 {
    return 0
  }
  let quarter = if self.max / 4 < 1024 { self.max / 4 } else { 1024 }
  let due = (self.now == 0 && self.processed > quarter) ||
    self.processed >= self.max / 2
  if !due {
    return 0
  }
  let room = self.max - self.now
  let inc = if self.processed < room { self.processed } else { room }
  self.processed = 0
  self.now = self.now + inc
  inc
}

///|
/// Widen the window by `n`, as an explicit WINDOW_UPDATE does.
fn Window::open(self : Window, n : Int32) -> Unit {
  self.now = self.now + n
  if self.now > self.max {
    self.max = self.now
  }
}
