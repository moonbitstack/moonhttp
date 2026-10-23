// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
let standard : Array[@method.Method] = [
  Get,
  Head,
  Post,
  Put,
  Delete,
  Connect,
  Options,
  Trace,
  Patch,
]

///|
test "every standard method survives its name" {
  for m in standard {
    assert_eq(@method.Method::of(m.name()), m)
  }
  assert_eq(
    standard.map(m => m.name()).join(" "),
    "GET HEAD POST PUT DELETE CONNECT OPTIONS TRACE PATCH",
  )
}

///|
test "any other token is an extension method, case and all" {
  assert_eq(@method.Method::of("get"), Other("get"))
  assert_eq(@method.Method::of("PURGE"), Other("PURGE"))
  assert_eq(@method.Method::of("M-SEARCH"), Other("M-SEARCH"))
  assert_eq(
    @method.Method::of("!#$%&'*+-.^_`|~09az"),
    Other("!#$%&'*+-.^_`|~09az"),
  )
  assert_eq(@method.Other("PURGE").name(), "PURGE")
}

///|
test "a name that is not a token is refused" {
  for name in ["", "GE T", "GET/1", "DÉLÉTE", "A(B)", "X:Y", "\"Q\""] {
    let accepted = @method.Method::of(name) catch {
      Token(got) => {
        assert_eq(got, name)
        continue
      }
    }
    fail("accepted " + accepted.name())
  }
}

///|
test "safe methods are the four RFC 9110 lists" {
  let safe = standard.filter(m => m.is_safe()).map(m => m.name())
  assert_eq(safe, ["GET", "HEAD", "OPTIONS", "TRACE"])
  assert_eq(@method.Other("PROPFIND").is_safe(), false)
}

///|
test "idempotent methods are the safe ones with PUT and DELETE" {
  let idempotent = standard.filter(m => m.is_idempotent()).map(m => m.name())
  assert_eq(idempotent, ["GET", "HEAD", "PUT", "DELETE", "OPTIONS", "TRACE"])
  assert_eq(@method.Patch.is_idempotent(), false)
  assert_eq(@method.Other("PURGE").is_idempotent(), false)
}

///|
test "a hand-built Other is not the standard method of the same name" {
  assert_eq(@method.Other("GET") == @method.Get, false)
}
