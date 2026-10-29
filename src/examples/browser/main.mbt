// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The calculator's response, worked out by `cache.Entry`: the origin dated it
/// `dated` seconds before it arrived and sent `Age: carried` with
/// `max-age=life`, the trip took `delay` seconds, and it has sat in the cache
/// for `resident` seconds since.
pub fn age(
  dated : Int32,
  carried : Int32,
  delay : Int32,
  resident : Int32,
  life : Int32,
) -> String {
  let at = fn(s : Int32) { @moondate.Moment::of_epoch(s.to_int64()) }
  let sent = 1_000_000
  let received = sent + delay
  let entry : @cache.Entry = {
    status: 200,
    control: @cache.Control::decode("max-age=\{life}"),
    date: Some(at(received - dated)),
    age: Some(carried),
    expires: None,
    last_modified: None,
    etag: None,
    vary: [],
    selects: [],
    sent: at(sent),
    received: at(received),
  }
  let now = at(received + resident)
  let lifetime = entry.lifetime().unwrap_or(0)
  let current = entry.current_age(now~)
  let json : Json = {
    "initial": Json::number(entry.current_age(now=at(received)).to_double()),
    "current": Json::number(current.to_double()),
    "lifetime": Json::number(lifetime.to_double()),
    "left": Json::number((lifetime - current).to_double()),
    "fresh": Json::boolean(entry.fresh(now~)),
  }
  json.stringify()
}
