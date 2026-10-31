// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// Read a request body as the form its `Content-Type` says it is: Go's
/// `Request.ParseForm`, and Starlette's `Request.form()`, without the request.
///
/// Any other content type, or a multipart one with no boundary to split on,
/// carried no form, and the answer is an empty one; `strict` raises `NotAForm`
/// instead. `limits` bounds both encodings, its `parts` counting pairs in a
/// urlencoded body.
pub fn parse(
  body : BytesView,
  content_type : StringView,
  limits~ : @moonmime.Limits = @moonmime.limits,
  strict~ : Bool = false,
) -> @moonmime.Form raise @moonmime.Refused {
  let kind = @moonmime.media_type(content_type)
  match kind.essence {
    "application/x-www-form-urlencoded" => {
      let bound = @moonurl.Limits::new(
        pairs=limits.parts,
        size=limits.part_size,
      )
      let query = @moonurl.Query::decode(body, limits=bound) catch {
        Pairs(limit~) => raise Parts(limit~)
        Pair(limit~, got~) => raise Part(limit~, got~)
        _ => abort("Query::decode refuses only by its limits")
      }
      let fields = query
        .entries()
        .map(p => @moonmime.Field::{ name: p.0, value: p.1, })
      @moonmime.Form::new(fields~)
    }
    "multipart/form-data" if kind.param("boundary") is Some(edge) =>
      @moonmime.formdata(body, edge[:], limits~, strict~)
    _ =>
      if strict {
        raise NotAForm(content_type=content_type.to_owned())
      } else {
        @moonmime.Form::new()
      }
  }
}
