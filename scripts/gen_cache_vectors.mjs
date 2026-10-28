// Turn the cache-tests suite's definitions into the decisions this repo makes.
//
// The suite (https://github.com/http-tests/cache-tests) states each case as a
// pair of requests: a setup response the cache stores, a pause, and a second
// request that must or must not be answered from the store. That is the same
// question `cache.Entry` answers, so the cases are extracted here — with their
// numeric date fields resolved against the suite's "now" — into
// `scripts/cache-tests.json`, which `scripts/gen_cache_vectors.py` turns into
// MoonBit.
//
//     git clone https://github.com/http-tests/cache-tests
//     node scripts/gen_cache_vectors.mjs ./cache-tests
//
// The pause the suite takes is three seconds (`test-engine/client/utils.mjs`),
// and a date field written as a number is an offset from the server's now, in
// seconds (`test-engine/lib/header-fixup.mjs`).

import { readdir, writeFile } from 'node:fs/promises'
import { pathToFileURL } from 'node:url'
import path from 'node:path'

// A fixed instant, so the vectors do not depend on when they were generated:
// the one RFC 9110 §5.6.7 prints.
const NOW = Date.UTC(1994, 10, 6, 8, 49, 37) / 1000
const PAUSE = 3
const DATE_FIELDS = new Set(['date', 'expires', 'last-modified', 'if-modified-since', 'if-unmodified-since'])
const WANTED = new Set(['cached', 'not_cached', 'etag_validated', 'lm_validated'])

function httpDate(seconds) {
  return new Date(seconds * 1000).toUTCString()
}

function headers(list) {
  if (!Array.isArray(list)) return []
  return list.map(([name, value]) => {
    if (DATE_FIELDS.has(name.toLowerCase()) && Number.isInteger(value)) {
      return [name, httpDate(NOW + value)]
    }
    return [name, String(value)]
  })
}

// A case is usable when it is: a setup response, an optional pause, and one
// check whose expectation is one of the four the suite names. Anything with a
// method, a body, a redirect, a conditional the client made up itself, or more
// than one check is left to the suite: it needs a proxy, not a decision.
function usable(test) {
  if (test.kind !== 'check') return false
  if (!Array.isArray(test.requests) || test.requests.length !== 2) return false
  const [setup, check] = test.requests
  if (!setup.setup || !Array.isArray(setup.response_headers)) return false
  if (!WANTED.has(check.expected_type)) return false
  for (const request of [setup, check]) {
    for (const key of ['request_method', 'request_body', 'redirect', 'mode', 'credentials', 'magic_ims', 'filename', 'query_arg']) {
      if (key in request) return false
    }
  }
  if ('expected_status' in check || 'expected_response_headers' in check) return false
  return true
}

// Cases the suite asserts on in a way this package deliberately does not go, each
// with the reading it follows instead. They are named rather than filtered by
// shape, so that a case which starts failing for another reason still fails.
const EXCLUDED = {
  'freshness-max-age-two-stale-fresh-sameline':
    '§4.2.1 lets a cache use the first of two values or call the response stale; this case requires the second to win',
  'freshness-max-age-two-stale-fresh-sepline':
    '§4.2.1 lets a cache use the first of two values or call the response stale; this case requires the second to win',
  'freshness-max-age-decimal-zero':
    '§4.2.1 encourages treating invalid freshness information as stale; this case requires keeping it',
  'freshness-max-age-decimal-five':
    '§4.2.1 encourages treating invalid freshness information as stale; this case requires keeping it',
  'freshness-max-age-a100':
    '§4.2.1 encourages treating invalid freshness information as stale; this case requires keeping it',
  'freshness-max-age-100a':
    '§4.2.1 encourages treating invalid freshness information as stale; this case requires keeping it',
  'cdn-max-age-case-insensitive':
    'CDN-Cache-Control is RFC 9213\'s field, not the Cache-Control this package reads',
  'conditional-etag-strong-generate-unquoted':
    '§8.8.3 requires the quotes, and an unquoted tag is not a validator to send back',
  'heuristic-delta-5':
    'a tenth of five seconds is no lifetime; this package adds no minimum the specification does not name',
  'heuristic-delta-10':
    'a tenth of ten seconds is no lifetime; this package adds no minimum the specification does not name',
  'stale-close':
    'the case turns on the fetch failing, which `verdict` is not told about',
  'stale-sie-close':
    'the case turns on the fetch failing, which `verdict` is not told about',
}

const root = process.argv[2]
if (!root) {
  console.error('usage: node scripts/gen_cache_vectors.mjs <path to cache-tests>')
  process.exit(1)
}

const dir = path.join(root, 'tests')
const files = (await readdir(dir)).filter(name => name.endsWith('.mjs')).sort()
const out = []
const seen = new Set()
for (const file of files) {
  const suite = (await import(pathToFileURL(path.join(dir, file)).href)).default
  for (const test of suite.tests ?? []) {
    if (test.id in EXCLUDED) seen.add(test.id)
    if (!usable(test)) continue
    if (test.id in EXCLUDED) continue
    const [setup, check] = test.requests
    out.push({
      id: test.id,
      suite: suite.id,
      kind: test.kind,
      status: 200,
      pause: setup.pause_after === true ? PAUSE : 0,
      response: headers(setup.response_headers),
      setup_request: headers(setup.request_headers),
      check_request: headers(check.request_headers),
      expect: check.expected_type,
    })
  }
}

for (const id of Object.keys(EXCLUDED)) {
  if (!seen.has(id)) {
    console.error(`the excluded case ${id} is no longer in the suite, so its reason is stale`)
    process.exit(1)
  }
}

await writeFile('scripts/cache-tests.json', JSON.stringify(out, null, 1) + '\n')
console.log(`${out.length} cases from ${files.length} suites, ${seen.size} excluded`)
