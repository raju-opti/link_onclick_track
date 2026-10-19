#!/usr/bin/env node
// Extract HTTP request bodies, and the responses to them, from a Chrome netlog.
//
// Capture: chrome://net-export -> select "Include raw bytes" -> Start Logging to Disk -> reproduce -> Stop.
// Usage:   node netlog-bodies.mjs <netlog.json> [url-regex]
//          e.g. node netlog-bodies.mjs chrome-net-export-log.json '/v1/events'
//
// Works for HTTP/1.1 and HTTP/2, over TLS or plain TCP, including connections opened before
// logging started. Chrome never logs HTTP/3 (QUIC) payloads, so those requests are listed
// with response headers only; disable QUIC via chrome://flags/#enable-quic to force HTTP/2.

import { readFileSync } from 'node:fs';
import zlib from 'node:zlib';

const [file, pattern] = process.argv.slice(2);
if (!file) {
  console.error('usage: node netlog-bodies.mjs <netlog.json> [url-regex]');
  process.exit(1);
}
const urlFilter = pattern ? new RegExp(pattern) : null;

function loadNetlog(path) {
  const text = readFileSync(path, 'utf8');
  try {
    return JSON.parse(text);
  } catch {
    // Chrome leaves the file unterminated if logging didn't stop cleanly; events are one per line.
    return JSON.parse(text.slice(0, text.lastIndexOf('},\n') + 1) + ']}');
  }
}

const log = loadNetlog(file);
const T = log.constants.logEventTypes;
const tickOffset = Number(log.constants.timeTickOffset);
const wallClock = (time) => new Date(tickOffset + Number(time)).toISOString();

const decodeBytes = (p) =>
  p.bytes != null ? Buffer.from(p.bytes, 'base64') :
  p.hex_encoded_bytes != null ? Buffer.from(p.hex_encoded_bytes, 'hex') : null;

// "name: value" strings, where HTTP/2 pseudo-headers start with ':' (":path: /x").
const parseHeaderLines = (lines) => Object.fromEntries(lines.map((line) => {
  const i = line.indexOf(':', 1);
  return [line.slice(0, i).trim().toLowerCase(), line.slice(i + 1).trim()];
}));

// --- Collect socket bytes, and HTTP/2 / QUIC metadata ---

const BYTE_EVENTS = new Map([
  [T.SSL_SOCKET_BYTES_SENT, { dir: 'sent', tls: true }],
  [T.SOCKET_BYTES_SENT, { dir: 'sent', tls: false }],
  [T.SSL_SOCKET_BYTES_RECEIVED, { dir: 'received', tls: true }],
  [T.SOCKET_BYTES_RECEIVED, { dir: 'received', tls: false }],
]);

const sockets = new Map(); // socket id -> { sent: { tls, plain }, received: { tls, plain } }, each a list of { time, bytes }
const h2SessionSocket = new Map(); // h2 session id -> socket id
const h2Streams = []; // { session, stream, headers, time }
const h2SentSize = new Map(); // `${session}:${stream}` -> request body bytes the session logged
const h2ReceivedSize = new Map(); // `${session}:${stream}` -> response body bytes the session logged
const h2ResponseHeaders = new Map(); // `${session}:${stream}` -> { lines, time }
const quicRequests = [];
const responseHeadersByRequest = new Map(); // URL_REQUEST id -> { lines, time }
let sawBytesEvents = false;

const addSize = (map, key, size) => map.set(key, (map.get(key) ?? 0) + size);

for (const e of log.events) {
  const p = e.params || {};
  const byteEvent = BYTE_EVENTS.get(e.type);
  if (byteEvent) {
    sawBytesEvents = true;
    const bytes = decodeBytes(p);
    if (!bytes) continue;
    const s = sockets.get(e.source.id) ?? { sent: { tls: [], plain: [] }, received: { tls: [], plain: [] } };
    s[byteEvent.dir][byteEvent.tls ? 'tls' : 'plain'].push({ time: e.time, bytes });
    sockets.set(e.source.id, s);
    continue;
  }
  const key = `${e.source.id}:${p.stream_id}`;
  switch (e.type) {
    case T.HTTP2_SESSION_INITIALIZED:
      if (p.source_dependency) h2SessionSocket.set(e.source.id, p.source_dependency.id);
      break;
    case T.HTTP2_SESSION_SEND_HEADERS:
      h2Streams.push({ session: e.source.id, stream: p.stream_id, headers: parseHeaderLines(p.headers), time: e.time });
      break;
    case T.HTTP2_SESSION_SEND_DATA:
      addSize(h2SentSize, key, p.size);
      break;
    case T.HTTP2_SESSION_RECV_HEADERS:
      // A second HEADERS block on a stream is trailers; keep the response headers.
      if (!h2ResponseHeaders.has(key)) h2ResponseHeaders.set(key, { lines: p.headers, time: e.time });
      break;
    case T.HTTP2_SESSION_RECV_DATA:
      addSize(h2ReceivedSize, key, p.size);
      break;
    case T.HTTP_TRANSACTION_QUIC_SEND_REQUEST_HEADERS:
      quicRequests.push({ headers: parseHeaderLines(p.headers), time: e.time, source: e.source.id });
      break;
    case T.HTTP_TRANSACTION_READ_RESPONSE_HEADERS:
      // Logged on the URL request for every protocol; the last one is the final response.
      responseHeadersByRequest.set(e.source.id, { lines: p.headers, time: e.time });
      break;
  }
}

if (sawBytesEvents && sockets.size === 0) {
  console.error('No raw bytes in this netlog. Re-capture with "Include raw bytes" selected in chrome://net-export.');
  process.exit(1);
}

// --- Rebuild a socket's plaintext stream in one direction ---

function socketStream(chunks, scheme) {
  const chunkStarts = [];
  let total = 0;
  for (const c of chunks) {
    chunkStarts.push(total);
    total += c.bytes.length;
  }
  const timeAt = (pos) => chunks[chunkStarts.findLastIndex((at) => at <= pos)]?.time ?? chunks[0]?.time;
  return { buf: Buffer.concat(chunks.map((c) => c.bytes)), chunkStarts, timeAt, scheme };
}

function dechunk(buf) {
  const parts = [];
  let i = 0;
  while (i < buf.length) {
    const lineEnd = buf.indexOf('\r\n', i);
    if (lineEnd < 0) break;
    const size = parseInt(buf.subarray(i, lineEnd).toString('latin1'), 16);
    if (!size) break;
    parts.push(buf.subarray(lineEnd + 2, lineEnd + 2 + size));
    i = lineEnd + 2 + size + 2;
  }
  return { body: Buffer.concat(parts), end: Math.min(i, buf.length) };
}

// Message body per RFC 9112: chunked, Content-Length, or (responses only) up to the next message.
function http1Body(buf, bodyStart, headers, nextMessageAt) {
  if (/chunked/i.test(headers['transfer-encoding'] ?? '')) {
    const d = dechunk(buf.subarray(bodyStart, nextMessageAt));
    return { body: d.body, end: bodyStart + d.end };
  }
  const end = headers['content-length'] != null
    ? Math.min(bodyStart + Number(headers['content-length']), nextMessageAt)
    : nextMessageAt;
  return { body: buf.subarray(bodyStart, end), end };
}

const REQUEST_LINE = /(?:GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD) \S+ HTTP\/1\.[01]\r\n/g;
const STATUS_LINE = /HTTP\/1\.[01] (\d{3})[^\r\n]*\r\n/g;

function parseHttp1Requests(socketId, { buf, timeAt, scheme }) {
  // latin1 maps bytes 1:1 to chars, so string indices are byte offsets.
  const text = buf.toString('latin1');
  const requests = [];
  REQUEST_LINE.lastIndex = 0;
  let m;
  while ((m = REQUEST_LINE.exec(text))) {
    const headEnd = text.indexOf('\r\n\r\n', m.index);
    if (headEnd < 0) break;
    const [requestLine, ...headerLines] = text.slice(m.index, headEnd).split('\r\n');
    const headers = parseHeaderLines(headerLines);
    const [method, path] = requestLine.split(' ');
    const bodyStart = headEnd + 4;
    // Requests without Content-Length or chunked encoding have no body.
    const { body, end } = headers['content-length'] != null || headers['transfer-encoding']
      ? http1Body(buf, bodyStart, headers, buf.length)
      : { body: buf.subarray(bodyStart, bodyStart), end: bodyStart };
    requests.push({
      method, url: `${scheme}://${headers.host}${path}`, headers, body,
      time: timeAt(m.index), where: `socket ${socketId}, HTTP/1.1`,
    });
    REQUEST_LINE.lastIndex = end;
  }
  return requests;
}

function parseHttp1Responses({ buf, timeAt }) {
  const text = buf.toString('latin1');
  const starts = [...text.matchAll(STATUS_LINE)];
  const responses = [];
  let consumed = 0;
  for (const [k, m] of starts.entries()) {
    if (m.index < consumed) continue;
    const headEnd = text.indexOf('\r\n\r\n', m.index);
    if (headEnd < 0) break;
    const [statusLine, ...headerLines] = text.slice(m.index, headEnd).split('\r\n');
    const status = Number(m[1]);
    const headers = parseHeaderLines(headerLines);
    const bodyStart = headEnd + 4;
    // Capping at the next status line also covers HEAD responses, which carry Content-Length but no body.
    const nextMessageAt = starts.slice(k + 1).find((n) => n.index >= bodyStart)?.index ?? buf.length;
    const { body, end } = status < 200 || status === 204 || status === 304
      ? { body: buf.subarray(bodyStart, bodyStart), end: bodyStart }
      : http1Body(buf, bodyStart, headers, nextMessageAt);
    consumed = end;
    if (status >= 200) responses.push({ statusLine, headerLines, headers, body, time: timeAt(m.index) });
  }
  return responses;
}

// Each request gets the first response that arrived after it was sent; responses before that
// belong to requests sent before the capture started.
function pairResponses(requests, responses) {
  const pending = [...responses];
  for (const r of requests) {
    const k = pending.findIndex((res) => Number(res.time) >= Number(r.time));
    if (k >= 0) r.response = pending.splice(0, k + 1).pop();
  }
}

const H2_PREFACE = 'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n';
const H2_MAX_FRAME = 1 << 14; // Chrome doesn't raise SETTINGS_MAX_FRAME_SIZE, so neither side exceeds it.
const H2_CONNECTION_FRAMES = new Set([0x4, 0x6, 0x7, 0xc]); // SETTINGS, PING, GOAWAY, ORIGIN: stream 0 only
const H2_STREAM_FRAMES = new Set([0x0, 0x1, 0x2, 0x3, 0x5, 0x9]); // DATA, HEADERS, PRIORITY, RST_STREAM, PUSH_PROMISE, CONTINUATION

function isFrameHeader(buf, i) {
  const len = buf.readUIntBE(i, 3);
  const type = buf[i + 3];
  const streamWord = buf.readUInt32BE(i + 5);
  const stream = streamWord & 0x7fffffff;
  return len <= H2_MAX_FRAME && !(streamWord >>> 31) &&
    !(H2_CONNECTION_FRAMES.has(type) && stream !== 0) && !(H2_STREAM_FRAMES.has(type) && stream === 0);
}

// First offset from which frame headers chain validly to the end of the buffer. Used for received
// bytes, whose read chunks don't line up with frames.
function alignFrames(buf, from) {
  for (let off = from; off + 9 <= buf.length && off <= from + H2_MAX_FRAME + 9; off++) {
    let i = off;
    while (i + 9 <= buf.length && isFrameHeader(buf, i)) i += 9 + buf.readUIntBE(i, 3);
    if (i + 9 > buf.length) return off;
  }
  return buf.length;
}

// Returns each stream's HEADERS frame time, DATA payloads, and DATA frame bytes (padding included,
// matching the sizes Chrome logs). If the connection predates the capture there's no preface and
// the bytes may start mid-frame, so on an invalid frame header parsing re-aligns via `realign`.
function parseHttp2Frames({ buf, timeAt }, start, realign) {
  const headersAt = new Map(); // stream id -> time
  const data = new Map(); // stream id -> Buffer[]
  const dataSize = new Map(); // stream id -> bytes
  let i = start;
  while (i + 9 <= buf.length) {
    if (!isFrameHeader(buf, i)) {
      i = realign(i);
      continue;
    }
    const len = buf.readUIntBE(i, 3);
    const type = buf[i + 3];
    const flags = buf[i + 4];
    const stream = buf.readUInt32BE(i + 5) & 0x7fffffff;
    let payload = buf.subarray(i + 9, i + 9 + len);
    if (type === 0x0) {
      addSize(dataSize, stream, payload.length);
      if (flags & 0x8) payload = payload.subarray(1, payload.length - payload[0]); // PADDED
      data.set(stream, [...(data.get(stream) ?? []), payload]);
    } else if (type === 0x1 && !headersAt.has(stream)) {
      headersAt.set(stream, timeAt(i));
    }
    i += 9 + len;
  }
  return { headersAt, data, dataSize };
}

// Chrome writes whole frames, so sent bytes re-align at the next write.
function parseSentFrames(stream) {
  const preface = stream.buf.indexOf(H2_PREFACE);
  return parseHttp2Frames(stream, preface < 0 ? 0 : preface + H2_PREFACE.length,
    (i) => stream.chunkStarts.find((at) => at > i) ?? stream.buf.length);
}

const parseReceivedFrames = (stream) =>
  parseHttp2Frames(stream, alignFrames(stream.buf, 0), (i) => alignFrames(stream.buf, i + 1));

// --- Decode each socket ---

const requests = [];
const uncaptured = []; // requests that had a body we couldn't recover
const h2Sockets = new Map(); // socket id -> { sent, received } parsed frames
const knownH2Sockets = new Set(h2SessionSocket.values());

for (const [socketId, s] of sockets) {
  // On TLS sockets SOCKET_BYTES_* is ciphertext, so use the SSL layer when present.
  const tls = s.sent.tls.length > 0 || s.received.tls.length > 0;
  const layer = tls ? 'tls' : 'plain';
  const sent = socketStream(s.sent[layer], tls ? 'https' : 'http');
  const received = socketStream(s.received[layer], tls ? 'https' : 'http');
  const http1 = knownH2Sockets.has(socketId) ? [] : parseHttp1Requests(socketId, sent);
  if (http1.length) {
    pairResponses(http1, parseHttp1Responses(received));
    requests.push(...http1);
  } else {
    h2Sockets.set(socketId, { sent: parseSentFrames(sent), received: parseReceivedFrames(received) });
  }
}

const sizeNote = (got, expected) => (got < expected ? `only ${got} of ${expected} bytes captured` : '');

// Chrome joins repeated headers (set-cookie, vary) with NUL; print one line per value.
const splitJoinedHeaders = (lines) => lines.flatMap((line) => {
  const i = line.indexOf(':', 1);
  return line.slice(i + 1).trim().split('\0').map((value) => `${line.slice(0, i)}: ${value}`);
});

function h2Response(key, frames, stream) {
  const logged = h2ResponseHeaders.get(key);
  if (!logged) return null;
  const headers = parseHeaderLines(logged.lines);
  const body = frames ? Buffer.concat(frames.data.get(stream) ?? []) : null;
  return {
    statusLine: `HTTP/2 ${headers[':status']}`,
    headerLines: splitJoinedHeaders(logged.lines.filter((line) => !line.startsWith(':'))),
    headers, body,
    note: frames ? sizeNote(frames.dataSize.get(stream) ?? 0, h2ReceivedSize.get(key) ?? 0) : 'body bytes not found in capture',
    time: logged.time,
  };
}

// Pair each logged HTTP/2 request with the socket that carried it. HTTP2_SESSION_INITIALIZED names
// the socket, but isn't logged for sessions opened before the capture started; then it's the
// socket with a HEADERS frame for the same stream id at (nearly) the same time, preferring one
// whose DATA size matches what the session logged.
for (const r of h2Streams) {
  const key = `${r.session}:${r.stream}`;
  const expected = h2SentSize.get(key) ?? 0;
  const knownSocket = h2SessionSocket.get(r.session);
  let best;
  for (const [socketId, frames] of h2Sockets) {
    if (knownSocket != null && socketId !== knownSocket) continue;
    const at = frames.sent.headersAt.get(r.stream);
    if (at == null) continue;
    const dt = Number(at) - Number(r.time);
    if (dt < -5 || dt > 5000) continue;
    const size = frames.sent.dataSize.get(r.stream) ?? 0;
    const sizeMismatch = size === expected ? 0 : 1;
    if (!best || sizeMismatch < best.sizeMismatch || (sizeMismatch === best.sizeMismatch && Math.abs(dt) < best.dt)) {
      best = { socketId, frames, size, sizeMismatch, dt: Math.abs(dt), body: Buffer.concat(frames.sent.data.get(r.stream) ?? []) };
    }
  }

  const h = r.headers;
  const request = { method: h[':method'], url: `${h[':scheme']}://${h[':authority']}${h[':path']}`, headers: h, time: r.time };
  const response = h2Response(key, best?.frames.received, r.stream);
  if (best?.body.length) {
    const partial = sizeNote(best.size, expected);
    requests.push({ ...request, body: best.body, response, where: `socket ${best.socketId}, HTTP/2 stream ${r.stream}${partial && `, ${partial}`}` });
  } else if (expected) {
    uncaptured.push({ ...request, response, why: `HTTP/2 session ${r.session} stream ${r.stream}: ${expected} body bytes sent, but not found in the raw socket bytes` });
  }
}

for (const q of quicRequests) {
  const h = q.headers;
  if (['GET', 'HEAD', 'OPTIONS'].includes(h[':method'])) continue;
  const logged = responseHeadersByRequest.get(q.source);
  const response = logged && {
    statusLine: logged.lines[0], headerLines: splitJoinedHeaders(logged.lines.slice(1)), headers: parseHeaderLines(logged.lines.slice(1)),
    body: null, note: 'body not logged by Chrome (HTTP/3)', time: logged.time,
  };
  uncaptured.push({ method: h[':method'], url: `https://${h[':authority']}${h[':path']}`, time: q.time, response, why: 'HTTP/3, body not logged by Chrome' });
}

// --- Print ---

// Partial bodies (capture cut off mid-response) still decompress up to where they end.
function decodeBody(body, encoding = '') {
  try {
    if (/gzip/i.test(encoding)) return zlib.gunzipSync(body, { finishFlush: zlib.constants.Z_SYNC_FLUSH });
    if (/deflate/i.test(encoding)) return zlib.inflateSync(body, { finishFlush: zlib.constants.Z_SYNC_FLUSH });
    if (/\bbr\b/i.test(encoding)) return zlib.brotliDecompressSync(body, { finishFlush: zlib.constants.BROTLI_OPERATION_FLUSH });
    if (/zstd/i.test(encoding)) return zlib.zstdDecompressSync?.(body) ?? null; // Node >= 22.15
    return body;
  } catch {
    return null;
  }
}

function formatBody(body, encoding) {
  if (!body.length) return '(empty body)';
  const decoded = decodeBody(body, encoding);
  if (!decoded) return `<${body.length} bytes, couldn't decode content-encoding: ${encoding}>`;
  const text = decoded.toString('utf8');
  try {
    return JSON.stringify(JSON.parse(text), null, 2);
  } catch {}
  return /[\x00-\x08\x0e-\x1f]/.test(text) ? `<${decoded.length} bytes of binary data>` : text;
}

function printResponse(res) {
  if (!res) {
    console.log('--- response not captured');
    return;
  }
  console.log(`--- response: ${res.statusLine}  ${wallClock(res.time)}${res.note ? `  (${res.note})` : ''}`);
  for (const line of res.headerLines) console.log(`    ${line}`);
  if (res.body) console.log(formatBody(res.body, res.headers['content-encoding']));
}

const byTime = (a, b) => Number(a.time) - Number(b.time);
const matchesUrl = (r) => !urlFilter || urlFilter.test(r.url);
const matches = requests.filter((r) => r.body.length && matchesUrl(r)).sort(byTime);
const missing = uncaptured.filter(matchesUrl).sort(byTime);

for (const r of matches) {
  console.log(`=== ${r.method} ${r.url}`);
  console.log(`    ${wallClock(r.time)}  (${r.where})`);
  if (r.headers['content-type']) console.log(`    content-type: ${r.headers['content-type']}`);
  console.log(formatBody(r.body, r.headers['content-encoding']));
  printResponse(r.response);
  console.log();
}

for (const r of missing) {
  console.log(`=== ${r.method} ${r.url}`);
  console.log(`    ${wallClock(r.time)}  (${r.why})`);
  printResponse(r.response);
  console.log();
}

if (!matches.length && !missing.length) {
  console.error(`No request bodies found${urlFilter ? ` matching ${urlFilter}` : ''}.`);
}
