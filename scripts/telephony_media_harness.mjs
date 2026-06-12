#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import https from "node:https";
import { performance } from "node:perf_hooks";

const WS_OPEN = 1;
const DEFAULTS = {
  durationMs: 30_000,
  intervalMs: 20,
  payloadSize: 160,
  path: "/media",
  mode: "text",
  dropAfterMs: 2_000,
  drainMs: 1_000,
  reconnect: true,
  reconnectDelayMs: 250,
  maxReconnectDelayMs: 5_000,
  connectTimeoutMs: 5_000,
  progressIntervalMs: 5_000,
  echoHost: "127.0.0.1",
  echoPort: 0,
};

function usage() {
  return `Usage:
  node scripts/telephony_media_harness.mjs --url wss://relay.example.com --path /media
  node scripts/telephony_media_harness.mjs --local-echo --duration 5s --mode binary

Options:
  --url <ws-url>              Target ws:// or wss:// URL. Required unless --local-echo is used.
  --path <path>               Override target path and query. Default: /media
  --duration <duration>       Bounded send duration. Default: 30s
  --interval <duration>       Frame interval. Default: 20ms
  --payload-size <bytes>      Audio payload bytes per frame. Default: 160
  --mode <text|binary>        Send JSON text frames or raw binary frames. Default: text
  --drop-after <duration>     Mark sent frames dropped if no echo arrives. Default: 2s
  --drain <duration>          Wait after final send for late echoes. Default: 1s
  --protocol <name>           Optional WebSocket subprotocol. May be repeated.
  --no-reconnect              Disable reconnect attempts after connection loss.
  --reconnect-delay <duration> Initial reconnect delay. Default: 250ms
  --max-reconnect-delay <duration> Maximum reconnect backoff. Default: 5s
  --connect-timeout <duration> Per-connection open timeout. Default: 5s
  --progress-interval <duration> Progress log interval. Use 0 to disable. Default: 5s
  --json                      Print the final report as JSON.
  --fail-on-drop              Exit non-zero when dropped or missed frames are observed.
  --insecure-tls              Set NODE_TLS_REJECT_UNAUTHORIZED=0 for self-signed wss tests.

Local echo options:
  --local-echo                Start an in-process WebSocket echo server and target it.
  --echo-host <host>          Echo bind host. Default: 127.0.0.1
  --echo-port <port>          Echo bind port. Default: 0
  --echo-tls                  Serve local echo over wss://. Requires --cert and --key.
  --cert <path>               TLS certificate for --echo-tls.
  --key <path>                TLS private key for --echo-tls.
`;
}

function parseDuration(value, optionName, defaultUnit) {
  const match = String(value).trim().match(/^(\d+(?:\.\d+)?)(ms|s|m)?$/i);
  if (!match) {
    throw new Error(`${optionName} must be a number with optional ms, s, or m suffix`);
  }

  const amount = Number(match[1]);
  const unit = (match[2] || defaultUnit).toLowerCase();
  if (!Number.isFinite(amount) || amount < 0) {
    throw new Error(`${optionName} must be non-negative`);
  }

  if (unit === "ms") {
    return amount;
  }
  if (unit === "s") {
    return amount * 1_000;
  }
  if (unit === "m") {
    return amount * 60_000;
  }
  throw new Error(`${optionName} has unsupported unit ${unit}`);
}

function parsePositiveInteger(value, optionName, { allowZero = false } = {}) {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < (allowZero ? 0 : 1)) {
    throw new Error(`${optionName} must be ${allowZero ? "a non-negative" : "a positive"} integer`);
  }
  return parsed;
}

function takeValue(argv, index, name) {
  const arg = argv[index];
  const equals = arg.indexOf("=");
  if (equals !== -1) {
    return { value: arg.slice(equals + 1), nextIndex: index + 1 };
  }
  if (index + 1 >= argv.length || argv[index + 1].startsWith("--")) {
    throw new Error(`${name} requires a value`);
  }
  return { value: argv[index + 1], nextIndex: index + 2 };
}

function parseArgs(argv) {
  const options = {
    ...DEFAULTS,
    protocols: [],
    pathProvided: false,
    localEcho: false,
    echoTls: false,
    json: false,
    failOnDrop: false,
    insecureTls: false,
  };

  for (let index = 0; index < argv.length;) {
    const arg = argv[index];
    const name = arg.includes("=") ? arg.slice(0, arg.indexOf("=")) : arg;

    switch (name) {
      case "--help":
      case "-h":
        options.help = true;
        index += 1;
        break;
      case "--url": {
        const taken = takeValue(argv, index, name);
        options.url = taken.value;
        index = taken.nextIndex;
        break;
      }
      case "--path": {
        const taken = takeValue(argv, index, name);
        options.path = normalizePath(taken.value);
        options.pathProvided = true;
        index = taken.nextIndex;
        break;
      }
      case "--duration": {
        const taken = takeValue(argv, index, name);
        options.durationMs = parseDuration(taken.value, name, "s");
        index = taken.nextIndex;
        break;
      }
      case "--interval": {
        const taken = takeValue(argv, index, name);
        options.intervalMs = parseDuration(taken.value, name, "ms");
        index = taken.nextIndex;
        break;
      }
      case "--payload-size": {
        const taken = takeValue(argv, index, name);
        options.payloadSize = parsePositiveInteger(taken.value, name);
        index = taken.nextIndex;
        break;
      }
      case "--mode": {
        const taken = takeValue(argv, index, name);
        options.mode = taken.value;
        index = taken.nextIndex;
        break;
      }
      case "--drop-after": {
        const taken = takeValue(argv, index, name);
        options.dropAfterMs = parseDuration(taken.value, name, "ms");
        index = taken.nextIndex;
        break;
      }
      case "--drain": {
        const taken = takeValue(argv, index, name);
        options.drainMs = parseDuration(taken.value, name, "ms");
        index = taken.nextIndex;
        break;
      }
      case "--protocol": {
        const taken = takeValue(argv, index, name);
        options.protocols.push(taken.value);
        index = taken.nextIndex;
        break;
      }
      case "--no-reconnect":
        options.reconnect = false;
        index += 1;
        break;
      case "--reconnect-delay": {
        const taken = takeValue(argv, index, name);
        options.reconnectDelayMs = parseDuration(taken.value, name, "ms");
        index = taken.nextIndex;
        break;
      }
      case "--max-reconnect-delay": {
        const taken = takeValue(argv, index, name);
        options.maxReconnectDelayMs = parseDuration(taken.value, name, "ms");
        index = taken.nextIndex;
        break;
      }
      case "--connect-timeout": {
        const taken = takeValue(argv, index, name);
        options.connectTimeoutMs = parseDuration(taken.value, name, "ms");
        index = taken.nextIndex;
        break;
      }
      case "--progress-interval": {
        const taken = takeValue(argv, index, name);
        options.progressIntervalMs = parseDuration(taken.value, name, "s");
        index = taken.nextIndex;
        break;
      }
      case "--json":
        options.json = true;
        index += 1;
        break;
      case "--fail-on-drop":
        options.failOnDrop = true;
        index += 1;
        break;
      case "--insecure-tls":
        options.insecureTls = true;
        index += 1;
        break;
      case "--local-echo":
        options.localEcho = true;
        index += 1;
        break;
      case "--echo-host": {
        const taken = takeValue(argv, index, name);
        options.echoHost = taken.value;
        index = taken.nextIndex;
        break;
      }
      case "--echo-port": {
        const taken = takeValue(argv, index, name);
        options.echoPort = parsePositiveInteger(taken.value, name, { allowZero: true });
        index = taken.nextIndex;
        break;
      }
      case "--echo-tls":
        options.echoTls = true;
        index += 1;
        break;
      case "--cert": {
        const taken = takeValue(argv, index, name);
        options.cert = taken.value;
        index = taken.nextIndex;
        break;
      }
      case "--key": {
        const taken = takeValue(argv, index, name);
        options.key = taken.value;
        index = taken.nextIndex;
        break;
      }
      default:
        throw new Error(`unknown option: ${arg}`);
    }
  }

  validateOptions(options);
  return options;
}

function validateOptions(options) {
  if (options.help) {
    return;
  }
  if (!options.localEcho && !options.url) {
    throw new Error("--url is required unless --local-echo is used");
  }
  if (!["text", "binary"].includes(options.mode)) {
    throw new Error("--mode must be text or binary");
  }
  if (options.intervalMs <= 0) {
    throw new Error("--interval must be greater than zero");
  }
  if (options.durationMs <= 0) {
    throw new Error("--duration must be greater than zero");
  }
  if (options.echoTls && (!options.cert || !options.key)) {
    throw new Error("--echo-tls requires --cert and --key");
  }
  if (options.reconnectDelayMs > options.maxReconnectDelayMs) {
    throw new Error("--reconnect-delay must be less than or equal to --max-reconnect-delay");
  }
}

function normalizePath(value) {
  const path = String(value || "/").trim();
  return path.startsWith("/") ? path : `/${path}`;
}

function applyPath(rawUrl, path) {
  const parsed = new URL(rawUrl);
  const pathUrl = new URL(normalizePath(path), "ws://local");
  parsed.pathname = pathUrl.pathname;
  parsed.search = pathUrl.search;
  return parsed.toString();
}

function validateWebSocketUrl(rawUrl) {
  const parsed = new URL(rawUrl);
  if (parsed.protocol !== "ws:" && parsed.protocol !== "wss:") {
    throw new Error(`target URL must use ws:// or wss://, got ${parsed.protocol}`);
  }
  return parsed.toString();
}

class MetricSeries {
  constructor(sampleLimit = 500_000) {
    this.sampleLimit = sampleLimit;
    this.values = [];
    this.count = 0;
    this.sum = 0;
    this.min = Number.POSITIVE_INFINITY;
    this.max = Number.NEGATIVE_INFINITY;
    this.sampled = false;
  }

  add(value) {
    if (!Number.isFinite(value)) {
      return;
    }
    this.count += 1;
    this.sum += value;
    this.min = Math.min(this.min, value);
    this.max = Math.max(this.max, value);
    if (this.values.length < this.sampleLimit) {
      this.values.push(value);
    } else {
      this.sampled = true;
      this.values[this.count % this.sampleLimit] = value;
    }
  }

  summary() {
    if (this.count === 0) {
      return {
        count: 0,
        min: null,
        avg: null,
        p50: null,
        p95: null,
        p99: null,
        max: null,
        sampled: false,
      };
    }

    const sorted = [...this.values].sort((a, b) => a - b);
    return {
      count: this.count,
      min: this.min,
      avg: this.sum / this.count,
      p50: percentile(sorted, 50),
      p95: percentile(sorted, 95),
      p99: percentile(sorted, 99),
      max: this.max,
      sampled: this.sampled,
    };
  }
}

function percentile(sorted, percent) {
  if (sorted.length === 0) {
    return null;
  }
  const rank = (percent / 100) * (sorted.length - 1);
  const lower = Math.floor(rank);
  const upper = Math.ceil(rank);
  if (lower === upper) {
    return sorted[lower];
  }
  const weight = rank - lower;
  return sorted[lower] * (1 - weight) + sorted[upper] * weight;
}

function hashPayload(payload) {
  return crypto.createHash("sha256").update(payload).digest("base64url");
}

function buildAudioPayload(sequence, payloadSize, sentAtMs) {
  const payload = Buffer.alloc(payloadSize);
  const sequence32 = sequence >>> 0;
  const timestampMicros = BigInt(Math.max(0, Math.round(sentAtMs * 1_000)));

  if (payload.length >= 4) {
    payload.writeUInt32BE(sequence32, 0);
  }
  if (payload.length >= 12) {
    payload.writeBigUInt64BE(timestampMicros, 4);
  }
  if (payload.length >= 16) {
    payload.writeUInt32BE(payloadSize >>> 0, 12);
  }

  const start = Math.min(payload.length, 16);
  for (let index = start; index < payload.length; index += 1) {
    payload[index] = (sequence + index) & 0xff;
  }

  if (payload.length < 4) {
    for (let index = 0; index < payload.length; index += 1) {
      payload[index] = (sequence >> (index * 8)) & 0xff;
    }
  }

  return payload;
}

function buildFrame(sequence, sentAtMs, options) {
  const audioPayload = buildAudioPayload(sequence, options.payloadSize, sentAtMs);
  if (options.mode === "binary") {
    const key = `bin:${hashPayload(audioPayload)}`;
    return {
      data: audioPayload,
      key,
      bytes: audioPayload.length,
    };
  }

  const frame = {
    event: "media",
    sequence,
    sent_at_ms: Number(sentAtMs.toFixed(3)),
    interval_ms: options.intervalMs,
    payload_size: options.payloadSize,
    media: {
      track: "inbound",
      chunk: sequence,
      timestamp_ms: Math.round((sequence - 1) * options.intervalMs),
      payload: audioPayload.toString("base64"),
    },
  };
  const data = JSON.stringify(frame);
  return {
    data,
    key: `seq:${sequence}`,
    bytes: Buffer.byteLength(data),
  };
}

function normalizeMessageData(data) {
  if (typeof data === "string") {
    return { kind: "text", value: data, bytes: Buffer.byteLength(data) };
  }
  if (Buffer.isBuffer(data)) {
    return { kind: "binary", value: data, bytes: data.length };
  }
  if (data instanceof ArrayBuffer) {
    const buffer = Buffer.from(data);
    return { kind: "binary", value: buffer, bytes: buffer.length };
  }
  if (ArrayBuffer.isView(data)) {
    const buffer = Buffer.from(data.buffer, data.byteOffset, data.byteLength);
    return { kind: "binary", value: buffer, bytes: buffer.length };
  }
  return { kind: "unknown", value: data, bytes: 0 };
}

function extractSequence(value) {
  const candidates = [
    value?.sequence,
    value?.seq,
    value?.sequenceNumber,
    value?.media?.chunk,
  ];
  for (const candidate of candidates) {
    const parsed = Number(candidate);
    if (Number.isInteger(parsed) && parsed > 0) {
      return parsed;
    }
  }
  return null;
}

function formatNumber(value, digits = 2) {
  return value === null || value === undefined ? "n/a" : Number(value).toFixed(digits);
}

function formatRate(numerator, denominator) {
  if (!denominator) {
    return "0.00%";
  }
  return `${((numerator / denominator) * 100).toFixed(2)}%`;
}

class TelephonyMediaHarness {
  constructor(options, logger) {
    this.options = options;
    this.logger = logger;
    this.pendingBySeq = new Map();
    this.pendingByKey = new Map();
    this.pendingByConnection = new Map();
    this.rttMs = new MetricSeries();
    this.rttJitterMs = new MetricSeries();
    this.sendJitterMs = new MetricSeries();
    this.lastRttMs = null;
    this.sequence = 0;
    this.connectionId = 0;
    this.currentWs = null;
    this.currentReconnectDelayMs = options.reconnectDelayMs;
    this.finished = false;
    this.finishStarted = false;
    this.resolveRun = null;
    this.targetUrl = options.targetUrl;
    this.stats = {
      framesScheduled: 0,
      framesSent: 0,
      framesAcked: 0,
      framesReceived: 0,
      framesDropped: 0,
      framesMissed: 0,
      framesLateOrUnmatched: 0,
      sendErrors: 0,
      bytesSent: 0,
      bytesReceived: 0,
      connects: 0,
      reconnectAttempts: 0,
      successfulReconnects: 0,
      connectionFailures: 0,
      closes: 0,
      errors: 0,
      lastClose: null,
    };
  }

  async run() {
    this.processStartedMs = performance.now();
    this.logger(`target=${this.targetUrl} mode=${this.options.mode} duration=${this.options.durationMs}ms interval=${this.options.intervalMs}ms payload=${this.options.payloadSize}B`);

    await this.connect({ waitForOpen: true });

    this.startedWall = new Date();
    this.startedMs = performance.now();
    this.deadlineMs = this.startedMs + this.options.durationMs;
    this.scheduleNextTick();
    this.dropTimer = setInterval(() => this.pruneExpired(performance.now()), Math.min(500, Math.max(20, this.options.dropAfterMs / 4)));
    if (this.options.progressIntervalMs > 0 && !this.options.json) {
      this.progressTimer = setInterval(() => this.printProgress(), this.options.progressIntervalMs);
    }

    await new Promise((resolve) => {
      this.resolveRun = resolve;
    });

    return this.report();
  }

  connect({ waitForOpen = false } = {}) {
    if (this.finished || (this.deadlineMs && performance.now() >= this.deadlineMs)) {
      return waitForOpen ? Promise.reject(new Error("run deadline elapsed before connecting")) : Promise.resolve();
    }
    if (typeof WebSocket !== "function") {
      throw new Error("global WebSocket is unavailable; use Node.js 22 or newer");
    }

    const connectionId = ++this.connectionId;
    const ws = this.options.protocols.length > 0
      ? new WebSocket(this.targetUrl, this.options.protocols)
      : new WebSocket(this.targetUrl);
    this.currentWs = ws;
    ws.binaryType = "arraybuffer";

    let settle = () => {};
    let fail = () => {};
    let settled = false;
    const openPromise = waitForOpen
      ? new Promise((resolve, reject) => {
        settle = resolve;
        fail = reject;
      })
      : Promise.resolve();

    let opened = false;
    let failedBeforeClose = false;
    const connectTimeout = setTimeout(() => {
      if (!opened && ws.readyState !== WS_OPEN) {
        this.stats.connectionFailures += 1;
        failedBeforeClose = true;
        if (waitForOpen && !settled) {
          settled = true;
          fail(new Error(`initial WebSocket connection timed out after ${this.options.connectTimeoutMs}ms`));
        }
        ws.close();
      }
    }, this.options.connectTimeoutMs);

    ws.addEventListener("open", () => {
      clearTimeout(connectTimeout);
      opened = true;
      this.currentReconnectDelayMs = this.options.reconnectDelayMs;
      this.stats.connects += 1;
      if (this.stats.connects > 1) {
        this.stats.successfulReconnects += 1;
      }
      if (waitForOpen && !settled) {
        settled = true;
        settle();
      }
    });

    ws.addEventListener("message", (event) => {
      this.handleMessage(event.data);
    });

    ws.addEventListener("error", () => {
      this.stats.errors += 1;
    });

    ws.addEventListener("close", (event) => {
      clearTimeout(connectTimeout);
      if (this.currentWs === ws) {
        this.currentWs = null;
      }
      if (opened) {
        this.stats.closes += 1;
        this.dropConnectionPending(connectionId);
      } else if (!this.finished && !failedBeforeClose) {
        this.stats.connectionFailures += 1;
      }
      this.stats.lastClose = {
        code: event.code,
        reason: event.reason,
        was_clean: event.wasClean,
      };
      if (waitForOpen && !opened && !settled) {
        settled = true;
        fail(new Error(`initial WebSocket connection closed before open: code=${event.code} reason=${event.reason || "n/a"}`));
      }
      if (!waitForOpen || opened) {
        this.scheduleReconnect();
      }
    });

    return openPromise;
  }

  scheduleReconnect() {
    if (this.finished || !this.options.reconnect || performance.now() >= this.deadlineMs) {
      return;
    }
    if (this.reconnectTimer) {
      return;
    }
    const delay = Math.min(this.currentReconnectDelayMs, Math.max(0, this.deadlineMs - performance.now()));
    this.stats.reconnectAttempts += 1;
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      this.currentReconnectDelayMs = Math.min(this.currentReconnectDelayMs * 2, this.options.maxReconnectDelayMs);
      this.connect();
    }, delay);
  }

  scheduleNextTick() {
    if (this.finished || this.finishStarted) {
      return;
    }
    const nextExpectedMs = this.startedMs + this.stats.framesScheduled * this.options.intervalMs;
    if (nextExpectedMs >= this.deadlineMs) {
      this.beginFinish();
      return;
    }
    const delay = Math.max(0, nextExpectedMs - performance.now());
    this.tickTimer = setTimeout(() => this.tick(nextExpectedMs), delay);
  }

  tick(expectedMs) {
    if (this.finished || this.finishStarted) {
      return;
    }

    const now = performance.now();
    const sequence = ++this.sequence;
    this.stats.framesScheduled += 1;
    this.sendJitterMs.add(Math.abs(now - expectedMs));
    this.pruneExpired(now);

    const ws = this.currentWs;
    if (!ws || ws.readyState !== WS_OPEN) {
      this.stats.framesMissed += 1;
      this.stats.framesDropped += 1;
      this.scheduleNextTick();
      return;
    }

    const sentAtMs = performance.now();
    const frame = buildFrame(sequence, sentAtMs, this.options);
    const pending = {
      sequence,
      key: frame.key,
      sentAtMs,
      connectionId: this.connectionId,
    };

    this.addPending(pending);
    try {
      ws.send(frame.data);
      this.stats.framesSent += 1;
      this.stats.bytesSent += frame.bytes;
    } catch {
      this.stats.sendErrors += 1;
      this.dropPending(pending, "send_error");
    }

    this.scheduleNextTick();
  }

  addPending(pending) {
    this.pendingBySeq.set(pending.sequence, pending);
    this.pendingByKey.set(pending.key, pending);
    const connectionPending = this.pendingByConnection.get(pending.connectionId) || new Set();
    connectionPending.add(pending);
    this.pendingByConnection.set(pending.connectionId, connectionPending);
  }

  removePending(pending) {
    this.pendingBySeq.delete(pending.sequence);
    this.pendingByKey.delete(pending.key);
    const connectionPending = this.pendingByConnection.get(pending.connectionId);
    if (connectionPending) {
      connectionPending.delete(pending);
      if (connectionPending.size === 0) {
        this.pendingByConnection.delete(pending.connectionId);
      }
    }
  }

  dropPending(pending) {
    this.removePending(pending);
    this.stats.framesDropped += 1;
  }

  dropConnectionPending(connectionId) {
    const connectionPending = this.pendingByConnection.get(connectionId);
    if (!connectionPending) {
      return;
    }
    for (const pending of [...connectionPending]) {
      this.dropPending(pending);
    }
  }

  pruneExpired(now) {
    for (const pending of [...this.pendingBySeq.values()]) {
      if (now - pending.sentAtMs >= this.options.dropAfterMs) {
        this.dropPending(pending);
      }
    }
  }

  handleMessage(data) {
    const now = performance.now();
    const normalized = normalizeMessageData(data);
    this.stats.framesReceived += 1;
    this.stats.bytesReceived += normalized.bytes;

    let pending = null;
    if (normalized.kind === "text") {
      try {
        const parsed = JSON.parse(normalized.value);
        const sequence = extractSequence(parsed);
        if (sequence !== null) {
          pending = this.pendingBySeq.get(sequence) || null;
        }
      } catch {
        pending = null;
      }
    } else if (normalized.kind === "binary") {
      const key = `bin:${hashPayload(normalized.value)}`;
      pending = this.pendingByKey.get(key) || null;
      if (!pending && normalized.value.length >= 4) {
        const sequence = normalized.value.readUInt32BE(0);
        pending = this.pendingBySeq.get(sequence) || null;
      }
    }

    if (!pending) {
      this.stats.framesLateOrUnmatched += 1;
      return;
    }

    this.removePending(pending);
    this.stats.framesAcked += 1;
    const rtt = now - pending.sentAtMs;
    this.rttMs.add(rtt);
    if (this.lastRttMs !== null) {
      this.rttJitterMs.add(Math.abs(rtt - this.lastRttMs));
    }
    this.lastRttMs = rtt;
  }

  beginFinish() {
    if (this.finishStarted) {
      return;
    }
    this.finishStarted = true;
    this.endedSendingMs = performance.now();
    clearTimeout(this.tickTimer);
    this.finishTimer = setTimeout(() => this.finish(), this.options.drainMs);
  }

  finish() {
    if (this.finished) {
      return;
    }
    this.finished = true;
    clearTimeout(this.tickTimer);
    clearTimeout(this.reconnectTimer);
    clearTimeout(this.finishTimer);
    clearInterval(this.dropTimer);
    clearInterval(this.progressTimer);
    this.pruneExpired(performance.now() + this.options.dropAfterMs + 1);

    const ws = this.currentWs;
    if (ws && ws.readyState === WS_OPEN) {
      ws.close(1000, "harness complete");
    }
    this.endedWall = new Date();
    this.endedMs = performance.now();
    if (this.resolveRun) {
      this.resolveRun();
    }
  }

  printProgress() {
    this.logger(`progress scheduled=${this.stats.framesScheduled} sent=${this.stats.framesSent} acked=${this.stats.framesAcked} dropped=${this.stats.framesDropped} reconnects=${this.stats.successfulReconnects}`);
  }

  report() {
    const activeDurationMs = this.options.durationMs;
    const totalRuntimeMs = this.endedMs - this.processStartedMs;
    const rtt = this.rttMs.summary();
    const rttJitter = this.rttJitterMs.summary();
    const sendJitter = this.sendJitterMs.summary();
    return {
      target_url: this.targetUrl,
      mode: this.options.mode,
      started_at: this.startedWall.toISOString(),
      ended_at: this.endedWall.toISOString(),
      configured: {
        duration_ms: this.options.durationMs,
        interval_ms: this.options.intervalMs,
        payload_size_bytes: this.options.payloadSize,
        drop_after_ms: this.options.dropAfterMs,
        drain_ms: this.options.drainMs,
        reconnect: this.options.reconnect,
      },
      observed: {
        duration_ms: activeDurationMs,
        total_runtime_ms: totalRuntimeMs,
        target_fps: 1_000 / this.options.intervalMs,
        sent_fps: this.stats.framesSent / (activeDurationMs / 1_000),
        acked_fps: this.stats.framesAcked / (activeDurationMs / 1_000),
        drop_rate: this.stats.framesDropped / Math.max(1, this.stats.framesScheduled),
      },
      stats: {
        ...this.stats,
        pending_frames: this.pendingBySeq.size,
      },
      rtt_ms: rtt,
      rtt_jitter_ms: rttJitter,
      send_schedule_jitter_ms: sendJitter,
    };
  }
}

function printHumanReport(report) {
  const stats = report.stats;
  const rtt = report.rtt_ms;
  const rttJitter = report.rtt_jitter_ms;
  const sendJitter = report.send_schedule_jitter_ms;

  console.log("Telephony media harness report");
  console.log(`target: ${report.target_url}`);
  console.log(`mode: ${report.mode}`);
  console.log(`duration: configured=${formatNumber(report.configured.duration_ms, 0)}ms observed=${formatNumber(report.observed.duration_ms, 0)}ms total=${formatNumber(report.observed.total_runtime_ms, 0)}ms`);
  console.log(`frames: scheduled=${stats.framesScheduled} sent=${stats.framesSent} acked=${stats.framesAcked} received=${stats.framesReceived} dropped=${stats.framesDropped} missed=${stats.framesMissed} unmatched=${stats.framesLateOrUnmatched} pending=${stats.pending_frames}`);
  console.log(`drop rate: ${formatRate(stats.framesDropped, stats.framesScheduled)}`);
  console.log(`throughput: sent=${formatNumber(report.observed.sent_fps)}fps acked=${formatNumber(report.observed.acked_fps)}fps target=${formatNumber(report.observed.target_fps)}fps`);
  console.log(`connections: opens=${stats.connects} reconnect_attempts=${stats.reconnectAttempts} successful_reconnects=${stats.successfulReconnects} failures=${stats.connectionFailures} closes=${stats.closes} errors=${stats.errors}`);
  console.log(`bytes: sent=${stats.bytesSent} received=${stats.bytesReceived}`);
  console.log(`rtt ms: avg=${formatNumber(rtt.avg)} p50=${formatNumber(rtt.p50)} p95=${formatNumber(rtt.p95)} p99=${formatNumber(rtt.p99)} min=${formatNumber(rtt.min)} max=${formatNumber(rtt.max)}`);
  console.log(`rtt jitter ms: avg=${formatNumber(rttJitter.avg)} p95=${formatNumber(rttJitter.p95)} max=${formatNumber(rttJitter.max)}`);
  console.log(`send schedule jitter ms: avg=${formatNumber(sendJitter.avg)} p95=${formatNumber(sendJitter.p95)} max=${formatNumber(sendJitter.max)}`);
}

function sendWsFrame(socket, opcode, payload) {
  const data = Buffer.isBuffer(payload) ? payload : Buffer.from(payload);
  const header = [];
  header.push(0x80 | opcode);
  if (data.length < 126) {
    header.push(data.length);
  } else if (data.length < 65_536) {
    header.push(126, (data.length >> 8) & 0xff, data.length & 0xff);
  } else {
    const length = BigInt(data.length);
    header.push(127);
    for (let shift = 56n; shift >= 0n; shift -= 8n) {
      header.push(Number((length >> shift) & 0xffn));
    }
  }
  socket.write(Buffer.concat([Buffer.from(header), data]));
}

class WebSocketFrameParser {
  constructor(onFrame) {
    this.buffer = Buffer.alloc(0);
    this.onFrame = onFrame;
  }

  push(chunk) {
    this.buffer = Buffer.concat([this.buffer, chunk]);
    while (true) {
      const frame = this.readFrame();
      if (!frame) {
        return;
      }
      this.onFrame(frame);
    }
  }

  readFrame() {
    if (this.buffer.length < 2) {
      return null;
    }

    const first = this.buffer[0];
    const second = this.buffer[1];
    let offset = 2;
    let length = second & 0x7f;
    const masked = (second & 0x80) !== 0;

    if (length === 126) {
      if (this.buffer.length < offset + 2) {
        return null;
      }
      length = this.buffer.readUInt16BE(offset);
      offset += 2;
    } else if (length === 127) {
      if (this.buffer.length < offset + 8) {
        return null;
      }
      const largeLength = this.buffer.readBigUInt64BE(offset);
      if (largeLength > BigInt(Number.MAX_SAFE_INTEGER)) {
        throw new Error("websocket frame too large");
      }
      length = Number(largeLength);
      offset += 8;
    }

    const maskLength = masked ? 4 : 0;
    if (this.buffer.length < offset + maskLength + length) {
      return null;
    }

    const mask = masked ? this.buffer.subarray(offset, offset + 4) : null;
    offset += maskLength;
    let payload = this.buffer.subarray(offset, offset + length);
    this.buffer = this.buffer.subarray(offset + length);

    if (mask) {
      const unmasked = Buffer.alloc(payload.length);
      for (let index = 0; index < payload.length; index += 1) {
        unmasked[index] = payload[index] ^ mask[index % 4];
      }
      payload = unmasked;
    } else {
      payload = Buffer.from(payload);
    }

    return {
      fin: (first & 0x80) !== 0,
      opcode: first & 0x0f,
      payload,
    };
  }
}

async function startLocalEchoServer(options, logger) {
  const server = options.echoTls
    ? https.createServer({
      cert: fs.readFileSync(options.cert),
      key: fs.readFileSync(options.key),
    })
    : http.createServer();

  server.on("request", (_request, response) => {
    response.writeHead(200, { "content-type": "text/plain" });
    response.end("telephony media echo server\n");
  });

  server.on("upgrade", (request, socket, head) => {
    const key = request.headers["sec-websocket-key"];
    if (!key) {
      socket.write("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n");
      socket.destroy();
      return;
    }

    const accept = crypto
      .createHash("sha1")
      .update(`${key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`)
      .digest("base64");

    socket.write([
      "HTTP/1.1 101 Switching Protocols",
      "Upgrade: websocket",
      "Connection: Upgrade",
      `Sec-WebSocket-Accept: ${accept}`,
      "",
      "",
    ].join("\r\n"));

    const parser = new WebSocketFrameParser((frame) => {
      if (frame.opcode === 0x1 || frame.opcode === 0x2) {
        sendWsFrame(socket, frame.opcode, frame.payload);
      } else if (frame.opcode === 0x8) {
        sendWsFrame(socket, 0x8, frame.payload);
        socket.end();
      } else if (frame.opcode === 0x9) {
        sendWsFrame(socket, 0xA, frame.payload);
      }
    });

    socket.on("data", (chunk) => {
      try {
        parser.push(chunk);
      } catch {
        socket.destroy();
      }
    });

    if (head.length > 0) {
      parser.push(head);
    }
  });

  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(options.echoPort, options.echoHost, () => {
      server.off("error", reject);
      resolve();
    });
  });

  const address = server.address();
  const port = typeof address === "object" && address ? address.port : options.echoPort;
  const protocol = options.echoTls ? "wss" : "ws";
  const url = `${protocol}://${options.echoHost}:${port}${options.path}`;
  logger(`local echo listening on ${url}`);

  return {
    url,
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}

async function main() {
  let options;
  try {
    options = parseArgs(process.argv.slice(2));
  } catch (error) {
    console.error(`error: ${error.message}`);
    console.error(usage());
    process.exitCode = 2;
    return;
  }

  if (options.help) {
    console.log(usage());
    return;
  }

  if (options.insecureTls) {
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
  }

  const logger = (message) => console.error(`[media-harness] ${message}`);
  let localEcho = null;

  try {
    if (options.localEcho) {
      localEcho = await startLocalEchoServer(options, logger);
      options.targetUrl = localEcho.url;
    } else {
      const targetUrl = options.pathProvided ? applyPath(options.url, options.path) : options.url;
      options.targetUrl = validateWebSocketUrl(targetUrl);
    }

    const harness = new TelephonyMediaHarness(options, logger);
    const report = await harness.run();

    if (options.json) {
      console.log(JSON.stringify(report, null, 2));
    } else {
      printHumanReport(report);
    }

    if (options.failOnDrop && report.stats.framesDropped > 0) {
      process.exitCode = 1;
    }
  } catch (error) {
    console.error(`error: ${error.stack || error.message}`);
    process.exitCode = 1;
  } finally {
    if (localEcho) {
      await localEcho.close();
    }
  }
}

await main();
