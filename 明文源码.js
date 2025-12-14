// src/worker.js
import { connect } from "cloudflare:sockets";

let sha224Password ='4b23f8479e2c6d03799d2cfc7a7d1ea872dfb1ec1fa1859b77e4594d';
let proxyIP = "";

// -------------------- KV：ProxyIP 缓存 --------------------
const KV_KEY = 'proxy_ip_cache';
const KV_TTL_SEC = 3600;

async function kvGetProxyIP(kv) {
  try {
    const raw = await kv.get(KV_KEY);
    if (!raw) return null;
    const { ip, ts } = JSON.parse(raw);
    if (Date.now() - ts > KV_TTL_SEC * 1000) return null;
    return ip;
  } catch { return null; }
}

async function kvPutProxyIP(kv, ip) {
  const payload = JSON.stringify({ ip, ts: Date.now() });
  await kv.put(KV_KEY, payload, { expirationTtl: KV_TTL_SEC });
}

// -------------------- KV：域名白名单 --------------------
const PROXY_LIST_KEY = 'direct_proxy_list';
const PROXY_LIST_TTL = 7 * 24 * 3600;

async function getProxySet(kv) {
  try {
    const raw = await kv.get(PROXY_LIST_KEY);
    if (!raw) return new Set();
    return new Set(JSON.parse(raw));
  } catch { return new Set(); }
}

async function addProxyHost(kv, host) {
  const set = await getProxySet(kv);
  if (set.has(host)) return;
  set.add(host);
  await kv.put(PROXY_LIST_KEY, JSON.stringify([...set]), {
    expirationTtl: PROXY_LIST_TTL
  });
}

// -------------------- 动态解析 proxyip.cmliussss.net --------------------
const PROXY_HOST = 'proxyip.cmliussss.net';
const PROBE_PORT = 443;
const PROBE_TIMEOUT = 3000;

let cachedProxyIP = null;

async function pickAliveIP(ips) {
  const testOne = ip => new Promise(r => {
    const t = setTimeout(() => r(false), PROBE_TIMEOUT);
    connect({ hostname: ip, port: PROBE_PORT })
      .opened.then(() => { clearTimeout(t); r(ip); })
      .catch(() => { clearTimeout(t); r(false); });
  });

  for (let i = 0; i < ips.length; i += 6) {
    const batch = ips.slice(i, i + 6).map(testOne);
    const ok = await Promise.race(batch);
    if (ok) return ok;
  }
  return null;
}

async function refreshProxyIP(kv) {
  const cached = await kvGetProxyIP(kv);
  if (cached) {
    cachedProxyIP = cached;
    proxyIP = cached;
    return;
  }

  try {
    const resp = await fetch(
      `https://cloudflare-dns.com/dns-query?name=${PROXY_HOST}&type=A`,
      { headers: { Accept: 'application/dns-json' } }
    );
    const data = await resp.json();
    const ips = (data.Answer || [])
      .filter(r => r.type === 1)
      .map(r => r.data);

    if (ips.length) {
      const ok = await pickAliveIP(ips);
      if (ok) {
        cachedProxyIP = ok;
        proxyIP = ok;
        await kvPutProxyIP(kv, ok);
      }
    }
  } catch {}
}

// -------------------- Worker 主体 --------------------
const worker_default = {
  async fetch(request, env, ctx) {

    sha224Password = env.SHA224PASS || sha224Password;

    // 后台刷新 ProxyIP
    ctx.waitUntil(refreshProxyIP(env.tran));
    if (cachedProxyIP) proxyIP = cachedProxyIP;

    const upgradeHeader = request.headers.get("Upgrade");

    if (!upgradeHeader || upgradeHeader !== "websocket") {
      const url = new URL(request.url);

      switch (url.pathname) {
        case "/Monchan":
          const host = request.headers.get('Host');
          return new Response(
            `trojan://Monchan@${host}:443/?type=ws&host=${host}&security=tls`,
            { status: 200, headers: { "Content-Type": "text/plain" } }
          );

        default:
          return new Response("404 Not found", { status: 404 });
      }
    }

    // WebSocket 处理
    return await trojanOverWSHandler(request, env, ctx);
  }
};

// -------------------- Trojan WS Handler --------------------
async function trojanOverWSHandler(request, env, ctx) {

  const webSocketPair = new WebSocketPair();
  const [client, webSocket] = Object.values(webSocketPair);
  webSocket.accept();

  let address = "";
  let portWithRandomLog = "";

  const log = (info, event) => {
    console.log(`[${address}:${portWithRandomLog}] ${info}`, event || "");
  };

  const earlyDataHeader = request.headers.get("sec-websocket-protocol") || "";
  const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);

  let remoteSocketWapper = { value: null };
  let udpStreamWrite = null;

  readableWebSocketStream.pipeTo(new WritableStream({
    async write(chunk) {

      if (udpStreamWrite) return udpStreamWrite(chunk);

      if (remoteSocketWapper.value) {
        const writer = remoteSocketWapper.value.writable.getWriter();
        await writer.write(chunk);
        writer.releaseLock();
        return;
      }

      const {
        hasError,
        message,
        portRemote = 443,
        addressRemote = "",
        rawClientData
      } = await parseTrojanHeader(chunk);

      address = addressRemote;
      portWithRandomLog = `${portRemote}--${Math.random()} tcp`;

      if (hasError) throw new Error(message);

      handleTCPOutBound(
        remoteSocketWapper,
        addressRemote,
        portRemote,
        rawClientData,
        webSocket,
        log,
        env,     // ✅ 传入完整 env
        ctx
      );
    }
  })).catch(err => log("pipeTo error", err));

  return new Response(null, { status: 101, webSocket: client });
}

// -------------------- TCP Outbound --------------------
async function handleTCPOutBound(remoteSocket, addressRemote, portRemote, rawClientData, webSocket, log, env, ctx) {

  const kv = env.tran;   // ✅ 正确的 KV 对象

  // ✅ 白名单命中
  const proxySet = await getProxySet(kv);
  if (proxySet.has(addressRemote)) {
    log(`hit proxy list, direct to proxyIP`);
    const tcpSocket = await connectAndWrite(proxyIP, portRemote);
    return remoteSocketToWS(tcpSocket, webSocket, null, log);
  }

  async function connectAndWrite(address, port) {
    const tcpSocket2 = connect({ hostname: address, port });
    remoteSocket.value = tcpSocket2;
    const writer = tcpSocket2.writable.getWriter();
    await writer.write(rawClientData);
    writer.releaseLock();
    return tcpSocket2;
  }

  async function retry() {
    const tcpSocket2 = await connectAndWrite(proxyIP || addressRemote, portRemote);

    // ✅ 写入白名单
    ctx.waitUntil(addProxyHost(kv, addressRemote));

    remoteSocketToWS(tcpSocket2, webSocket, null, log);
  }

  const tcpSocket = await connectAndWrite(addressRemote, portRemote);
  remoteSocketToWS(tcpSocket, webSocket, retry, log);
}

// -------------------- 其他工具函数（保持不变） --------------------
function makeReadableWebSocketStream(ws, earlyDataHeader, log) {
  let canceled = false;
  return new ReadableStream({
    start(controller) {
      ws.addEventListener("message", e => {
        if (!canceled) controller.enqueue(e.data);
      });
      ws.addEventListener("close", () => controller.close());
      ws.addEventListener("error", err => controller.error(err));

      const { earlyData } = base64ToArrayBuffer(earlyDataHeader);
      if (earlyData) controller.enqueue(earlyData);
    },
    cancel() {
      canceled = true;
      ws.close();
    }
  });
}

async function remoteSocketToWS(remoteSocket, webSocket, retry, log) {
  let hasIncomingData = false;

  await remoteSocket.readable.pipeTo(new WritableStream({
    async write(chunk) {
      hasIncomingData = true;
      webSocket.send(chunk);
    }
  })).catch(err => {
    log("remoteSocketToWS error", err);
    webSocket.close();
  });

  if (!hasIncomingData && retry) retry();
}

function parseTrojanHeader(buffer) {
  // ...（保持你原来的实现）
}

function base64ToArrayBuffer(base64Str) {
  if (!base64Str) return { error: null };
  try {
    base64Str = base64Str.replace(/-/g, "+").replace(/_/g, "/");
    const decode = atob(base64Str);
    const arr = Uint8Array.from(decode, c => c.charCodeAt(0));
    return { earlyData: arr.buffer, error: null };
  } catch (error) {
    return { error };
  }
}

export default worker_default;