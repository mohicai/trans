// src/worker.js
import { connect } from "cloudflare:sockets";
let sha224Password ='4b23f8479e2c6d03799d2cfc7a7d1ea872dfb1ec1fa1859b77e4594d';
let proxyIP = "";
let a = "";

// -------------------- 新增：KV 缓存层 --------------------
const KV_KEY = 'proxy_ip_cache';
const KV_TTL_SEC = 3600; // 1 h

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
// -------------------- 新增结束 --------------------


// ----------- 无脑写入测试 -----------
async function forceWrite(request, env) {
  const kv = env.tran;
  await kv.put('proxy_ip_cache', '{"ip":"104.21.123.45","ts":1712345678900}', { expirationTtl: 3600 });
  return new Response('ok', { status: 200 });
}



// -------------------- 新增：动态解析 proxyip.cmliussss.net --------------------
const PROXY_HOST = 'proxyip.cmliussss.net';
const PROBE_PORT = 443;
const PROBE_TIMEOUT = 3000;
const CACHE_TTL = 3600_000;
let cachedProxyIP = null;
let lastUpdateTs = 0;

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
    lastUpdateTs = Date.now();
    console.log(`[refreshProxyIP] use KV cached ${cached}`);
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
        lastUpdateTs = Date.now();
        await kvPutProxyIP(kv, ok);
        console.log(`[refreshProxyIP] picked & saved ${ok}`);
      }
    }
  } catch (e) {
    console.log('[refreshProxyIP] err', e);
  }
}
// -------------------- 新增结束 --------------------



// ★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★
// ★ 新增：按域名缓存是否需要走 proxy 的 KV 路由表
// ★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★

const ROUTE_CACHE_KEY = "route_cache";

async function loadRouteCache(kv) {
  try {
    const raw = await kv.get(ROUTE_CACHE_KEY);
    return raw ? JSON.parse(raw) : {};
  } catch {
    return {};
  }
}

async function saveRouteCache(kv, table) {
  await kv.put(ROUTE_CACHE_KEY, JSON.stringify(table), {
    expirationTtl: 24 * 3600 // 1 天
  });
}

// ★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★



if (!isValidSHA224(sha224Password)) {
    throw new Error('sha224Password is not valid');
}

const worker_default = {
    async fetch(request, env, ctx) {
        try {
            sha224Password = env.SHA224PASS || sha224Password;

            ctx.waitUntil(refreshProxyIP(env.tran));
            if (cachedProxyIP) proxyIP = cachedProxyIP;

            const upgradeHeader = request.headers.get("Upgrade");
            if (!upgradeHeader || upgradeHeader !== "websocket") {
                const url = new URL(request.url);
                switch (url.pathname) {
                    case "/Monchan":
                        const host = request.headers.get('Host');
                        return new Response(`trojan://Monchan@${host}:443/?type=ws&host=${host}&security=tls\ntrojan://Monchan@warps.dynv6.net:443/?type=ws&host=${host}&security=tls\ntrojan://Monchan@test.mohic.lol:443/?type=ws&host=${host}&security=tls`, {
                            status: 200,
                            headers: {
                                "Content-Type": "text/plain;charset=utf-8",
                            }
                        });
                    default:
                        return new Response("404 Not found", { status: 404 });
                }
            } else {
                globalThis.env = env; // ★ 新增：让 handleTCPOutBound 能访问 env.tran
                return await trojanOverWSHandler(request);
            }
        } catch (err) {
            let e = err;
            return new Response(e.toString());
        }
    }
};



// ★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★
// ★ 修改 handleTCPOutBound：加入域名路由缓存逻辑
// ★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★

async function handleTCPOutBound(remoteSocket, addressRemote, portRemote, rawClientData, webSocket, log) {

    const kv = globalThis.env.tran;
    const routeTable = await loadRouteCache(kv);
    const host = addressRemote;

    async function connectAndWrite(address, port) {
        const tcpSocket2 = connect({ hostname: address, port });
        remoteSocket.value = tcpSocket2;
        log(`connected to ${address}:${port}`);
        const writer = tcpSocket2.writable.getWriter();
        await writer.write(rawClientData);
        writer.releaseLock();
        return tcpSocket2;
    }

    async function retry() {
        const tcpSocket2 = await connectAndWrite(proxyIP || addressRemote, portRemote);
        tcpSocket2.closed.catch((error) => {
            console.log("retry tcpSocket closed error", error);
        }).finally(() => {
            safeCloseWebSocket(webSocket);
        });
        remoteSocketToWS(tcpSocket2, webSocket, null, log);

        // ★ 记录：该域名需要走 proxy
        routeTable[host] = true;
        await saveRouteCache(kv, routeTable);
    }

    try {
        // ★ 如果缓存表里标记为 true → 直接走 proxy
        if (routeTable[host] === true) {
            log(`route cache: ${host} → proxy`);
            return retry();
        }

        // ★ 尝试直连
        const tcpSocket = await connectAndWrite(addressRemote, portRemote);
        remoteSocketToWS(tcpSocket, webSocket, retry, log);

        // ★ 直连成功 → 记录不需要走 proxy
        routeTable[host] = false;
        await saveRouteCache(kv, routeTable);

    } catch (e) {
        log(`direct connect failed, fallback to proxy`);

        // ★ 直连失败 → 走 proxy
        await retry();
    }
}



// ★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★
// ★ 以下部分保持原样（未改动）
// ★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★

function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
    let readableStreamCancel = false;
    const stream = new ReadableStream({
        start(controller) {
            webSocketServer.addEventListener("message", (event) => {
                if (readableStreamCancel) {
                    return;
                }
                const message = event.data;
                controller.enqueue(message);
            });
            webSocketServer.addEventListener("close", () => {
                safeCloseWebSocket(webSocketServer);
                if (readableStreamCancel) {
                    return;
                }
                controller.close();
            });
            webSocketServer.addEventListener("error", (err) => {
                log("webSocketServer error");
                controller.error(err);
            });
            const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
            if (error) {
                controller.error(error);
            } else if (earlyData) {
                controller.enqueue(earlyData);
            }
        },
        pull(controller) {},
        cancel(reason) {
            if (readableStreamCancel) {
                return;
            }
            log(`readableStream was canceled, due to ${reason}`);
            readableStreamCancel = true;
            safeCloseWebSocket(webSocketServer);
        }
    });
    return stream;
}

async function remoteSocketToWS(remoteSocket, webSocket, retry, log) {
    let hasIncomingData = false;
    await remoteSocket.readable.pipeTo(
        new WritableStream({
            start() {},
            async write(chunk, controller) {
                hasIncomingData = true;
                if (webSocket.readyState !== WS_READY_STATE_OPEN) {
                    controller.error("webSocket connection is not open");
                }
                webSocket.send(chunk);
            },
            close() {
                log(`remoteSocket.readable is closed, hasIncomingData: ${hasIncomingData}`);
            },
            abort(reason) {
                console.error("remoteSocket.readable abort", reason);
            }
        })
    ).catch((error) => {
        console.error(`remoteSocketToWS error:`, error.stack || error);
        safeCloseWebSocket(webSocket);
    });
    if (hasIncomingData === false && retry) {
        log(`retry`);
        retry();
    }
}

function isValidSHA224(hash) {
    const sha224Regex = /^[0-9a-f]{56}$/i;
    return sha224Regex.test(hash);
}

function base64ToArrayBuffer(base64Str) {
    if (!base64Str) {
        return { error: null };
    }
    try {
        base64Str = base64Str.replace(/-/g, "+").replace(/_/g, "/");
        const decode = atob(base64Str);
        const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
        return { earlyData: arryBuffer.buffer, error: null };
    } catch (error) {
        return { error };
    }
}

let WS_READY_STATE_OPEN = 1;
let WS_READY_STATE_CLOSING = 2;

function safeCloseWebSocket(socket) {
    try {
        if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
            socket.close();
        }
    } catch (error) {
        console.error("safeCloseWebSocket error", error);
    }
}

export { worker_default as default };