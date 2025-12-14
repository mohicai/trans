// src/worker.js
import { connect } from "cloudflare:sockets";
let sha224Password ='4b23f8479e2c6d03799d2cfc7a7d1ea872dfb1ec1fa1859b77e4594d';
let proxyIP = "";
let a = "";

// -------------------- 新增：KV 缓存层 --------------------
// 注意：env.PROXY_IP_KV 就是 wrangler.toml 里绑定的 KV 对象
const KV_KEY = 'proxy_ip_cache';

const KV_TTL_SEC = 3600;            // 1 h

/** 从 KV 读缓存，没有或过期返回 null */
async function kvGetProxyIP(kv) {
  try {
    const raw = await kv.get(KV_KEY);
    if (!raw) return null;
    const { ip, ts } = JSON.parse(raw);
    // 多一层保险：如果 KV 的 expiration 失效了，也检查时间戳
    if (Date.now() - ts > KV_TTL_SEC * 1000) return null;
    return ip;
  } catch { return null; }
}

/** 把探测到的 IP 写回 KV，并设置 1 h 过期 */
async function kvPutProxyIP(kv, ip) {
  const payload = JSON.stringify({ ip, ts: Date.now() });
  await kv.put(KV_KEY, payload, { expirationTtl: KV_TTL_SEC });
}
// -------------------- 新增结束 --------------------



// ----------- 无脑写入测试 -----------
async function forceWrite(request, env) {
  const kv = env.tran;                       // 绑定名
  await kv.put('proxy_ip_cache', '{"ip":"104.21.123.45","ts":1712345678900}', { expirationTtl: 3600 });
  return new Response('ok', { status: 200 });
}




// -------------------- 新增：动态解析 proxyip.cmliussss.net --------------------
const PROXY_HOST = 'proxyip.cmliussss.net';
const PROBE_PORT = 443;          // 测 443 端口
const PROBE_TIMEOUT = 3000;      // 3 s 超时
const CACHE_TTL = 3600_000;      // 1 h
let cachedProxyIP = null;        // 上一次成功 IP
let lastUpdateTs = 0;            // 时间戳

/** 并发探测，返回第一个能通的 IP */
async function pickAliveIP(ips) {
  const testOne = ip => new Promise(r => {
    const t = setTimeout(() => r(false), PROBE_TIMEOUT);
    connect({ hostname: ip, port: PROBE_PORT })
      .opened.then(() => { clearTimeout(t); r(ip); })
      .catch(() => { clearTimeout(t); r(false); });
  });
  // 并发 6 个，顺序返回第一个成功
  for (let i = 0; i < ips.length; i += 6) {
    const batch = ips.slice(i, i + 6).map(testOne);
    const ok = await Promise.race(batch);          // 只要一个通就返回
    if (ok) return ok;
  }
  return null;
}

/** 冷启动或过期时刷新 proxyIP，先读 KV，没有再探测 */
async function refreshProxyIP(kv) {
  // 1. 先看 KV 有没有
  const cached = await kvGetProxyIP(kv);
  if (cached) {
    cachedProxyIP = cached;          // 内存也留一份，减少 await 次数
    lastUpdateTs = Date.now();
    console.log(`[refreshProxyIP] use KV cached ${cached}`);
    return;
  }

  // 2. KV 没有，才去 DNS 解析 + 探测
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
        await kvPutProxyIP(kv, ok);   // 写回 KV
        console.log(`[refreshProxyIP] picked & saved ${ok}`);
      }
    }
  } catch (e) {
    console.log('[refreshProxyIP] err', e);
  }
}

// -------------------- 新增结束 --------------------



if (!isValidSHA224(sha224Password)) {
    throw new Error('sha224Password is not valid');
}

const worker_default = {
    /**
     * @param {import("@cloudflare/workers-types").Request} request
     * @param {{SHA224PASS: string, PROXYIP: string}} env
     * @param {import("@cloudflare/workers-types").ExecutionContext} ctx
     * @returns {Promise<Response>}
     */
    async fetch(request, env, ctx) {
        try {
           // proxyIP = env.PROXYIP || proxyIP;
            sha224Password = env.SHA224PASS || sha224Password



const url = new URL(request.url);
switch (url.pathname) {
  case '/write':                       // ← 新增
    return forceWrite(request, env);
  // 其他 case …
}



    
    /* ---------- 新增：后台刷新 proxyIP ---------- */
 
       ctx.waitUntil(refreshProxyIP(env.tran));   // 非阻塞
    if (cachedProxyIP) proxyIP = cachedProxyIP; // 如有缓存优先用
    /* ---------- 新增结束 ------------------------ */


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
                return await trojanOverWSHandler(request);
            }
        } catch (err) {
            let e = err;
            return new Response(e.toString());
        }
    }
};

async function trojanOverWSHandler(request) {
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
    let remoteSocketWapper = {
        value: null
    };
    let udpStreamWrite = null;
    readableWebSocketStream.pipeTo(new WritableStream({
        async write(chunk, controller) {
            if (udpStreamWrite) {
                return udpStreamWrite(chunk);
            }
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
            if (hasError) {
                throw new Error(message);
                return;
            }
            handleTCPOutBound(remoteSocketWapper, addressRemote, portRemote, rawClientData, webSocket, log);
        },
        close() {
            log(`readableWebSocketStream is closed`);
        },
        abort(reason) {
            log(`readableWebSocketStream is aborted`, JSON.stringify(reason));
        }
    })).catch((err) => {
        log("readableWebSocketStream pipeTo error", err);
    });
    return new Response(null, {
        status: 101,
        // @ts-ignore
        webSocket: client
    });
}

async function parseTrojanHeader(buffer) {
    if (buffer.byteLength < 56) {
        return {
            hasError: true,
            message: "invalid data"
        };
    }
    let crLfIndex = 56;
    if (new Uint8Array(buffer.slice(56, 57))[0] !== 0x0d || new Uint8Array(buffer.slice(57, 58))[0] !== 0x0a) {
        return {
            hasError: true,
            message: "invalid header format (missing CR LF)"
        };
    }
    const password = new TextDecoder().decode(buffer.slice(0, crLfIndex));
    if (password !== sha224Password) {
        return {
            hasError: true,
            message: "invalid password"
        };
    }

    const socks5DataBuffer = buffer.slice(crLfIndex + 2);
    if (socks5DataBuffer.byteLength < 6) {
        return {
            hasError: true,
            message: "invalid SOCKS5 request data"
        };
    }

    const view = new DataView(socks5DataBuffer);
    const cmd = view.getUint8(0);
    if (cmd !== 1) {
        return {
            hasError: true,
            message: "unsupported command, only TCP (CONNECT) is allowed"
        };
    }

    const atype = view.getUint8(1);
    // 0x01: IPv4 address
    // 0x03: Domain name
    // 0x04: IPv6 address
    let addressLength = 0;
    let addressIndex = 2;
    let address = "";
    switch (atype) {
        case 1:
            addressLength = 4;
            address = new Uint8Array(
              socks5DataBuffer.slice(addressIndex, addressIndex + addressLength)
            ).join(".");
            break;
        case 3:
            addressLength = new Uint8Array(
              socks5DataBuffer.slice(addressIndex, addressIndex + 1)
            )[0];
            addressIndex += 1;
            address = new TextDecoder().decode(
              socks5DataBuffer.slice(addressIndex, addressIndex + addressLength)
            );
            break;
        case 4:
            addressLength = 16;
            const dataView = new DataView(socks5DataBuffer.slice(addressIndex, addressIndex + addressLength));
            const ipv6 = [];
            for (let i = 0; i < 8; i++) {
                ipv6.push(dataView.getUint16(i * 2).toString(16));
            }
            address = ipv6.join(":");
            break;
        default:
            return {
                hasError: true,
                message: `invalid addressType is ${atype}`
            };
    }

    if (!address) {
        return {
            hasError: true,
            message: `address is empty, addressType is ${atype}`
        };
    }

    const portIndex = addressIndex + addressLength;
    const portBuffer = socks5DataBuffer.slice(portIndex, portIndex + 2);
    const portRemote = new DataView(portBuffer).getUint16(0);
    return {
        hasError: false,
        addressRemote: address,
        portRemote,
        rawClientData: socks5DataBuffer.slice(portIndex + 4)
    };
}

async function handleTCPOutBound(remoteSocket, addressRemote, portRemote, rawClientData, webSocket, log) {
    async function connectAndWrite(address, port) {
        const tcpSocket2 = connect({
            hostname: address,
            port
        });
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
    }
    const tcpSocket = await connectAndWrite(addressRemote, portRemote);
    remoteSocketToWS(tcpSocket, webSocket, retry, log);
}

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
            /**
             *
             * @param {Uint8Array} chunk
             * @param {*} controller
             */
            async write(chunk, controller) {
                hasIncomingData = true;
                if (webSocket.readyState !== WS_READY_STATE_OPEN) {
                    controller.error(
                        "webSocket connection is not open"
                    );
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
        console.error(
            `remoteSocketToWS error:`,
            error.stack || error
        );
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
export {
    worker_default as
    default
};
//# sourceMappingURL=worker.js.map
