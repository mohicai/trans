export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const parts = url.pathname.slice(1).split("/");

    // URL 格式： /UUID/文件路径...
    const uuid = parts.shift();
    const filePath = parts.join("/");

    // 校验 UUID
    if (uuid !== env.UUID) {
      return new Response("Invalid UUID", { status: 403 });
    }

    if (!filePath) {
      return new Response("Missing file path", { status: 400 });
    }

    // GitHub 仓库信息
    const owner = env.GH_OWNER || "mr";
    const repo = env.GH_REPO || "myrepo";
    const branch = env.GH_BRANCH || "main";
    const random = Math.random().toString(36).slice(2);

    // 获取GitHub文件内容
    const apiUrl = `https://api.github.com/repos/${owner}/${repo}/contents/${filePath}?ref=${branch}&t=${random}`;
    const githubResp = await fetch(apiUrl, {
      headers: {
        "Authorization": `token ${env.GITHUB_TOKEN}`,
        "User-Agent": "Cloudflare-Worker",
        "Accept": "application/vnd.github.v3.raw"
      },
      cache: "no-store"
    });

    if (!githubResp.ok) {
      return new Response(`GitHub API fetch failed: ${githubResp.status}`, {
        status: githubResp.status,
      });
    }

    // 获取订阅内容
    let content = await githubResp.text();
    
    // 检查是否需要替换HTTP代理的IP和端口
    if (content.includes("HTTP-IP")) {
      try {
        const httpIpPort = await getRedirectIpPort("http://stun.mohic.lol/http");
        if (httpIpPort) {
          content = replaceHttpServerPort(content, httpIpPort.ip, httpIpPort.port);
        }
      } catch (error) {
        console.error("Failed to get HTTP IP/Port:", error);
      }
    }

    // 检查是否需要替换VMess代理的IP和端口
    if (content.includes("VMESS-IP")) {
      try {
        const vmessIpPort = await getRedirectIpPort("http://stun.mohic.lol/vmess");
        if (vmessIpPort) {
          content = replaceVmessServerPort(content, vmessIpPort.ip, vmessIpPort.port);
        }
      } catch (error) {
        console.error("Failed to get VMess IP/Port:", error);
      }
    }

    // 检查是否需要替换WireGuard代理的endpoint
    if (content.includes("WireGuard-IP")) {
      try {
        const wgIpPort = await getRedirectIpPort("http://stun.mohic.lol/wg");
        if (wgIpPort) {
          content = replaceWireGuardEndpoint(content, wgIpPort.ip, wgIpPort.port);
        }
      } catch (error) {
        console.error("Failed to get WireGuard IP/Port:", error);
      }
    }

    // 返回处理后的内容
    return new Response(content, {
      status: 200,
      headers: {
        "Content-Type": githubResp.headers.get("Content-Type") || "application/octet-stream",
        "Cache-Control": "no-store, no-cache, must-revalidate",
        "Pragma": "no-cache",
        "Expires": "0",
        "X-Bypass-Random": random
      },
    });
  },
};

// 获取重定向URL中的IP和端口
async function getRedirectIpPort(url) {
  try {
    const response = await fetch(url, {
      redirect: "manual", // 不自动跟随重定向
      headers: {
        "User-Agent": "Cloudflare-Worker"
      }
    });

    // 获取重定向的Location
    const location = response.headers.get("Location");
    if (!location) {
      console.error("No redirect location found for:", url);
      return null;
    }

    // 解析Location中的IP和端口
    const urlObj = new URL(location);
    const ip = urlObj.hostname;
    const port = urlObj.port || (urlObj.protocol === "https:" ? "443" : "80");

    return { ip, port };
  } catch (error) {
    console.error("Error fetching redirect URL:", error);
    return null;
  }
}

// 替换HTTP代理的server和port
function replaceHttpServerPort(content, ip, port) {
  // 替换HTTP代理格式（Clash/V2Ray格式）
  const patterns = [
    // Clash格式: server: HTTP-IP, port: 8080
    { regex: /(server:\s*)HTTP-IP(\s*,\s*port:\s*)\d+/g, replacement: `$1${ip}$2${port}` },
    // V2Ray格式: "address": "HTTP-IP", "port": 8080
    { regex: /("address":\s*")HTTP-IP("\s*,\s*"port":\s*)\d+/g, replacement: `$1${ip}$2${port}` },
    // 通用格式: server = HTTP-IP, server_port = 8080
    { regex: /(server\s*=\s*)HTTP-IP(\s*,\s*server_port\s*=\s*)\d+/g, replacement: `$1${ip}$2${port}` }
  ];

  let newContent = content;
  patterns.forEach(pattern => {
    newContent = newContent.replace(pattern.regex, pattern.replacement);
  });

  return newContent;
}

// 替换VMess代理的server和port
function replaceVmessServerPort(content, ip, port) {
  // 替换VMess代理格式
  const patterns = [
    // Clash格式: server: VMESS-IP, port: 443
    { regex: /(server:\s*)VMESS-IP(\s*,\s*port:\s*)\d+/g, replacement: `$1${ip}$2${port}` },
    // V2RayN格式: "add": "VMESS-IP", "port": "443"
    { regex: /("add":\s*")VMESS-IP("\s*,\s*"port":\s*")\d+(")/g, replacement: `$1${ip}$2${port}$3` },
    // Base64编码的VMess链接（需要解码后替换再编码）
    { regex: /(vmess:\/\/[A-Za-z0-9+/=]+)/g, (match) => {
      try {
        const decoded = atob(match.split('://')[1]);
        if (decoded.includes('VMESS-IP')) {
          const replaced = decoded.replace(/"add":"VMESS-IP"/g, `"add":"${ip}"`)
                                 .replace(/"port":"\d+"/g, `"port":"${port}"`)
                                 .replace(/"port":\d+/g, `"port":${port}`);
          return `vmess://${btoa(replaced)}`;
        }
      } catch (e) {
        // 如果不是有效的Base64，跳过
      }
      return match;
    }}
  ];

  let newContent = content;
  patterns.forEach(pattern => {
    if (typeof pattern.replacement === 'function') {
      newContent = newContent.replace(pattern.regex, pattern.replacement);
    } else {
      newContent = newContent.replace(pattern.regex, pattern.replacement);
    }
  });

  return newContent;
}

// 替换WireGuard的endpoint
function replaceWireGuardEndpoint(content, ip, port) {
  // 替换WireGuard配置格式
  const patterns = [
    // 标准WireGuard格式: Endpoint = WireGuard-IP:51820
    { regex: /(Endpoint\s*=\s*)WireGuard-IP:\d+/g, replacement: `$1${ip}:${port}` },
    // Clash WireGuard格式: endpoint: WireGuard-IP:51820
    { regex: /(endpoint:\s*)WireGuard-IP:\d+/g, replacement: `$1${ip}:${port}` },
    // 简化格式: server: WireGuard-IP, port: 51820
    { regex: /(server:\s*)WireGuard-IP(\s*,\s*port:\s*)\d+/g, replacement: `$1${ip}$2${port}` }
  ];

  let newContent = content;
  patterns.forEach(pattern => {
    newContent = newContent.replace(pattern.regex, pattern.replacement);
  });

  return newContent;
}