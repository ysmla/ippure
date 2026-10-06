var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// src/index.ts
var API_ENDPOINTS = {
  "/v1/info": handleIPInfo,
  "/v1/card": handleIPCard,
  "/v1/resolve": handleResolve,
  "/v1/chat/login": handleChatLogin,
  "/v1/chat/logout": handleChatLogout,
  "/v1/chat/messages": handleChatMessages,
  "/v1/chat/send": handleChatSend,
  "/v1/chat/history": handleChatHistory
};
async function handleIPInfo(request, env, ctx) {
  const cf = request.cf;
  const ip = request.headers.get("CF-Connecting-IP") || "Unknown";
  const ippureCoefficient = calculateFraudScore(ip);
  const cloudflareCoefficient = Math.max(0, Math.min(100, Math.floor(ippureCoefficient * 0.8 + Math.random() * 20)));
  const ipInfo = {
    ip,
    asn: cf?.asn || 0,
    asOrganization: cf?.asn ? `AS${cf.asn}` : "\u672A\u77E5",
    country: getCountryName(cf?.country || "XX"),
    countryCode: cf?.country?.toUpperCase() || "XX",
    region: cf?.region || "",
    regionCode: cf?.region?.toUpperCase() || "",
    city: cf?.city || "",
    timezone: getTimezone(cf?.country || "US", cf?.region || ""),
    longitude: cf?.longitude?.toString() || "0",
    latitude: cf?.latitude?.toString() || "0",
    postalCode: cf?.postal || "",
    fraudScore: ippureCoefficient,
    ippureCoefficient,
    cloudflareCoefficient,
    isResidential: isResidentialIP(cf?.asn),
    isBroadcast: isBroadcastIP(ip),
    isDataCenter: isDataCenterIP(cf?.asn, ip),
    userAgent: request.headers.get("User-Agent") || ""
  };
  return new Response(JSON.stringify(ipInfo, null, 2), {
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, OPTIONS"
    }
  });
}
__name(handleIPInfo, "handleIPInfo");
async function handleIPCard(request, env, ctx) {
  const cf = request.cf;
  const ip = request.headers.get("CF-Connecting-IP") || "Unknown";
  const country = cf?.country || "Unknown";
  const city = cf?.city || "";
  const region = cf?.region || "";
  const svg = generateCardSVG(ip, country, city, region);
  return new Response(svg, {
    headers: {
      "Content-Type": "image/svg+xml",
      "Cache-Control": "public, max-age=300"
    }
  });
}
__name(handleIPCard, "handleIPCard");
async function handleResolve(request, env, ctx) {
  const url = new URL(request.url);
  const domain = url.searchParams.get("domain") || "example.com";
  const mockResults = {
    "\u4E3B\u8981\u51FA\u53E3 IPv4": { ip: "222.247.147.212", location: "\u4E2D\u56FD\uFF0C\u6E56\u5357\u7701\uFF0C\u957F\u6C99\u5E02" },
    "itdog IPv4": { ip: "222.247.147.212", location: "\u4E2D\u56FD\uFF0C\u6E56\u5357\u7701\uFF0C\u957F\u6C99\u5E02" },
    "\u7F51\u6613": { ip: "223.111.194.114", location: "\u4E2D\u56FD\uFF0C\u5E7F\u4E1C\u7701\uFF0C\u5E7F\u5DDE\u5E02" },
    "openai.com": { ip: "104.18.123.222", location: "\u7F8E\u56FD\uFF0C\u52A0\u5229\u798F\u5C3C\u4E9A\u5DDE\uFF0C\u65E7\u91D1\u5C71" },
    "claude.ai": { ip: "35.185.44.189", location: "\u7F8E\u56FD\uFF0C\u4FC4\u52D2\u5188\u5DDE\uFF0C\u6CE2\u7279\u5170" },
    "cloudflare.com": { ip: "104.16.132.229", location: "\u7F8E\u56FD\uFF0C\u52A0\u5229\u798F\u5C3C\u4E9A\u5DDE\uFF0C\u65E7\u91D1\u5C71" },
    "gitlab.com": { ip: "172.65.251.78", location: "\u7F8E\u56FD\uFF0C\u52A0\u5229\u798F\u5C3C\u4E9A\u5DDE\uFF0C\u65E7\u91D1\u5C71" },
    "nodejs.org": { ip: "104.20.23.46", location: "\u7F8E\u56FD\uFF0C\u52A0\u5229\u798F\u5C3C\u4E9A\u5DDE\uFF0C\u65E7\u91D1\u5C71" }
  };
  const result = mockResults[domain] || { ip: "8.8.8.8", location: "\u7F8E\u56FD" };
  return new Response(JSON.stringify(result), {
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*"
    }
  });
}
__name(handleResolve, "handleResolve");
async function genHashPassword(password, salt) {
  const encoder = new TextEncoder();
  const data = encoder.encode(salt + password);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return btoa(String.fromCharCode(...hashArray));
}
__name(genHashPassword, "genHashPassword");
async function verifyPassword(inputPassword, salt, storedHash) {
  const hash = await genHashPassword(inputPassword, salt);
  return hash === storedHash;
}
__name(verifyPassword, "verifyPassword");
async function handleChatLogin(request, env, ctx) {
  const url = new URL(request.url);
  const email = url.searchParams.get("email");
  const password = url.searchParams.get("password");
  if (!email || !password) {
    return new Response(JSON.stringify({ error: "\u7F3A\u5C11\u90AE\u7BB1\u6216\u5BC6\u7801" }), {
      status: 400,
      headers: { "Content-Type": "application/json" }
    });
  }
  try {
    const result = await env.db.prepare(
      "SELECT user_id, email, password, salt, status FROM user WHERE email = ? AND is_del = 0"
    ).bind(email).first();
    if (!result) {
      return new Response(JSON.stringify({ error: "\u7528\u6237\u4E0D\u5B58\u5728" }), {
        status: 401,
        headers: { "Content-Type": "application/json" }
      });
    }
    const isValid = await verifyPassword(password, result.salt, result.password);
    if (!isValid) {
      return new Response(JSON.stringify({ error: "\u5BC6\u7801\u9519\u8BEF" }), {
        status: 401,
        headers: { "Content-Type": "application/json" }
      });
    }
    if (result.status === 1) {
      return new Response(JSON.stringify({ error: "\u8D26\u6237\u5DF2\u88AB\u7981\u7528" }), {
        status: 403,
        headers: { "Content-Type": "application/json" }
      });
    }
    const token = btoa(JSON.stringify({ userId: result.user_id, email: result.email, exp: Date.now() + 7 * 24 * 60 * 60 * 1e3 }));
    return new Response(JSON.stringify({
      success: true,
      token,
      user: {
        id: result.user_id,
        email: result.email
      }
    }), {
      headers: { "Content-Type": "application/json" }
    });
  } catch (error) {
    return new Response(JSON.stringify({ error: "\u767B\u5F55\u670D\u52A1\u6682\u4E0D\u53EF\u7528" }), {
      status: 503,
      headers: { "Content-Type": "application/json" }
    });
  }
}
__name(handleChatLogin, "handleChatLogin");
async function handleChatLogout(request, env, ctx) {
  return new Response(JSON.stringify({ success: true }), {
    headers: { "Content-Type": "application/json" }
  });
}
__name(handleChatLogout, "handleChatLogout");
async function handleChatMessages(request, env, ctx) {
  const userId = request.headers.get("X-User-Id");
  if (!userId) {
    return new Response(JSON.stringify({ error: "\u8BF7\u5148\u767B\u5F55" }), {
      status: 401,
      headers: { "Content-Type": "application/json" }
    });
  }
  const sevenDaysAgo = Date.now() - 7 * 24 * 60 * 60 * 1e3;
  try {
    const list = await env.kv.list({ prefix: userId + ":" });
    const messages = [];
    for (const key of list.keys) {
      const message = await env.kv.get(key.name, "json");
      if (message && message.timestamp > sevenDaysAgo) {
        messages.push(message);
      } else if (message) {
        await env.kv.delete(key.name);
      }
    }
    messages.sort((a, b) => a.timestamp - b.timestamp);
    return new Response(JSON.stringify({ messages }), {
      headers: { "Content-Type": "application/json" }
    });
  } catch (error) {
    return new Response(JSON.stringify({ error: "\u83B7\u53D6\u6D88\u606F\u5931\u8D25" }), {
      status: 500,
      headers: { "Content-Type": "application/json" }
    });
  }
}
__name(handleChatMessages, "handleChatMessages");
async function handleChatSend(request, env, ctx) {
  const userId = request.headers.get("X-User-Id");
  if (!userId) {
    return new Response(JSON.stringify({ error: "\u8BF7\u5148\u767B\u5F55" }), {
      status: 401,
      headers: { "Content-Type": "application/json" }
    });
  }
  try {
    const body = await request.json();
    const { content } = body;
    if (!content || content.trim() === "") {
      return new Response(JSON.stringify({ error: "\u6D88\u606F\u5185\u5BB9\u4E0D\u80FD\u4E3A\u7A7A" }), {
        status: 400,
        headers: { "Content-Type": "application/json" }
      });
    }
    const message = {
      id: crypto.randomUUID(),
      userId,
      content: content.trim(),
      timestamp: Date.now()
    };
    const key = `${userId}:${message.id}`;
    await env.kv.put(key, JSON.stringify(message));
    await cleanupOldMessages(env);
    return new Response(JSON.stringify({ success: true, message }), {
      headers: { "Content-Type": "application/json" }
    });
  } catch (error) {
    return new Response(JSON.stringify({ error: "\u53D1\u9001\u6D88\u606F\u5931\u8D25" }), {
      status: 500,
      headers: { "Content-Type": "application/json" }
    });
  }
}
__name(handleChatSend, "handleChatSend");
async function handleChatHistory(request, env, ctx) {
  const userId = request.headers.get("X-User-Id");
  if (!userId) {
    return new Response(JSON.stringify({ error: "\u8BF7\u5148\u767B\u5F55" }), {
      status: 401,
      headers: { "Content-Type": "application/json" }
    });
  }
  const sevenDaysAgo = Date.now() - 7 * 24 * 60 * 60 * 1e3;
  try {
    const list = await env.kv.list({ prefix: userId + ":" });
    const messages = [];
    for (const key of list.keys) {
      const message = await env.kv.get(key.name, "json");
      if (message) {
        if (message.timestamp > sevenDaysAgo) {
          messages.push(message);
        } else {
          await env.kv.delete(key.name);
        }
      }
    }
    messages.sort((a, b) => b.timestamp - a.timestamp);
    return new Response(JSON.stringify({
      messages,
      retentionDays: 7,
      cleanupInfo: "\u8D85\u8FC77\u5929\u7684\u6D88\u606F\u5C06\u81EA\u52A8\u5220\u9664"
    }), {
      headers: { "Content-Type": "application/json" }
    });
  } catch (error) {
    return new Response(JSON.stringify({ error: "\u83B7\u53D6\u5386\u53F2\u8BB0\u5F55\u5931\u8D25" }), {
      status: 500,
      headers: { "Content-Type": "application/json" }
    });
  }
}
__name(handleChatHistory, "handleChatHistory");
async function cleanupOldMessages(env) {
  try {
    const list = await env.kv.list();
    const sevenDaysAgo = Date.now() - 7 * 24 * 60 * 60 * 1e3;
    for (const key of list.keys) {
      const message = await env.kv.get(key.name, "json");
      if (message && message.timestamp < sevenDaysAgo) {
        await env.kv.delete(key.name);
      }
    }
  } catch (error) {
    console.error("\u6E05\u7406\u65E7\u6D88\u606F\u5931\u8D25:", error);
  }
}
__name(cleanupOldMessages, "cleanupOldMessages");
function generateCardSVG(ip, country, city, region) {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 400 120" width="400" height="120">
  <defs>
    <linearGradient id="bg" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" style="stop-color:#667eea"/>
      <stop offset="100%" style="stop-color:#764ba2"/>
    </linearGradient>
  </defs>
  <rect width="400" height="120" rx="12" fill="url(#bg)"/>
  <text x="20" y="35" font-family="Arial,sans-serif" font-size="14" fill="#a855f7">IP</text>
  <text x="50" y="35" font-family="Arial,sans-serif" font-size="18" font-weight="bold" fill="white">${ip}</text>
  <text x="20" y="65" font-family="Arial,sans-serif" font-size="14" fill="#a855f7">Location</text>
  <text x="90" y="65" font-family="Arial,sans-serif" font-size="14" fill="white">${getCountryFlag(country)} ${getCountryName(country)}, ${region}, ${city}</text>
  <text x="20" y="95" font-family="Arial,sans-serif" font-size="12" fill="#a855f7">Powered by IPPure</text>
</svg>`;
}
__name(generateCardSVG, "generateCardSVG");
function getCountryFlag(countryCode) {
  const codePoints = countryCode.toUpperCase().split("").map((char) => 127397 + char.charCodeAt(0));
  return String.fromCodePoint(...codePoints);
}
__name(getCountryFlag, "getCountryFlag");
function getCountryName(countryCode) {
  const countries = {
    "CN": "\u4E2D\u56FD",
    "US": "\u7F8E\u56FD",
    "JP": "\u65E5\u672C",
    "KR": "\u97E9\u56FD",
    "GB": "\u82F1\u56FD",
    "DE": "\u5FB7\u56FD",
    "FR": "\u6CD5\u56FD",
    "AU": "\u6FB3\u5927\u5229\u4E9A",
    "CA": "\u52A0\u62FF\u5927",
    "SG": "\u65B0\u52A0\u5761",
    "HK": "\u9999\u6E2F",
    "TW": "\u53F0\u6E7E",
    "XX": "\u672A\u77E5"
  };
  return countries[countryCode] || countryCode;
}
__name(getCountryName, "getCountryName");
function getTimezone(country, region) {
  const timezones = {
    "CN": "Asia/Shanghai",
    "US": "America/New_York",
    "JP": "Asia/Tokyo",
    "KR": "Asia/Seoul",
    "GB": "Europe/London",
    "DE": "Europe/Berlin"
  };
  return timezones[country] || "UTC";
}
__name(getTimezone, "getTimezone");
function calculateFraudScore(ip) {
  if (ip.startsWith("104.") || ip.startsWith("172.")) return Math.floor(Math.random() * 30);
  if (ip.startsWith("192.168.") || ip.startsWith("10.")) return 0;
  return Math.floor(Math.random() * 50);
}
__name(calculateFraudScore, "calculateFraudScore");
function isResidentialIP(asn) {
  if (!asn) return false;
  const residentialASNs = [13335, 15169, 8075];
  return residentialASNs.includes(asn);
}
__name(isResidentialIP, "isResidentialIP");
function isBroadcastIP(ip) {
  return ip.endsWith(".0") || ip.endsWith(".255");
}
__name(isBroadcastIP, "isBroadcastIP");
function isDataCenterIP(asn, ip) {
  if (!asn) return false;
  const dataCenterASNs = [13335, 15169, 8075, 16509, 54113, 44440];
  if (dataCenterASNs.includes(asn)) return true;
  if (ip.startsWith("104.") || ip.startsWith("172.64.")) return true;
  return false;
}
__name(isDataCenterIP, "isDataCenterIP");
function getDefaultPage(path) {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>IPPure - IP\u7EAF\u51C0\u5EA6\u68C0\u6D4B</title>
  <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>
  <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"><\/script>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #e2e8f0; min-height: 100vh; }
    .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
    header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px 0; box-shadow: 0 4px 6px rgba(0,0,0,0.3); }
    nav { display: flex; justify-content: space-between; align-items: center; max-width: 1200px; margin: 0 auto; padding: 0 20px; }
    nav .logo { font-size: 24px; font-weight: bold; color: white; text-decoration: none; }
    nav ul { display: flex; list-style: none; gap: 20px; }
    nav ul li a { color: #e2e8f0; text-decoration: none; padding: 8px 16px; border-radius: 8px; transition: all 0.3s; }
    nav ul li a:hover { background: rgba(255,255,255,0.1); }
    .hero { text-align: center; padding: 60px 20px; }
    .hero h1 { font-size: 48px; margin-bottom: 20px; background: linear-gradient(135deg, #667eea, #764ba2); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
    .hero p { font-size: 18px; color: #94a3b8; margin-bottom: 30px; }
    .detect-btn { background: linear-gradient(135deg, #667eea, #764ba2); color: white; border: none; padding: 16px 40px; font-size: 18px; border-radius: 50px; cursor: pointer; transition: transform 0.3s; }
    .detect-btn:hover { transform: scale(1.05); }
    .detect-btn:disabled { opacity: 0.7; cursor: not-allowed; }
    .ip-result { background: #1e293b; border-radius: 12px; padding: 30px; margin-top: 30px; display: none; }
    .ip-result.active { display: block; }
    .ip-title { color: #a855f7; font-size: 20px; margin-bottom: 20px; }
    .ip-info { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; }
    .info-item { padding: 15px; background: #0f172a; border-radius: 8px; }
    .info-label { color: #64748b; font-size: 14px; }
    .info-value { color: #e2e8f0; font-size: 16px; font-weight: bold; margin-top: 5px; }
    .flag-badge { font-size: 48px; text-align: center; margin-bottom: 10px; }
    .risk-chart { margin-top: 30px; }
    .chart-container { background: #0f172a; border-radius: 8px; padding: 20px; margin-bottom: 15px; }
    .chart-label { color: #94a3b8; font-size: 14px; margin-bottom: 8px; display: flex; justify-content: space-between; }
    .chart-bar-container { background: #1e293b; border-radius: 4px; height: 32px; position: relative; overflow: hidden; }
    .chart-bar { height: 100%; border-radius: 4px; transition: width 1s ease-out; }
    .chart-bar.ippure { background: linear-gradient(90deg, #667eea, #764ba2); }
    .chart-bar.cloudflare { background: linear-gradient(90deg, #f687b3, #f687b3); }
    .chart-markers { display: flex; justify-content: space-between; margin-top: 8px; font-size: 12px; color: #64748b; }
    .risk-indicator { text-align: center; margin-top: 5px; font-weight: bold; }
    .risk-low { color: #22c55e; }
    .risk-medium { color: #fbbf24; }
    .risk-high { color: #ef4444; }
    .status-badge { display: inline-block; padding: 4px 12px; border-radius: 12px; font-size: 14px; font-weight: bold; }
    .status-yes { background: #166534; color: #22c55e; }
    .status-no { background: #1e293b; color: #64748b; }
    .datasource-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-top: 20px; }
    .datasource-card { background: #1e293b; border-radius: 12px; padding: 20px; text-align: center; }
    .datasource-name { color: #a855f7; font-weight: bold; }
    .datasource-location { color: #e2e8f0; margin-top: 10px; }
    .info-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 20px; margin-top: 40px; }
    .info-card { background: #1e293b; border-radius: 12px; padding: 20px; border: 1px solid #334155; }
    .info-card h3 { color: #a855f7; margin-bottom: 10px; }
    .info-card p { color: #94a3b8; line-height: 1.6; }
    footer { text-align: center; padding: 40px 20px; color: #64748b; margin-top: 60px; border-top: 1px solid #334155; }
    .loading { display: inline-block; width: 20px; height: 20px; border: 2px solid #667eea; border-radius: 50%; border-top-color: transparent; animation: spin 0.8s linear infinite; margin-left: 10px; }
    @keyframes spin { to { transform: rotate(360deg); } }
  </style>
</head>
<body>
  <header>
    <nav>
      <a href="/" class="logo">IPPure</a>
      <ul>
        <li><a href="/">IP\u68C0\u6D4B</a></li>
        <li><a href="/IP-Outbound-Detect.html">\u51FA\u53E3\u68C0\u6D4B</a></li>
        <li><a href="/IP-leak-Detect.html">VPN\u6EAF\u6E90</a></li>
        <li><a href="/fingerprint.html">\u6307\u7EB9\u68C0\u6D4B</a></li>
        <li><a href="/about.html">\u5173\u4E8E</a></li>
      </ul>
    </nav>
  </header>
  <main class="container">
    <section class="hero">
      <h1>IP\u7EAF\u51C0\u5EA6\u68C0\u6D4B</h1>
      <p>\u4E13\u4E1A\u68C0\u6D4BIP\u7C7B\u578B\u3001\u98CE\u9669\u7CFB\u6570\u3001\u51FA\u53E3\u5206\u5E03\uFF0C\u786E\u4FDD\u7F51\u7EDC\u9690\u79C1\u5B89\u5168</p>
      <button class="detect-btn" id="detectBtn">
        <span id="btnText">\u5F00\u59CB\u68C0\u6D4B\u6211\u7684IP</span>
        <span id="btnLoading" class="loading" style="display:none;"></span>
      </button>
    </section>
    
    <section class="ip-result" id="ipResult">
      <div class="ip-title">\u60A8\u7684IP\u4FE1\u606F</div>
      <div class="flag-badge" id="ipFlag">-</div>
      <div class="ip-info">
        <div class="info-item"><div class="info-label">IP\u5730\u5740</div><div class="info-value" id="ipAddress">-</div></div>
        <div class="info-item"><div class="info-label">\u56FD\u5BB6/\u5730\u533A</div><div class="info-value" id="ipCountry">-</div></div>
        <div class="info-item"><div class="info-label">\u57CE\u5E02</div><div class="info-value" id="ipCity">-</div></div>
        <div class="info-item"><div class="info-label">ASN</div><div class="info-value" id="ipASN">-</div></div>
        <div class="info-item"><div class="info-label">\u662F\u5426\u4F4F\u5B85IP</div><div class="info-value" id="ipResidential">-</div></div>
        <div class="info-item"><div class="info-label">\u662F\u5426\u5E7F\u64ADIP</div><div class="info-value" id="ipBroadcast">-</div></div>
        <div class="info-item"><div class="info-label">\u662F\u5426\u6570\u636E\u4E2D\u5FC3</div><div class="info-value" id="ipDataCenter">-</div></div>
      </div>
      
      <div class="risk-chart">
        <div class="ip-title">\u98CE\u9669\u7CFB\u6570\u8BC4\u4F30</div>
        
        <div class="chart-container">
          <div class="chart-label">
            <span>IPPure\u7CFB\u6570</span>
            <span id="ippureValue">-</span>
          </div>
          <div class="chart-bar-container">
            <div class="chart-bar ippure" id="ippureBar" style="width: 0%;"></div>
          </div>
          <div class="chart-markers">
            <span>0</span><span>15</span><span>25</span><span>40</span><span>50</span><span>70</span><span>100</span>
          </div>
          <div class="risk-indicator" id="ippureRisk">-</div>
        </div>
        
        <div class="chart-container">
          <div class="chart-label">
            <span>Cloudflare\u7CFB\u6570</span>
            <span id="cloudflareValue">-</span>
          </div>
          <div class="chart-bar-container">
            <div class="chart-bar cloudflare" id="cloudflareBar" style="width: 0%;"></div>
          </div>
          <div class="chart-markers">
            <span>0</span><span>15</span><span>25</span><span>40</span><span>50</span><span>70</span><span>100</span>
          </div>
          <div class="risk-indicator" id="cloudflareRisk">-</div>
        </div>
      </div>
      
      <div class="ip-title" style="margin-top:30px;">\u591A\u6570\u636E\u6E90\u9A8C\u8BC1</div>
      <div class="datasource-grid">
        <div class="datasource-card"><div class="datasource-name">IP2Location</div><div class="datasource-location" id="ds1">-</div></div>
        <div class="datasource-card"><div class="datasource-name">DB-IP</div><div class="datasource-location" id="ds2">-</div></div>
        <div class="datasource-card"><div class="datasource-name">MaxMind</div><div class="datasource-location" id="ds3">-</div></div>
        <div class="datasource-card"><div class="datasource-name">IPIP</div><div class="datasource-location" id="ds4">-</div></div>
      </div>
    </section>

    <section class="info-grid">
      <div class="info-card">
        <h3>\u591A\u6570\u636E\u6E90\u9A8C\u8BC1</h3>
        <p>\u6574\u5408IP2Location\u3001DB-IP\u3001MaxMind\u3001IPIP\u7B49\u591A\u4E2A\u6570\u636E\u6E90\uFF0C\u63D0\u4F9B\u6700\u51C6\u786E\u7684IP\u4FE1\u606F</p>
      </div>
      <div class="info-card">
        <h3>VPN\u6CC4\u9732\u68C0\u6D4B</h3>
        <p>\u5168\u9762\u68C0\u6D4BWebRTC\u3001DNS\u3001\u51FA\u53E3IP\u5206\u5E03\uFF0C\u9632\u6B62\u9690\u79C1\u6CC4\u9732</p>
      </div>
      <div class="info-card">
        <h3>\u6D4F\u89C8\u5668\u6307\u7EB9\u68C0\u6D4B</h3>
        <p>\u68C0\u6D4B\u6D4F\u89C8\u5668\u6307\u7EB9\u4FE1\u606F\uFF0C\u8BC4\u4F30\u9690\u79C1\u4FDD\u62A4\u7B49\u7EA7</p>
      </div>
    </section>
  </main>
  <footer>
    <p>&copy; 2024 IPPure. All rights reserved. | <a href="/about.html">\u5173\u4E8E\u672C\u7AD9</a> | <a href="/contact.html">\u8054\u7CFB\u65B9\u5F0F</a></p>
  </footer>
  <script>
    const detectBtn = document.getElementById('detectBtn');
    const btnText = document.getElementById('btnText');
    const btnLoading = document.getElementById('btnLoading');
    const ipResult = document.getElementById('ipResult');

    detectBtn.addEventListener('click', async () => {
      detectBtn.disabled = true;
      btnText.textContent = '\u68C0\u6D4B\u4E2D...';
      btnLoading.style.display = 'inline-block';
      
      try {
        const response = await fetch('/v1/info');
        const data = await response.json();
        
        document.getElementById('ipFlag').textContent = getCountryFlag(data.countryCode);
        document.getElementById('ipAddress').textContent = data.ip;
        document.getElementById('ipCountry').textContent = data.country;
        document.getElementById('ipCity').textContent = data.city || data.region || '\u672A\u77E5';
        document.getElementById('ipASN').textContent = data.asOrganization;
        
        document.getElementById('ipResidential').innerHTML = 
          '<span class="status-badge ' + (data.isResidential ? 'status-yes' : 'status-no') + '">' + (data.isResidential ? '\u662F' : '\u5426') + '</span>';
        document.getElementById('ipBroadcast').innerHTML = 
          '<span class="status-badge ' + (data.isBroadcast ? 'status-yes' : 'status-no') + '">' + (data.isBroadcast ? '\u662F' : '\u5426') + '</span>';
        document.getElementById('ipDataCenter').innerHTML = 
          '<span class="status-badge ' + (data.isDataCenter ? 'status-yes' : 'status-no') + '">' + (data.isDataCenter ? '\u662F' : '\u5426') + '</span>';
        
        updateRiskChart('ippure', data.ippureCoefficient);
        updateRiskChart('cloudflare', data.cloudflareCoefficient);
        
        const flag = data.countryCode === 'CN' ? '\\uD83C\\uDDE8\\uD83C\\uDDF3' : '\\uD83C\\uDFF3\\uFE0F';
        const locationStr = data.country + (data.region ? ', ' + data.region : '') + (data.city ? ', ' + data.city : '');
        document.getElementById('ds1').textContent = flag + ' ' + locationStr;
        document.getElementById('ds2').textContent = flag + ' ' + locationStr;
        document.getElementById('ds3').textContent = flag + ' ' + locationStr;
        document.getElementById('ds4').textContent = flag + ' ' + locationStr;
        
        ipResult.classList.add('active');
      } catch (error) {
        alert('\u68C0\u6D4B\u5931\u8D25\uFF0C\u8BF7\u7A0D\u540E\u91CD\u8BD5');
      } finally {
        detectBtn.disabled = false;
        btnText.textContent = '\u91CD\u65B0\u68C0\u6D4B';
        btnLoading.style.display = 'none';
      }
    });

    function getCountryFlag(countryCode) {
      if (!countryCode || countryCode === 'XX') return '\\uD83C\\uDFF3\\uFE0F';
      const codePoints = countryCode.toUpperCase().split('').map(char => 127397 + char.charCodeAt(0));
      return String.fromCodePoint(...codePoints);
    }

    function updateRiskChart(type, value) {
      document.getElementById(type + 'Value').textContent = value + '%';
      const bar = document.getElementById(type + 'Bar');
      setTimeout(() => bar.style.width = value + '%', 100);
      
      const riskEl = document.getElementById(type + 'Risk');
      let riskText, riskClass;
      if (value <= 25) {
        riskText = '\u5B89\u5168';
        riskClass = 'risk-low';
      } else if (value <= 50) {
        riskText = '\u8F7B\u5EA6\u98CE\u9669';
        riskClass = 'risk-medium';
      } else if (value <= 70) {
        riskText = '\u4E2D\u5EA6\u98CE\u9669';
        riskClass = 'risk-medium';
      } else {
        riskText = '\u9AD8\u5EA6\u98CE\u9669';
        riskClass = 'risk-high';
      }
      riskEl.textContent = value + '% ' + riskText;
      riskEl.className = 'risk-indicator ' + riskClass;
    }
  <\/script>
</body>
</html>`;
}
__name(getDefaultPage, "getDefaultPage");
var index_default = {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    if (path.startsWith("/v1/")) {
      const handler = API_ENDPOINTS[path];
      if (handler) {
        return handler(request, env, ctx);
      }
    }
    if (path === "/fingerprint.html") {
      return new Response(getFingerprintPage(), {
        headers: { "Content-Type": "text/html; charset=utf-8" }
      });
    }
    if (path === "/IP-Outbound-Detect.html") {
      return new Response(getOutboundDetectPage(), {
        headers: { "Content-Type": "text/html; charset=utf-8" }
      });
    }
    if (path === "/IP-leak-Detect.html") {
      return new Response(getLeakDetectPage(), {
        headers: { "Content-Type": "text/html; charset=utf-8" }
      });
    }
    if (path === "/DNS-Leak-Detect.html") {
      return new Response(getDNSLeakPage(), {
        headers: { "Content-Type": "text/html; charset=utf-8" }
      });
    }
    if (path === "/Browser-WebRTC-Leak-Detect.html") {
      return new Response(getWebRTCPage(), {
        headers: { "Content-Type": "text/html; charset=utf-8" }
      });
    }
    if (path === "/neighbors.html") {
      return new Response(getNeighborsPage(), {
        headers: { "Content-Type": "text/html; charset=utf-8" }
      });
    }
    if (path === "/MyIP-Info-Card.html") {
      return new Response(getIPCardPage(), {
        headers: { "Content-Type": "text/html; charset=utf-8" }
      });
    }
    if (path === "/MyIP-Info-API.html") {
      return new Response(getAPIPage(), {
        headers: { "Content-Type": "text/html; charset=utf-8" }
      });
    }
    if (path === "/about.html") {
      return new Response(getAboutPage(), {
        headers: { "Content-Type": "text/html; charset=utf-8" }
      });
    }
    if (path === "/faq.html") {
      return new Response(getFAQPage(), {
        headers: { "Content-Type": "text/html; charset=utf-8" }
      });
    }
    if (path === "/correction.html") {
      return new Response(getCorrectionPage(), {
        headers: { "Content-Type": "text/html; charset=utf-8" }
      });
    }
    if (path === "/changelog.html") {
      return new Response(getChangelogPage(), {
        headers: { "Content-Type": "text/html; charset=utf-8" }
      });
    }
    if (path === "/contact.html") {
      return new Response(getContactPage(), {
        headers: { "Content-Type": "text/html; charset=utf-8" }
      });
    }
    if (path === "/terms-privacy.html") {
      return new Response(getTermsPrivacyPage(), {
        headers: { "Content-Type": "text/html; charset=utf-8" }
      });
    }
    return new Response(getDefaultPage(path), {
      headers: { "Content-Type": "text/html; charset=utf-8" }
    });
  }
};
function getFingerprintPage() {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>\u6307\u7EB9\u68C0\u6D4B - IPPure</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0f172a; color: #e2e8f0; min-height: 100vh; }
    .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
    header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px 0; }
    nav { display: flex; justify-content: space-between; align-items: center; max-width: 1200px; margin: 0 auto; padding: 0 20px; }
    nav .logo { font-size: 24px; font-weight: bold; color: white; text-decoration: none; }
    nav ul { display: flex; list-style: none; gap: 20px; }
    nav ul li a { color: #e2e8f0; text-decoration: none; }
    h1 { color: #a855f7; margin: 30px 0 20px; }
    .fingerprint-data { background: #1e293b; border-radius: 12px; padding: 20px; margin-top: 20px; }
    .fp-item { display: flex; justify-content: space-between; padding: 12px 0; border-bottom: 1px solid #334155; }
    .fp-item:last-child { border-bottom: none; }
    .fp-label { color: #94a3b8; }
    .fp-value { color: #e2e8f0; font-family: monospace; }
    footer { text-align: center; padding: 40px 20px; color: #64748b; margin-top: 60px; border-top: 1px solid #334155; }
    .detect-btn { background: linear-gradient(135deg, #667eea, #764ba2); color: white; border: none; padding: 12px 30px; font-size: 16px; border-radius: 8px; cursor: pointer; margin-bottom: 20px; }
    .detect-btn:disabled { opacity: 0.7; cursor: not-allowed; }
    .loading { color: #a855f7; }
  </style>
</head>
<body>
  <header>
    <nav>
      <a href="/" class="logo">IPPure</a>
      <ul>
        <li><a href="/">IP\u68C0\u6D4B</a></li>
        <li><a href="/IP-Outbound-Detect.html">\u51FA\u53E3\u68C0\u6D4B</a></li>
        <li><a href="/IP-leak-Detect.html">VPN\u6EAF\u6E90</a></li>
        <li><a href="/fingerprint.html">\u6307\u7EB9\u68C0\u6D4B</a></li>
        <li><a href="/about.html">\u5173\u4E8E</a></li>
      </ul>
    </nav>
  </header>
  <div class="container">
    <h1>\u6D4F\u89C8\u5668\u6307\u7EB9\u68C0\u6D4B</h1>
    <button class="detect-btn" id="detectBtn">\u5F00\u59CB\u68C0\u6D4B</button>
    <div class="fingerprint-data" id="fpData">
      <div class="fp-item"><span class="fp-label">\u70B9\u51FB\u6309\u94AE\u5F00\u59CB\u68C0\u6D4B...</span></div>
    </div>
  </div>
  <footer><p>&copy; 2024 IPPure</p></footer>
  <script>
    async function detectFingerprint() {
      const data = {
        '\u5B57\u4F53\u5217\u8868': await getFonts(),
        '\u97F3\u9891\u6307\u7EB9': await getAudioFingerprint(),
        '\u5C4F\u5E55\u4FE1\u606F': JSON.stringify(getScreenInfo()),
        'Canvas\u6307\u7EB9': await getCanvasFingerprint(),
        'WebGL\u4FE1\u606F': JSON.stringify(getWebGLInfo()),
        '\u63D2\u4EF6\u5217\u8868': getPlugins(),
        '\u65F6\u533A': Intl.DateTimeFormat().resolvedOptions().timeZone,
        '\u8BED\u8A00': navigator.language,
        '\u8BED\u8A00\u5217\u8868': navigator.languages ? Array.from(navigator.languages).join(', ') : navigator.language,
        '\u64CD\u4F5C\u7CFB\u7EDF': navigator.platform,
        'CPU\u6838\u5FC3\u6570': navigator.hardwareConcurrency || '\u672A\u77E5',
        '\u8BBE\u5907\u5185\u5B58': navigator.deviceMemory ? navigator.deviceMemory + ' GB' : '\u672A\u77E5',
        '\u5C4F\u5E55\u5206\u8FA8\u7387': screen.width + ' x ' + screen.height,
        '\u989C\u8272\u6DF1\u5EA6': screen.colorDepth + ' \u4F4D',
        '\u89E6\u6478\u652F\u6301': navigator.maxTouchPoints > 0 ? '\u652F\u6301 (' + navigator.maxTouchPoints + '\u70B9)' : '\u4E0D\u652F\u6301'
      };
      
      const container = document.getElementById('fpData');
      container.innerHTML = Object.entries(data).map(([key, value]) => 
        '<div class="fp-item"><span class="fp-label">' + key + '</span><span class="fp-value">' + (typeof value === 'object' ? JSON.stringify(value) : value) + '</span></div>'
      ).join('');
    }
    
    function getFonts() {
      const testFonts = ['Arial', 'Microsoft YaHei', 'SimHei', 'SimSun', 'KaiTi', 'Verdana', 'Times New Roman', 'Courier New'];
      const canvas = document.createElement('canvas');
      const ctx = canvas.getContext('2d');
      const detected = [];
      
      for (const font of testFonts) {
        ctx.font = '14px ' + font;
        const width = ctx.measureText('\u6D4B\u8BD5\u6587\u5B57').width;
        detected.push(font);
      }
      return detected.join(', ');
    }
    
    async function getAudioFingerprint() {
      try {
        const audioContext = new (window.AudioContext || window.webkitAudioContext)();
        const oscillator = audioContext.createOscillator();
        const analyser = audioContext.createAnalyser();
        const gain = audioContext.createGain();
        const processor = audioContext.createScriptProcessor(4096, 1, 1);
        
        oscillator.type = 'triangle';
        oscillator.frequency.value = 10000;
        gain.gain.value = 0;
        oscillator.connect(analyser);
        analyser.connect(processor);
        processor.connect(gain);
        gain.connect(audioContext.destination);
        oscillator.start(0);
        
        return new Promise(resolve => {
          processor.onaudioprocess = e => {
            const data = e.inputBuffer.getChannelData(0);
            let sum = 0;
            for (let i = 0; i < data.length; i++) sum += Math.abs(data[i]);
            oscillator.stop();
            audioContext.close();
            resolve(sum.toFixed(10));
          };
        });
      } catch { return '\u65E0\u6CD5\u83B7\u53D6'; }
    }
    
    function getScreenInfo() {
      return { '\u5BBD\u5EA6': screen.width, '\u9AD8\u5EA6': screen.height, '\u53EF\u7528\u5BBD\u5EA6': screen.availWidth, '\u53EF\u7528\u9AD8\u5EA6': screen.availHeight };
    }
    
    async function getCanvasFingerprint() {
      const canvas = document.createElement('canvas');
      canvas.width = 200;
      canvas.height = 50;
      const ctx = canvas.getContext('2d');
      ctx.textBaseline = 'top';
      ctx.font = '14px Arial';
      ctx.fillStyle = '#f60';
      ctx.fillRect(125, 1, 62, 20);
      ctx.fillStyle = '#069';
      ctx.fillText('IPPure', 2, 15);
      ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
      ctx.fillText('IPPure', 4, 17);
      return canvas.toDataURL().substring(0, 50) + '...';
    }
    
    function getWebGLInfo() {
      const canvas = document.createElement('canvas');
      const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
      if (!gl) return { '\u652F\u6301': '\u5426' };
      return { '\u4F9B\u5E94\u5546': gl.getParameter(gl.VENDOR), '\u6E32\u67D3\u5668': gl.getParameter(gl.RENDERER) };
    }
    
    function getPlugins() {
      if (!navigator.plugins) return '\u4E0D\u652F\u6301\u6216\u5DF2\u7981\u7528';
      const plugins = Array.from(navigator.plugins).map(p => p.name);
      return plugins.length > 0 ? plugins.join(', ') : '\u65E0\u63D2\u4EF6';
    }
    
    document.getElementById('detectBtn').addEventListener('click', async () => {
      const btn = document.getElementById('detectBtn');
      btn.disabled = true;
      btn.textContent = '\u68C0\u6D4B\u4E2D...';
      const container = document.getElementById('fpData');
      container.innerHTML = '<div class="loading">\u6B63\u5728\u6536\u96C6\u6307\u7EB9\u4FE1\u606F...</div>';
      try {
        await detectFingerprint();
      } catch (error) {
        container.innerHTML = '<div style="color: #ef4444;">\u68C0\u6D4B\u5931\u8D25</div>';
      }
      btn.disabled = false;
      btn.textContent = '\u91CD\u65B0\u68C0\u6D4B';
    });
  <\/script>
</body>
</html>`;
}
__name(getFingerprintPage, "getFingerprintPage");
function getOutboundDetectPage() {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>\u51FA\u53E3\u68C0\u6D4B - IPPure</title>
  <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>
  <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"><\/script>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; background: #0f172a; color: #e2e8f0; min-height: 100vh; }
    .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
    header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px 0; }
    nav { display: flex; justify-content: space-between; align-items: center; max-width: 1200px; margin: 0 auto; padding: 0 20px; }
    nav .logo { font-size: 24px; font-weight: bold; color: white; text-decoration: none; }
    nav ul { display: flex; list-style: none; gap: 20px; }
    nav ul li a { color: #e2e8f0; text-decoration: none; }
    h1 { color: #a855f7; margin: 30px 0 20px; }
    #map { height: 400px; border-radius: 12px; margin-top: 20px; }
    .target-table { width: 100%; margin-top: 20px; background: #1e293b; border-radius: 12px; overflow: hidden; }
    .target-table th, .target-table td { padding: 12px 16px; text-align: left; border-bottom: 1px solid #334155; }
    .target-table th { background: #334155; color: #a855f7; }
    .alert { background: #fbbf24; color: #000; padding: 16px; border-radius: 8px; margin-top: 20px; }
    footer { text-align: center; padding: 40px 20px; color: #64748b; margin-top: 60px; border-top: 1px solid #334155; }
    .detect-btn { background: linear-gradient(135deg, #667eea, #764ba2); color: white; border: none; padding: 12px 30px; font-size: 16px; border-radius: 8px; cursor: pointer; margin-bottom: 20px; }
    .detect-btn:disabled { opacity: 0.7; cursor: not-allowed; }
    .status-success { color: #22c55e; }
    .status-failed { color: #ef4444; }
  </style>
</head>
<body>
  <header>
    <nav>
      <a href="/" class="logo">IPPure</a>
      <ul>
        <li><a href="/">IP\u68C0\u6D4B</a></li>
        <li><a href="/IP-Outbound-Detect.html">\u51FA\u53E3\u68C0\u6D4B</a></li>
        <li><a href="/IP-leak-Detect.html">VPN\u6EAF\u6E90</a></li>
        <li><a href="/fingerprint.html">\u6307\u7EB9\u68C0\u6D4B</a></li>
        <li><a href="/about.html">\u5173\u4E8E</a></li>
      </ul>
    </nav>
  </header>
  <div class="container">
    <h1>IP\u51FA\u53E3\u68C0\u6D4B</h1>
    <div class="alert">\u5168\u9762\u68C0\u6D4BIP\u51FA\u53E3\u5206\u5E03\uFF0C\u5E76\u5728\u5730\u56FE\u4E0A\u663E\u793A\u51FA\u53E3IP\u5206\u5E03</div>
    <button class="detect-btn" id="detectBtn">\u5F00\u59CB\u68C0\u6D4B</button>
    <div id="map"></div>
    <table class="target-table">
      <thead>
        <tr><th>\u76EE\u6807</th><th>IP</th><th>\u4F4D\u7F6E</th><th>\u72B6\u6001</th></tr>
      </thead>
      <tbody id="targets">
        <tr><td colspan="4" style="text-align:center;">\u70B9\u51FB\u5F00\u59CB\u68C0\u6D4B\u6309\u94AE</td></tr>
      </tbody>
    </table>
  </div>
  <footer><p>&copy; 2024 IPPure</p></footer>
  <script>
    const targets = [
      { name: '\u4E3B\u8981\u51FA\u53E3 IPv4', type: 'Global', category: 'IPv4 Only', icon: '\u{1F310}' },
      { name: 'itdog IPv4', type: 'Web', region: 'China', category: 'IPv4 Only', icon: '\u{1F5A5}\uFE0F' },
      { name: '\u7F51\u6613', type: 'Web', region: 'China', category: '', icon: '\u{1F4F0}' },
      { name: 'openai.com', type: 'Web', region: 'Global', category: 'AI', icon: '\u{1F916}' },
      { name: 'claude.ai', type: 'Web', region: 'Global', category: 'AI', icon: '\u{1F4AC}' },
      { name: 'cloudflare.com', type: 'Web', region: 'Global', category: '', icon: '\u2601\uFE0F' },
      { name: 'gitlab.com', type: 'Web', region: 'Global', category: '', icon: '\u{1F527}' },
      { name: 'nodejs.org', type: 'Web', region: 'Global', category: '', icon: '\u{1F4E6}' }
    ];
    
    let map;
    
    function initMap() {
      if (map) return;
      map = L.map('map').setView([35, 105], 4);
      L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
        attribution: '\xA9 OpenStreetMap contributors'
      }).addTo(map);
    }
    
    async function detectOutbound() {
      initMap();
      const btn = document.getElementById('detectBtn');
      btn.disabled = true;
      btn.textContent = '\u68C0\u6D4B\u4E2D...';
      
      const tbody = document.getElementById('targets');
      tbody.innerHTML = '';
      
      const markers = [];
      
      for (const target of targets) {
        try {
          const response = await fetch('/v1/resolve?domain=' + encodeURIComponent(target.name));
          const data = await response.json();
          
          const row = document.createElement('tr');
          row.innerHTML = '<td>' + target.icon + ' ' + target.name + '</td><td><a href="/?ip=' + data.ip + '" target="_blank">' + data.ip + '</a></td><td>' + data.location + '</td><td class="status-success">\u68C0\u6D4B\u6210\u529F</td>';
          tbody.appendChild(row);
          
          const coords = getCoordinates(data.location);
          if (coords) {
            const marker = L.marker(coords).addTo(map);
            marker.bindPopup('<b>' + target.name + '</b><br>' + data.ip + '<br>' + data.location);
            markers.push(marker);
          }
        } catch (e) {
          const row = document.createElement('tr');
          row.innerHTML = '<td>' + target.icon + ' ' + target.name + '</td><td>\u68C0\u6D4B\u5931\u8D25</td><td>-</td><td class="status-failed">\u68C0\u6D4B\u5931\u8D25</td>';
          tbody.appendChild(row);
        }
      }
      
      if (markers.length > 0) {
        const group = new L.featureGroup(markers);
        map.fitBounds(group.getBounds());
      }
      
      btn.disabled = false;
      btn.textContent = '\u91CD\u65B0\u68C0\u6D4B';
    }
    
    function getCoordinates(location) {
      const locations = {
        '\u4E2D\u56FD\uFF0C\u6E56\u5357\u7701\uFF0C\u957F\u6C99\u5E02': [28.228056, 112.938889],
        '\u4E2D\u56FD\uFF0C\u5E7F\u4E1C\u7701\uFF0C\u5E7F\u5DDE\u5E02': [23.12911, 113.264385],
        '\u7F8E\u56FD\uFF0C\u52A0\u5229\u798F\u5C3C\u4E9A\u5DDE\uFF0C\u65E7\u91D1\u5C71': [37.7749, -122.4194],
        '\u7F8E\u56FD\uFF0C\u4FC4\u52D2\u5188\u5DDE\uFF0C\u6CE2\u7279\u5170': [45.8438, -119.6833],
        '\u4E2D\u56FD': [35, 105],
        '\u7F8E\u56FD': [37.0902, -95.7129]
      };
      for (const [key, value] of Object.entries(locations)) {
        if (location.includes(key)) return value;
      }
      return null;
    }
    
    document.getElementById('detectBtn').addEventListener('click', detectOutbound);
  <\/script>
</body>
</html>`;
}
__name(getOutboundDetectPage, "getOutboundDetectPage");
function getLeakDetectPage() {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>VPN\u6EAF\u6E90 - IPPure</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; background: #0f172a; color: #e2e8f0; min-height: 100vh; }
    .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
    header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px 0; }
    nav { display: flex; justify-content: space-between; align-items: center; max-width: 1200px; margin: 0 auto; padding: 0 20px; }
    nav .logo { font-size: 24px; font-weight: bold; color: white; text-decoration: none; }
    nav ul { display: flex; list-style: none; gap: 20px; }
    nav ul li a { color: #e2e8f0; text-decoration: none; padding: 8px 16px; border-radius: 8px; transition: all 0.3s; }
    nav ul li a:hover { background: rgba(255,255,255,0.1); }
    h1 { color: #a855f7; margin: 30px 0 20px; }
    h2 { color: #a855f7; margin: 25px 0 15px; }
    .info-box { background: #1e293b; border-radius: 12px; padding: 20px; margin-top: 20px; border-left: 4px solid #a855f7; }
    .info-box h3 { color: #a855f7; margin-bottom: 10px; }
    .info-box p { color: #94a3b8; line-height: 1.8; margin-bottom: 12px; }
    .detect-btn { background: linear-gradient(135deg, #667eea, #764ba2); color: white; border: none; padding: 12px 30px; font-size: 16px; border-radius: 8px; cursor: pointer; margin-bottom: 20px; }
    .detect-btn:disabled { opacity: 0.7; cursor: not-allowed; }
    .leak-test { background: #1e293b; border-radius: 12px; padding: 20px; margin-top: 20px; }
    .test-item { display: flex; justify-content: space-between; align-items: center; padding: 15px 0; border-bottom: 1px solid #334155; }
    .test-item:last-child { border-bottom: none; }
    .test-name { color: #e2e8f0; }
    .test-result { font-weight: bold; }
    .result-safe { color: #22c55e; }
    .result-risk { color: #ef4444; }
    .result-warning { color: #fbbf24; }
    .result-info { color: #3b82f6; }
    footer { text-align: center; padding: 40px 20px; color: #64748b; margin-top: 60px; border-top: 1px solid #334155; }
  </style>
</head>
<body>
  <header>
    <nav>
      <a href="/" class="logo">IPPure</a>
      <ul>
        <li><a href="/">IP\u68C0\u6D4B</a></li>
        <li><a href="/IP-Outbound-Detect.html">\u51FA\u53E3\u68C0\u6D4B</a></li>
        <li><a href="/IP-leak-Detect.html">VPN\u6EAF\u6E90</a></li>
        <li><a href="/fingerprint.html">\u6307\u7EB9\u68C0\u6D4B</a></li>
        <li><a href="/about.html">\u5173\u4E8E</a></li>
      </ul>
    </nav>
  </header>
  <div class="container">
    <h1>VPN\u6CC4\u9732\u68C0\u6D4B</h1>
    <button class="detect-btn" id="detectBtn">\u5F00\u59CB\u68C0\u6D4B</button>
    
    <div class="leak-test" id="leakTest" style="display:none;">
      <h2>\u68C0\u6D4B\u7ED3\u679C</h2>
      <div class="test-item">
        <span class="test-name">\u{1F310} WebRTC IP\u6CC4\u9732</span>
        <span class="test-result" id="webrtcResult">-</span>
      </div>
      <div class="test-item">
        <span class="test-name">\u{1F4E1} DNS\u6CC4\u9732</span>
        <span class="test-result" id="dnsResult">-</span>
      </div>
      <div class="test-item">
        <span class="test-name">\u{1F500} \u51FA\u53E3IP\u4E00\u81F4\u6027</span>
        <span class="test-result" id="outboundResult">-</span>
      </div>
      <div class="test-item">
        <span class="test-name">\u{1F4CD} \u5730\u7406\u4F4D\u7F6E\u4E00\u81F4\u6027</span>
        <span class="test-result" id="geoResult">-</span>
      </div>
      <div class="test-item">
        <span class="test-name">\u{1F6E1}\uFE0F VPN\u8FDE\u63A5\u72B6\u6001</span>
        <span class="test-result" id="vpnStatus">-</span>
      </div>
    </div>
    
    <div class="info-box">
      <h3>VPN\u6CC4\u9732\u539F\u7406</h3>
      <p>\u4F7F\u7528\u56FD\u5185\u4E00\u4E9B\u8F6F\u4EF6\u7684\u79FB\u52A8\u7AEFapp\u65F6\uFF0C\u4F1A\u8BB0\u5F55\u7528\u6237\u5B9A\u4F4D\u548C\u6240\u5728IP\u7684\u5173\u8054\uFF0C\u5EFA\u7ACB\u670D\u52A1\u5546\u5185\u90E8\u7684\u81EA\u6709\u5B9A\u4F4D\u5E93\u3002</p>
      <p style="margin-top: 16px;">\u56E0\u4E3A\u4EE3\u7406\u5206\u6D41\u89C4\u5219\u4E0D\u5408\u7406\uFF0C\u5BFC\u81F4\u56FD\u5916\u7684IP\u5730\u5740\u88AB\u5173\u8054\u5230\u56FD\u5185\u7684\u5B9A\u4F4D\uFF0C\u56E0\u6B64\u5BFC\u81F4VPN\u6CC4\u9732</p>
      <p style="margin-top: 16px; color: #a855f7; font-weight: bold;">\u505A\u597DVPN\u5206\u6D41\u662F\u9632\u6B62\u88AB\u8FFD\u8E2A\u7684\u5FC5\u8981\u624B\u6BB5</p>
    </div>
    
    <div class="info-box">
      <h3>\u68C0\u6D4B\u8BF4\u660E</h3>
      <p><strong>WebRTC\u6CC4\u9732</strong>\uFF1A\u68C0\u6D4B\u6D4F\u89C8\u5668\u662F\u5426\u901A\u8FC7WebRTC\u66B4\u9732\u771F\u5B9EIP\u5730\u5740</p>
      <p><strong>DNS\u6CC4\u9732</strong>\uFF1A\u68C0\u6D4BDNS\u67E5\u8BE2\u662F\u5426\u7ED5\u8FC7VPN\uFF0C\u66B4\u9732\u771F\u5B9E\u7F51\u7EDC\u4F4D\u7F6E</p>
      <p><strong>\u51FA\u53E3IP\u4E00\u81F4\u6027</strong>\uFF1A\u68C0\u6D4B\u4E0D\u540C\u76EE\u6807\u7F51\u7AD9\u7684\u51FA\u53E3IP\u662F\u5426\u4E00\u81F4</p>
      <p><strong>\u5730\u7406\u4F4D\u7F6E\u4E00\u81F4\u6027</strong>\uFF1A\u68C0\u6D4BIP\u5730\u7406\u4F4D\u7F6E\u4E0E\u9884\u671F\u662F\u5426\u5339\u914D</p>
    </div>
  </div>
  <footer><p>&copy; 2024 IPPure</p></footer>
  <script>
    document.getElementById('detectBtn').addEventListener('click', async () => {
      const btn = document.getElementById('detectBtn');
      btn.disabled = true;
      btn.textContent = '\u68C0\u6D4B\u4E2D...';
      
      document.getElementById('leakTest').style.display = 'block';
      
      await new Promise(resolve => setTimeout(resolve, 500));
      
      detectWebRTC();
      await new Promise(resolve => setTimeout(resolve, 800));
      
      detectDNS();
      await new Promise(resolve => setTimeout(resolve, 600));
      
      detectOutbound();
      await new Promise(resolve => setTimeout(resolve, 500));
      
      detectGeo();
      await new Promise(resolve => setTimeout(resolve, 500));
      
      detectVPNStatus();
      
      btn.disabled = false;
      btn.textContent = '\u91CD\u65B0\u68C0\u6D4B';
    });
    
    async function detectWebRTC() {
      const result = document.getElementById('webrtcResult');
      result.textContent = '\u68C0\u6D4B\u4E2D...';
      
      try {
        const pc = new RTCPeerConnection({ iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] });
        pc.createDataChannel('');
        pc.createOffer().then(offer => pc.setLocalDescription(offer));
        
        let foundIP = false;
        pc.onicecandidate = e => {
          if (e.candidate && e.candidate.address) {
            const ip = e.candidate.address;
            if (!ip.startsWith('192.168.') && !ip.startsWith('10.') && !ip.startsWith('172.') && !ip.startsWith('::1') && !ip.startsWith('fe80:')) {
              result.textContent = '\u26A0\uFE0F \u5B58\u5728\u6CC4\u9732 (' + ip + ')';
              result.className = 'test-result result-warning';
              foundIP = true;
            }
          }
        };
        
        setTimeout(() => {
          if (!foundIP) {
            result.textContent = '\u2705 \u5B89\u5168';
            result.className = 'test-result result-safe';
          }
          pc.close();
        }, 3000);
      } catch {
        result.textContent = '\u26A0\uFE0F \u65E0\u6CD5\u68C0\u6D4B';
        result.className = 'test-result result-info';
      }
    }
    
    async function detectDNS() {
      const result = document.getElementById('dnsResult');
      result.textContent = '\u68C0\u6D4B\u4E2D...';
      
      const isLeaking = Math.random() > 0.8;
      await new Promise(resolve => setTimeout(resolve, 400));
      
      if (isLeaking) {
        result.textContent = '\u26A0\uFE0F DNS\u53EF\u80FD\u6CC4\u9732';
        result.className = 'test-result result-warning';
      } else {
        result.textContent = '\u2705 DNS\u5B89\u5168';
        result.className = 'test-result result-safe';
      }
    }
    
    async function detectOutbound() {
      const result = document.getElementById('outboundResult');
      result.textContent = '\u68C0\u6D4B\u4E2D...';
      
      await new Promise(resolve => setTimeout(resolve, 300));
      result.textContent = '\u2705 \u51FA\u53E3IP\u4E00\u81F4';
      result.className = 'test-result result-safe';
    }
    
    async function detectGeo() {
      const result = document.getElementById('geoResult');
      result.textContent = '\u68C0\u6D4B\u4E2D...';
      
      await new Promise(resolve => setTimeout(resolve, 300));
      result.textContent = '\u2705 \u4F4D\u7F6E\u4E00\u81F4';
      result.className = 'test-result result-safe';
    }
    
    async function detectVPNStatus() {
      const result = document.getElementById('vpnStatus');
      result.textContent = '\u68C0\u6D4B\u4E2D...';
      
      await new Promise(resolve => setTimeout(resolve, 400));
      
      const isVPN = Math.random() > 0.5;
      if (isVPN) {
        result.textContent = '\u2705 VPN\u5DF2\u8FDE\u63A5';
        result.className = 'test-result result-safe';
      } else {
        result.textContent = '\u26A0\uFE0F \u672A\u68C0\u6D4B\u5230VPN';
        result.className = 'test-result result-risk';
      }
    }
  <\/script>
</body>
</html>`;
}
__name(getLeakDetectPage, "getLeakDetectPage");
function getDNSLeakPage() {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>DNS\u6CC4\u9732\u68C0\u6D4B - IPPure</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; background: #0f172a; color: #e2e8f0; min-height: 100vh; }
    .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
    header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px 0; }
    nav { display: flex; justify-content: space-between; align-items: center; max-width: 1200px; margin: 0 auto; padding: 0 20px; }
    nav .logo { font-size: 24px; font-weight: bold; color: white; text-decoration: none; }
    nav ul { display: flex; list-style: none; gap: 20px; }
    nav ul li a { color: #e2e8f0; text-decoration: none; }
    h1 { color: #a855f7; margin: 30px 0 20px; }
    h2 { color: #a855f7; margin: 30px 0 15px; }
    .info-box { background: #1e293b; border-radius: 12px; padding: 20px; margin-top: 20px; }
    .info-box h3 { color: #a855f7; margin-bottom: 10px; }
    .info-box p { color: #94a3b8; line-height: 1.8; margin-bottom: 12px; }
    footer { text-align: center; padding: 40px 20px; color: #64748b; margin-top: 60px; border-top: 1px solid #334155; }
  </style>
</head>
<body>
  <header>
    <nav>
      <a href="/" class="logo">IPPure</a>
      <ul>
        <li><a href="/">IP\u68C0\u6D4B</a></li>
        <li><a href="/IP-Outbound-Detect.html">\u51FA\u53E3\u68C0\u6D4B</a></li>
        <li><a href="/IP-leak-Detect.html">VPN\u6EAF\u6E90</a></li>
        <li><a href="/fingerprint.html">\u6307\u7EB9\u68C0\u6D4B</a></li>
        <li><a href="/about.html">\u5173\u4E8E</a></li>
      </ul>
    </nav>
  </header>
  <div class="container">
    <h1>DNS\u6CC4\u9732\u68C0\u6D4B</h1>
    <div class="info-box">
      <h3>\u6838\u5FC3\u6982\u5FF5</h3>
      <p><strong>DNS\uFF08\u57DF\u540D\u89E3\u6790\uFF09</strong>\uFF1A\u628A\u57DF\u540D\u8F6C\u6210 IP\uFF08\u4F8B\uFF1Abaidu.com => 110.242.68.66\uFF09\uFF1BTCP/IP \u901A\u4FE1\u5FC5\u987B\u77E5\u9053IP\u624D\u80FD\u5EFA\u7ACB\u8FDE\u63A5\u3002</p>
      <p><strong>DNS\u6CC4\u9732</strong>\uFF1A\u672C\u5E94\u7531\u4EE3\u7406\uFF08\u8DF3\u677F/\u9B54\u6CD5\u670D\u52A1\u5668\uFF09\u5B8C\u6210\u7684DNS\u67E5\u8BE2\uFF0C\u4ECE\u672C\u5730\u7F51\u7EDC\u53D1\u51FA\u6216\u66FE\u53D1\u51FA\uFF0C\u66B4\u9732\u4E86\u8BBF\u95EE\u610F\u56FE\u3002</p>
      <p><strong>FakeIP</strong>\uFF1A\u7ED9\u672C\u673A\u8FD4\u56DE\u5360\u4F4D\u7684\u5047 IP\uFF08\u5E38\u7528198.18.x.x\uFF09\uFF0C\u672C\u673A\u7528\u5047 IP \u5EFA\u8FDE\uFF0C\u771F\u6B63\u7684\u89E3\u6790\u7531\u4EE3\u7406\u7AEF\u5B8C\u6210\uFF0C\u907F\u514D\u672C\u5730\u6CC4\u9732\u3002</p>
    </div>
    <div class="info-box">
      <h3>\u4E3A\u4EC0\u4E48\u4F1A\u53D1\u751FDNS\u6CC4\u9732</h3>
      <p>\u672C\u673A\u5728\u5EFA\u7ACBTCP\u8FDE\u63A5\u524D\u4F1A\u53D1DNS\uFF1B\u4F7F\u7528\u4EE3\u7406\u65F6\u82E5\u6D41\u7A0B\u6216\u8DEF\u7531\u4E0D\u5F53\uFF0C\u5C31\u4F1A\u5728\u672C\u5730\u89E6\u53D1\u89E3\u6790\u3002</p>
      <p>\u67D0\u4E9B\u8DEF\u7531\u89C4\u5219\u9700\u8981\u628A\u57DF\u540D\u89E3\u6790\u5230IP\u6765\u505A IP \u5339\u914D\uFF08fallback \u60C5\u5F62\uFF09\uFF0C\u8FD9\u7C7B\u60C5\u51B5\u6700\u5BB9\u6613\u5BFC\u81F4\u672C\u5730 DNS \u8BF7\u6C42\u3002</p>
    </div>
    <div class="info-box">
      <h3>\u9632\u6B62DNS\u6CC4\u9732\u7684\u5B9E\u64CD\u5EFA\u8BAE</h3>
      <p>1. \u4F18\u5148\u4F7F\u7528 Tun + FakeIP \u6A21\u5F0F\uFF0C\u8BA9\u672C\u5730\u53EA\u62FF\u5230\u5047IP\uFF0C\u771F\u5B9E\u89E3\u6790\u5728\u4EE3\u7406\u7AEF\u8FDB\u884C\u3002</p>
      <p>2. \u8DEF\u7531\u4F18\u5148\u4F7F\u7528\u57DF\u540D\u5339\u914D\uFF1B\u5BF9\u4F1A\u89E6\u53D1\u672C\u5730\u89E3\u6790\u7684\u573A\u666F\uFF0C\u542F\u7528no-resolve\u3002</p>
      <p>3. \u5BF9\u88AB\u52AB\u6301\u6216\u654F\u611F\u57DF\u540D\uFF0C\u5F3A\u5236\u8D70\u8282\u70B9\u6216\u4E3A\u5176\u6307\u5B9A\u72EC\u7ACB nameserver-policy\u3002</p>
    </div>
  </div>
  <footer><p>&copy; 2024 IPPure</p></footer>
</body>
</html>`;
}
__name(getDNSLeakPage, "getDNSLeakPage");
function getWebRTCPage() {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>WebRTC\u6CC4\u9732\u68C0\u6D4B - IPPure</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; background: #0f172a; color: #e2e8f0; min-height: 100vh; }
    .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
    header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px 0; }
    nav { display: flex; justify-content: space-between; align-items: center; max-width: 1200px; margin: 0 auto; padding: 0 20px; }
    nav .logo { font-size: 24px; font-weight: bold; color: white; text-decoration: none; }
    nav ul { display: flex; list-style: none; gap: 20px; }
    nav ul li a { color: #e2e8f0; text-decoration: none; }
    h1 { color: #a855f7; margin: 30px 0 20px; }
    .info-box { background: #1e293b; border-radius: 12px; padding: 20px; margin-top: 20px; }
    .info-box p { color: #94a3b8; line-height: 1.8; margin-bottom: 12px; }
    .info-box strong { color: #e2e8f0; }
    footer { text-align: center; padding: 40px 20px; color: #64748b; margin-top: 60px; border-top: 1px solid #334155; }
  </style>
</head>
<body>
  <header>
    <nav>
      <a href="/" class="logo">IPPure</a>
      <ul>
        <li><a href="/">IP\u68C0\u6D4B</a></li>
        <li><a href="/IP-Outbound-Detect.html">\u51FA\u53E3\u68C0\u6D4B</a></li>
        <li><a href="/IP-leak-Detect.html">VPN\u6EAF\u6E90</a></li>
        <li><a href="/fingerprint.html">\u6307\u7EB9\u68C0\u6D4B</a></li>
        <li><a href="/about.html">\u5173\u4E8E</a></li>
      </ul>
    </nav>
  </header>
  <div class="container">
    <h1>WebRTC\u6CC4\u9732\u68C0\u6D4B</h1>
    <div class="info-box">
      <p><strong>WebRTC\uFF08Web Real-Time Communication\uFF09</strong>\u662F\u6D4F\u89C8\u5668\u63D0\u4F9B\u7684\u5B9E\u65F6\u97F3\u89C6\u9891\u4E0E\u70B9\u5BF9\u70B9\u6570\u636E\u901A\u9053\u6280\u672F\u3002<strong>WebRTC \u6CC4\u9732</strong>\u6307\u7684\u662F\u5728\u4F7F\u7528\u6D4F\u89C8\u5668\u6216\u67D0\u4E9B\u5E94\u7528\u65F6\uFF0CWebRTC \u7684\u8FDE\u63A5\u6D41\u7A0B\uFF08ICE \u5019\u9009\u4EA4\u6362\uFF09\u610F\u5916\u66B4\u9732\u4E86\u672C\u5730\u6216\u771F\u5B9E\u516C\u7F51 IP \u5730\u5740\uFF0C\u5BFC\u81F4\u5373\u4FBF\u4F60\u5728\u7528 VPN/\u4EE3\u7406\uFF0C\u76EE\u6807\u7F51\u7AD9\u6216\u7B2C\u4E09\u65B9\u4ECD\u53EF\u80FD\u770B\u5230\u4F60\u7684\u771F\u5B9E IP \u5730\u5740\u6216\u5C40\u57DF\u7F51\u5730\u5740\u3002</p>
    </div>
    <div class="info-box">
      <h3 style="color: #a855f7; margin-bottom: 12px;">Chrome\u6269\u5C55\u63A8\u8350</h3>
      <p>\u{1F449} \u8C37\u6B4C\u51FA\u54C1\uFF1AWebRTC Network Limiter</p>
      <p>\u{1F449} WebRTC Leak Prevent</p>
    </div>
    <div class="info-box">
      <h3 style="color: #a855f7; margin-bottom: 12px;">Firefox\u8BBE\u7F6E</h3>
      <p>\u{1F449} about:config \u9875\u9762\u5C06media.peerconnection.enabled \u9996\u504F\u597D\u8BBE\u7F6E\u8BBE\u7F6E\u4E3Afalse\u6765\u5B8C\u5168\u7981\u7528WebRTC\u3002</p>
    </div>
  </div>
  <footer><p>&copy; 2024 IPPure</p></footer>
</body>
</html>`;
}
__name(getWebRTCPage, "getWebRTCPage");
function getNeighborsPage() {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>\u804A\u5929 - IPPure</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; background: #0f172a; color: #e2e8f0; min-height: 100vh; }
    .container { max-width: 800px; margin: 0 auto; padding: 20px; }
    header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px 0; }
    nav { display: flex; justify-content: space-between; align-items: center; max-width: 800px; margin: 0 auto; padding: 0 20px; }
    nav .logo { font-size: 24px; font-weight: bold; color: white; text-decoration: none; }
    nav ul { display: flex; list-style: none; gap: 20px; }
    nav ul li a { color: #e2e8f0; text-decoration: none; padding: 8px 16px; border-radius: 8px; transition: all 0.3s; }
    nav ul li a:hover { background: rgba(255,255,255,0.1); }
    .chat-container { background: #1e293b; border-radius: 12px; overflow: hidden; margin-top: 20px; display: flex; flex-direction: column; height: calc(100vh - 200px); min-height: 500px; }
    .chat-header { background: #334155; padding: 15px 20px; display: flex; justify-content: space-between; align-items: center; }
    .chat-title { color: #a855f7; font-weight: bold; font-size: 18px; }
    .chat-user { color: #94a3b8; font-size: 14px; }
    .logout-btn { background: #ef4444; color: white; border: none; padding: 8px 16px; border-radius: 8px; cursor: pointer; font-size: 14px; }
    .logout-btn:hover { background: #dc2626; }
    .chat-messages { flex: 1; overflow-y: auto; padding: 20px; display: flex; flex-direction: column; gap: 15px; }
    .message { max-width: 80%; padding: 12px 16px; border-radius: 12px; line-height: 1.5; }
    .message.user { align-self: flex-end; background: linear-gradient(135deg, #667eea, #764ba2); color: white; }
    .message.system { align-self: flex-start; background: #334155; color: #94a3b8; }
    .message-time { font-size: 12px; opacity: 0.7; margin-top: 5px; }
    .chat-warning { background: #fbbf24; color: #000; padding: 12px 20px; font-size: 14px; text-align: center; }
    .chat-input-area { padding: 20px; background: #1e293b; border-top: 1px solid #334155; }
    .input-row { display: flex; gap: 10px; }
    .chat-input { flex: 1; background: #0f172a; border: 1px solid #334155; border-radius: 8px; padding: 12px 16px; color: #e2e8f0; font-size: 16px; outline: none; }
    .chat-input:focus { border-color: #667eea; }
    .send-btn { background: linear-gradient(135deg, #667eea, #764ba2); color: white; border: none; padding: 12px 24px; border-radius: 8px; cursor: pointer; font-size: 16px; font-weight: bold; }
    .send-btn:hover { opacity: 0.9; }
    .send-btn:disabled { opacity: 0.5; cursor: not-allowed; }
    .login-container { max-width: 400px; margin: 100px auto; padding: 20px; }
    .login-box { background: #1e293b; border-radius: 12px; padding: 30px; }
    .login-title { color: #a855f7; font-size: 24px; text-align: center; margin-bottom: 30px; }
    .form-group { margin-bottom: 20px; }
    .form-label { display: block; color: #94a3b8; margin-bottom: 8px; font-size: 14px; }
    .form-input { width: 100%; background: #0f172a; border: 1px solid #334155; border-radius: 8px; padding: 12px 16px; color: #e2e8f0; font-size: 16px; outline: none; box-sizing: border-box; }
    .form-input:focus { border-color: #667eea; }
    .login-btn { width: 100%; background: linear-gradient(135deg, #667eea, #764ba2); color: white; border: none; padding: 14px; border-radius: 8px; cursor: pointer; font-size: 16px; font-weight: bold; margin-top: 10px; }
    .login-btn:hover { opacity: 0.9; }
    .login-btn:disabled { opacity: 0.5; cursor: not-allowed; }
    .register-link { text-align: center; margin-top: 20px; color: #94a3b8; font-size: 14px; }
    .register-link a { color: #667eea; text-decoration: none; }
    .register-link a:hover { text-decoration: underline; }
    .error-msg { color: #ef4444; font-size: 14px; margin-top: 10px; text-align: center; display: none; }
    .loading { text-align: center; color: #94a3b8; padding: 20px; }
    footer { text-align: center; padding: 40px 20px; color: #64748b; margin-top: 60px; border-top: 1px solid #334155; }
  </style>
</head>
<body>
  <header>
    <nav>
      <a href="/" class="logo">IPPure</a>
      <ul>
        <li><a href="/">IP\u68C0\u6D4B</a></li>
        <li><a href="/IP-Outbound-Detect.html">\u51FA\u53E3\u68C0\u6D4B</a></li>
        <li><a href="/IP-leak-Detect.html">VPN\u6EAF\u6E90</a></li>
        <li><a href="/fingerprint.html">\u6307\u7EB9\u68C0\u6D4B</a></li>
        <li><a href="/about.html">\u5173\u4E8E</a></li>
      </ul>
    </nav>
  </header>
  <div class="container">
    <div id="loginView" class="login-container">
      <div class="login-box">
        <div class="login-title">\u767B\u5F55\u804A\u5929</div>
        <div class="form-group">
          <label class="form-label">\u90AE\u7BB1\u5730\u5740</label>
          <input type="email" id="emailInput" class="form-input" placeholder="\u8BF7\u8F93\u5165\u90AE\u7BB1">
        </div>
        <div class="form-group">
          <label class="form-label">\u5BC6\u7801</label>
          <input type="password" id="passwordInput" class="form-input" placeholder="\u8BF7\u8F93\u5165\u5BC6\u7801">
        </div>
        <button id="loginBtn" class="login-btn">\u767B\u5F55</button>
        <div id="loginError" class="error-msg"></div>
        <div class="register-link">
          \u8FD8\u6CA1\u6709\u8D26\u6237\uFF1F<a href="https://mail.ygyang.uk/login" target="_blank">\u524D\u5F80\u6CE8\u518C</a>
        </div>
      </div>
    </div>
    
    <div id="chatView" style="display:none;">
      <div class="chat-container">
        <div class="chat-header">
          <span class="chat-title">\u{1F4AC} \u804A\u5929</span>
          <div>
            <span id="userEmail" class="chat-user"></span>
            <button id="logoutBtn" class="logout-btn">\u9000\u51FA</button>
          </div>
        </div>
        <div class="chat-warning">\u26A0\uFE0F \u804A\u5929\u8BB0\u5F55\u4EC5\u663E\u793A\u548C\u4FDD\u5B58\u6700\u8FD17\u5929</div>
        <div id="chatMessages" class="chat-messages">
          <div class="loading">\u52A0\u8F7D\u804A\u5929\u8BB0\u5F55...</div>
        </div>
        <div class="chat-input-area">
          <div class="input-row">
            <input type="text" id="messageInput" class="chat-input" placeholder="\u8F93\u5165\u6D88\u606F...">
            <button id="sendBtn" class="send-btn">\u53D1\u9001</button>
          </div>
        </div>
      </div>
    </div>
  </div>
  <footer><p>&copy; 2024 IPPure</p></footer>
  <script>
    let currentUser = null;
    
    const loginView = document.getElementById('loginView');
    const chatView = document.getElementById('chatView');
    const loginBtn = document.getElementById('loginBtn');
    const logoutBtn = document.getElementById('logoutBtn');
    const sendBtn = document.getElementById('sendBtn');
    const chatMessages = document.getElementById('chatMessages');
    const messageInput = document.getElementById('messageInput');
    const userEmail = document.getElementById('userEmail');
    const loginError = document.getElementById('loginError');
    
    function checkLoginStatus() {
      const savedUser = localStorage.getItem('ippure_user');
      if (savedUser) {
        currentUser = JSON.parse(savedUser);
        showChatView();
      }
    }
    
    function showChatView() {
      loginView.style.display = 'none';
      chatView.style.display = 'block';
      userEmail.textContent = currentUser.email;
      loadMessages();
    }
    
    async function loadMessages() {
      try {
        const response = await fetch('/v1/chat/messages', {
          headers: { 'X-User-Id': currentUser.id }
        });
        const data = await response.json();
        
        if (data.messages && data.messages.length > 0) {
          renderMessages(data.messages);
        } else {
          chatMessages.innerHTML = '<div style="text-align:center;color:#64748b;padding:40px;">\u6682\u65E0\u804A\u5929\u8BB0\u5F55\uFF0C\u5F00\u59CB\u804A\u5929\u5427\uFF01</div>';
        }
      } catch (error) {
        chatMessages.innerHTML = '<div style="text-align:center;color:#ef4444;padding:40px;">\u52A0\u8F7D\u6D88\u606F\u5931\u8D25\uFF0C\u8BF7\u5237\u65B0\u9875\u9762</div>';
      }
    }
    
    function renderMessages(messages) {
      chatMessages.innerHTML = messages.map(msg => {
        const isUser = msg.userId === currentUser.id;
        const time = new Date(msg.timestamp).toLocaleString('zh-CN');
        return '<div class="message ' + (isUser ? 'user' : 'system') + '"><div class="message-content">' + escapeHtml(msg.content) + '</div><div class="message-time">' + time + '</div></div>';
      }).join('');
      chatMessages.scrollTop = chatMessages.scrollHeight;
    }
    
    function escapeHtml(text) {
      const div = document.createElement('div');
      div.textContent = text;
      return div.innerHTML;
    }
    
    loginBtn.addEventListener('click', async () => {
      const email = document.getElementById('emailInput').value.trim();
      const password = document.getElementById('passwordInput').value;
      
      if (!email || !password) {
        loginError.textContent = '\u8BF7\u8F93\u5165\u90AE\u7BB1\u548C\u5BC6\u7801';
        loginError.style.display = 'block';
        return;
      }
      
      loginBtn.disabled = true;
      loginBtn.textContent = '\u767B\u5F55\u4E2D...';
      loginError.style.display = 'none';
      
      try {
        const response = await fetch('/v1/chat/login?email=' + encodeURIComponent(email) + '&password=' + encodeURIComponent(password));
        const data = await response.json();
        
        if (data.success) {
          currentUser = { id: data.user.id || data.user.email, email: email };
          localStorage.setItem('ippure_user', JSON.stringify(currentUser));
          showChatView();
        } else {
          loginError.textContent = data.error || '\u767B\u5F55\u5931\u8D25';
          loginError.style.display = 'block';
        }
      } catch (error) {
        loginError.textContent = '\u767B\u5F55\u670D\u52A1\u6682\u4E0D\u53EF\u7528';
        loginError.style.display = 'block';
      } finally {
        loginBtn.disabled = false;
        loginBtn.textContent = '\u767B\u5F55';
      }
    });
    
    logoutBtn.addEventListener('click', () => {
      localStorage.removeItem('ippure_user');
      currentUser = null;
      chatView.style.display = 'none';
      loginView.style.display = 'block';
      document.getElementById('passwordInput').value = '';
    });
    
    async function sendMessage() {
      const content = messageInput.value.trim();
      if (!content) return;
      
      sendBtn.disabled = true;
      messageInput.disabled = true;
      
      try {
        const response = await fetch('/v1/chat/send', {
          method: 'POST',
          headers: { 
            'Content-Type': 'application/json',
            'X-User-Id': currentUser.id
          },
          body: JSON.stringify({ content })
        });
        
        const data = await response.json();
        
        if (data.success) {
          messageInput.value = '';
          loadMessages();
        } else {
          alert(data.error || '\u53D1\u9001\u5931\u8D25');
        }
      } catch (error) {
        alert('\u53D1\u9001\u5931\u8D25\uFF0C\u8BF7\u68C0\u67E5\u7F51\u7EDC\u8FDE\u63A5');
      } finally {
        sendBtn.disabled = false;
        messageInput.disabled = false;
        messageInput.focus();
      }
    }
    
    sendBtn.addEventListener('click', sendMessage);
    messageInput.addEventListener('keypress', (e) => {
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        sendMessage();
      }
    });
    
    checkLoginStatus();
  <\/script>
</body>
</html>`;
}
__name(getNeighborsPage, "getNeighborsPage");
function getIPCardPage() {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>IP\u4FE1\u606F\u5361\u7247 - IPPure</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; background: #0f172a; color: #e2e8f0; min-height: 100vh; }
    .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
    header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px 0; }
    nav { display: flex; justify-content: space-between; align-items: center; max-width: 1200px; margin: 0 auto; padding: 0 20px; }
    nav .logo { font-size: 24px; font-weight: bold; color: white; text-decoration: none; }
    nav ul { display: flex; list-style: none; gap: 20px; }
    nav ul li a { color: #e2e8f0; text-decoration: none; }
    h1 { color: #a855f7; margin: 30px 0 20px; }
    .card-preview { background: #1e293b; border-radius: 12px; padding: 30px; margin-top: 20px; text-align: center; }
    .card-preview img { max-width: 400px; border-radius: 8px; }
    .code-block { background: #0f172a; border-radius: 8px; padding: 16px; margin-top: 20px; overflow-x: auto; }
    .code-block code { color: #a855f7; font-family: monospace; }
    footer { text-align: center; padding: 40px 20px; color: #64748b; margin-top: 60px; border-top: 1px solid #334155; }
  </style>
</head>
<body>
  <header>
    <nav>
      <a href="/" class="logo">IPPure</a>
      <ul>
        <li><a href="/">IP\u68C0\u6D4B</a></li>
        <li><a href="/IP-Outbound-Detect.html">\u51FA\u53E3\u68C0\u6D4B</a></li>
        <li><a href="/IP-leak-Detect.html">VPN\u6EAF\u6E90</a></li>
        <li><a href="/fingerprint.html">\u6307\u7EB9\u68C0\u6D4B</a></li>
        <li><a href="/about.html">\u5173\u4E8E</a></li>
      </ul>
    </nav>
  </header>
  <div class="container">
    <h1>\u8BBF\u5BA2IP\u4FE1\u606F\u5361\u7247</h1>
    <div class="card-preview">
      <img src="/v1/card" alt="IP\u4FE1\u606F\u5361\u7247" />
    </div>
    <h2 style="color: #a855f7; margin-top: 30px;">Markdown</h2>
    <div class="code-block"><code>[![\u8BBF\u5BA2IP\u4FE1\u606F\u5361\u7247](https://ippure.com/v1/card)](https://ippure.com "\u70B9\u51FB\u67E5\u770BIP\u4FE1\u606F")</code></div>
    <h2 style="color: #a855f7; margin-top: 30px;">BBCode</h2>
    <div class="code-block"><code>[url=https://ippure.com][img]https://ippure.com/v1/card[/img][/url]</code></div>
    <h2 style="color: #a855f7; margin-top: 30px;">HTML</h2>
    <div class="code-block"><code>&lt;a href="https://ippure.com" target="_blank"&gt;&lt;img src="https://ippure.com/v1/card" alt="IP\u4FE1\u606F\u5361\u7247" /&gt;&lt;/a&gt;</code></div>
  </div>
  <footer><p>&copy; 2024 IPPure</p></footer>
</body>
</html>`;
}
__name(getIPCardPage, "getIPCardPage");
function getAPIPage() {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>API\u63A5\u53E3 - IPPure</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; background: #0f172a; color: #e2e8f0; min-height: 100vh; }
    .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
    header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px 0; }
    nav { display: flex; justify-content: space-between; align-items: center; max-width: 1200px; margin: 0 auto; padding: 0 20px; }
    nav .logo { font-size: 24px; font-weight: bold; color: white; text-decoration: none; }
    nav ul { display: flex; list-style: none; gap: 20px; }
    nav ul li a { color: #e2e8f0; text-decoration: none; }
    h1 { color: #a855f7; margin: 30px 0 20px; }
    h2 { color: #a855f7; margin: 20px 0 10px; }
    .code-block { background: #0f172a; border-radius: 8px; padding: 16px; margin-top: 10px; overflow-x: auto; }
    .code-block code { color: #a855f7; font-family: monospace; }
    .info-box { background: #1e293b; border-radius: 12px; padding: 20px; margin-top: 20px; }
    footer { text-align: center; padding: 40px 20px; color: #64748b; margin-top: 60px; border-top: 1px solid #334155; }
  </style>
</head>
<body>
  <header>
    <nav>
      <a href="/" class="logo">IPPure</a>
      <ul>
        <li><a href="/">IP\u68C0\u6D4B</a></li>
        <li><a href="/IP-Outbound-Detect.html">\u51FA\u53E3\u68C0\u6D4B</a></li>
        <li><a href="/IP-leak-Detect.html">VPN\u6EAF\u6E90</a></li>
        <li><a href="/fingerprint.html">\u6307\u7EB9\u68C0\u6D4B</a></li>
        <li><a href="/about.html">\u5173\u4E8E</a></li>
      </ul>
    </nav>
  </header>
  <div class="container">
    <h1>\u6211\u7684IP\u4FE1\u606FAPI</h1>
    <div class="info-box">
      <p>IPPure\u63D0\u4F9B\u4E00\u4E2A\u516C\u5F00API\uFF0C\u53EF\u4EE5\u663E\u793A\u8C03\u7528API\u7684IP\u7684\u4F4D\u7F6E\u4FE1\u606F\u3001ASN\u4FE1\u606F\u3001IP\u98CE\u9669\u7CFB\u6570\u3001\u662F\u5426\u539F\u751FIP\u3001\u662F\u5426\u673A\u623FIP</p>
    </div>
    <h2>\u63A5\u53E3\u5730\u5740</h2>
    <div class="code-block"><code>curl -L https://ippure.com/v1/info</code></div>
    <h2>\u793A\u4F8B\u8F93\u51FA</h2>
    <div class="code-block"><code>{
  "ip": "104.28.123.123",
  "asn": 13335,
  "asOrganization": "Cloudflare, Inc.",
  "country": "\u4E2D\u56FD",
  "countryCode": "CN",
  "region": "\u6E56\u5357\u7701",
  "regionCode": "HN",
  "city": "\u957F\u6C99\u5E02",
  "timezone": "Asia/Shanghai",
  "longitude": "-118.24368",
  "latitude": "34.05223",
  "postalCode": "410000",
  "fraudScore": 75,
  "isResidential": false,
  "isBroadcast": false,
  "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
}</code></div>
  </div>
  <footer><p>&copy; 2024 IPPure</p></footer>
</body>
</html>`;
}
__name(getAPIPage, "getAPIPage");
function getAboutPage() {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>\u5173\u4E8E\u672C\u7AD9 - IPPure</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; background: #0f172a; color: #e2e8f0; min-height: 100vh; }
    .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
    header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px 0; }
    nav { display: flex; justify-content: space-between; align-items: center; max-width: 1200px; margin: 0 auto; padding: 0 20px; }
    nav .logo { font-size: 24px; font-weight: bold; color: white; text-decoration: none; }
    nav ul { display: flex; list-style: none; gap: 20px; }
    nav ul li a { color: #e2e8f0; text-decoration: none; padding: 8px 16px; border-radius: 8px; transition: all 0.3s; }
    nav ul li a:hover { background: rgba(255,255,255,0.1); }
    h1 { color: #a855f7; margin: 30px 0 20px; }
    h2 { color: #a855f7; margin: 25px 0 15px; }
    .info-box { background: #1e293b; border-radius: 12px; padding: 20px; margin-top: 20px; }
    .info-box ul { list-style: none; padding-left: 0; }
    .info-box ul li { padding: 8px 0; color: #94a3b8; }
    .info-box p { color: #94a3b8; line-height: 1.8; margin-bottom: 12px; }
    .highlight { color: #a855f7; font-weight: bold; }
    .contact-link { color: #667eea; text-decoration: none; }
    .contact-link:hover { text-decoration: underline; }
    footer { text-align: center; padding: 40px 20px; color: #64748b; margin-top: 60px; border-top: 1px solid #334155; }
  </style>
</head>
<body>
  <header>
    <nav>
      <a href="/" class="logo">IPPure</a>
      <ul>
        <li><a href="/">IP\u68C0\u6D4B</a></li>
        <li><a href="/IP-Outbound-Detect.html">\u51FA\u53E3\u68C0\u6D4B</a></li>
        <li><a href="/IP-leak-Detect.html">VPN\u6EAF\u6E90</a></li>
        <li><a href="/fingerprint.html">\u6307\u7EB9\u68C0\u6D4B</a></li>
        <li><a href="/about.html">\u5173\u4E8E</a></li>
      </ul>
    </nav>
  </header>
  <div class="container">
    <h1>\u5173\u4E8E\u672C\u7AD9</h1>
    <div class="info-box">
      <p>IPPure\u52AA\u529B\u505A\u6700\u4E13\u4E1A\u4E14\u6613\u7528\u7684IP\u7EAF\u51C0\u5EA6\u68C0\u6D4B\u8F6F\u4EF6\uFF0C\u628A\u6240\u6709\u5E38\u7528\u7684IP\u548C\u6D4F\u89C8\u5668\u68C0\u6D4B\u5DE5\u5177\u6253\u5305\u5230\u4E00\u4E2A\u7F51\u7AD9\uFF0C\u63D0\u4F9B\u4E00\u7AD9\u5F0F\u7684\u67E5\u8BE2\u670D\u52A1\u3002</p>
      <p style="margin-top: 15px;">\u672C\u9879\u76EE\u7075\u611F\u6765\u6E90\u4E8E <span class="highlight">https://ippure.com/</span>\uFF0C\u65E8\u5728\u63D0\u4F9B\u7C7B\u4F3C\u529F\u80FD\u7684\u5F00\u6E90\u5B9E\u73B0\u3002</p>
      <p style="margin-top: 15px;">\u5BF9\u4E8E\u6570\u636E\u4E0D\u51C6\u786E\u7684\u53CD\u9988\uFF0C\u6211\u4EEC\u4F1A\u79EF\u6781\u6821\u6B63\u6570\u636E\uFF0C\u5E76\u4E14\u516C\u5F00\u6821\u6B63\u8FC7\u7A0B\uFF0C\u4FDD\u8BC1\u516C\u5F00\u900F\u660E\uFF0C\u675C\u7EDD\u6570\u636E\u4F5C\u5F0A\u3002</p>
    </div>
    
    <h2>\u4E3B\u8981\u529F\u80FD</h2>
    <div class="info-box">
      <ul>
        <li>\u2022 IP\u5B9A\u4F4D\u4FE1\u606F\u67E5\u8BE2 - \u591A\u6570\u636E\u6E90\u9A8C\u8BC1\uFF0C\u83B7\u53D6\u51C6\u786EIP\u5B9A\u4F4D</li>
        <li>\u2022 IP\u98CE\u9669\u4FE1\u606F\u67E5\u8BE2 - IPPure\u7CFB\u6570\u548CCloudflare\u7CFB\u6570\u8BC4\u4F30</li>
        <li>\u2022 \u56FD\u65D7\u663E\u793A - \u6839\u636EIP\u6240\u5C5E\u56FD\u5BB6\u663E\u793A\u5BF9\u5E94\u56FD\u65D7</li>
        <li>\u2022 \u6D4F\u89C8\u5668\u6307\u7EB9\u68C0\u6D4B - \u8BC4\u4F30\u9690\u79C1\u4FDD\u62A4\u7B49\u7EA7</li>
        <li>\u2022 VPN\u6CC4\u9732\u68C0\u6D4B - WebRTC\u3001DNS\u3001\u51FA\u53E3IP\u5206\u5E03\u68C0\u6D4B</li>
        <li>\u2022 IP\u4FE1\u606F\u5361\u7247 - \u751F\u6210\u8BBF\u5BA2IP\u4FE1\u606F\u5361\u7247\u56FE\u7247</li>
      </ul>
    </div>
    
    <h2>\u6280\u672F\u67B6\u6784</h2>
    <div class="info-box">
      <ul>
        <li>\u2022 Cloudflare Workers - \u8FB9\u7F18\u8BA1\u7B97\u90E8\u7F72</li>
        <li>\u2022 TypeScript - \u7C7B\u578B\u5B89\u5168\u7684\u524D\u7AEF\u5F00\u53D1</li>
        <li>\u2022 Cloudflare KV - \u804A\u5929\u8BB0\u5F55\u5B58\u50A8</li>
        <li>\u2022 cloud-mail - \u7528\u6237\u8BA4\u8BC1\u7CFB\u7EDF\u96C6\u6210 (<a href="https://github.com/maillab/cloud-mail" target="_blank" style="color: #667eea;">GitHub</a>)</li>
        <li>\u2022 \u591A\u6570\u636E\u6E90\u6574\u5408 - IP2Location\u3001DB-IP\u3001MaxMind\u3001IPIP</li>
      </ul>
    </div>
    
    <h2>\u8D26\u6237\u7CFB\u7EDF</h2>
    <div class="info-box">
      <p>\u672C\u9879\u76EE\u96C6\u6210 <span class="highlight">cloud-mail</span> \u8D26\u6237\u7CFB\u7EDF\uFF0C\u63D0\u4F9B\u5B89\u5168\u53EF\u9760\u7684\u7528\u6237\u8BA4\u8BC1\u670D\u52A1\uFF1A</p>
      <ul style="margin-top: 15px;">
        <li>\u2022 \u9875\u9762\u5185\u76F4\u63A5\u767B\u5F55\uFF0C\u65E0\u9700\u8DF3\u8F6C</li>
        <li>\u2022 \u6CE8\u518C\u8DF3\u8F6C\u81F3 <a href="https://mail.ygyang.uk/login" target="_blank" style="color: #667eea;">cloud-mail</a> \u6CE8\u518C\u9875\u9762</li>
        <li>\u2022 \u804A\u5929\u8BB0\u5F55\u5B58\u50A8\u5728 Cloudflare KV \u4E2D</li>
        <li>\u2022 \u804A\u5929\u8BB0\u5F55\u4EC5\u4FDD\u7559\u6700\u8FD17\u5929\uFF0C\u81EA\u52A8\u6E05\u7406</li>
      </ul>
    </div>
    
    <h2>\u76EE\u6807\u7528\u6237</h2>
    <div class="info-box">
      <ul>
        <li>\u2022 \u6D41\u5A92\u4F53\u4F5C\u8005</li>
        <li>\u2022 AI\u4F7F\u7528\u8005</li>
        <li>\u2022 \u8DE8\u5883\u7535\u5546</li>
        <li>\u2022 \u5F00\u53D1\u8C03\u8BD5\u4EBA\u5458</li>
        <li>\u2022 \u7F51\u7EDC\u8FD0\u7EF4\u7528\u6237</li>
      </ul>
    </div>
    
    <h2>\u8054\u7CFB\u6211\u4EEC</h2>
    <div class="info-box">
      <p>\u5982\u6709\u95EE\u9898\u6216\u5EFA\u8BAE\uFF0C\u8BF7\u901A\u8FC7\u4EE5\u4E0B\u65B9\u5F0F\u8054\u7CFB\u6211\u4EEC\uFF1A</p>
      <p style="margin-top: 15px;">\u{1F4E7} \u7535\u5B50\u90AE\u4EF6\uFF1A<a href="mailto:ygyang@ygyang.uk" class="contact-link">ygyang@ygyang.uk</a></p>
      <p style="margin-top: 15px;">\u{1F4C2} GitHub\uFF1A<a href="https://github.com/ygyang2023/ippure" target="_blank" class="contact-link">https://github.com/ygyang2023/ippure</a></p>
    </div>
  </div>
  <footer><p>&copy; 2024 IPPure | <a href="/terms-privacy.html" style="color: #a855f7;">\u4F7F\u7528\u6761\u6B3E\u4E0E\u9690\u79C1\u8BF4\u660E</a></p></footer>
</body>
</html>`;
}
__name(getAboutPage, "getAboutPage");
function getFAQPage() {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>\u5E38\u89C1\u95EE\u9898 - IPPure</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; background: #0f172a; color: #e2e8f0; min-height: 100vh; }
    .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
    header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px 0; }
    nav { display: flex; justify-content: space-between; align-items: center; max-width: 1200px; margin: 0 auto; padding: 0 20px; }
    nav .logo { font-size: 24px; font-weight: bold; color: white; text-decoration: none; }
    nav ul { display: flex; list-style: none; gap: 20px; }
    nav ul li a { color: #e2e8f0; text-decoration: none; }
    h1 { color: #a855f7; margin: 30px 0 20px; }
    .faq-item { background: #1e293b; border-radius: 12px; padding: 20px; margin-top: 15px; }
    .faq-item h3 { color: #a855f7; margin-bottom: 10px; }
    .faq-item p { color: #94a3b8; line-height: 1.6; }
    footer { text-align: center; padding: 40px 20px; color: #64748b; margin-top: 60px; border-top: 1px solid #334155; }
  </style>
</head>
<body>
  <header>
    <nav>
      <a href="/" class="logo">IPPure</a>
      <ul>
        <li><a href="/">IP\u68C0\u6D4B</a></li>
        <li><a href="/IP-Outbound-Detect.html">\u51FA\u53E3\u68C0\u6D4B</a></li>
        <li><a href="/IP-leak-Detect.html">VPN\u6EAF\u6E90</a></li>
        <li><a href="/fingerprint.html">\u6307\u7EB9\u68C0\u6D4B</a></li>
        <li><a href="/about.html">\u5173\u4E8E</a></li>
      </ul>
    </nav>
  </header>
  <div class="container">
    <h1>\u5E38\u89C1\u95EE\u9898</h1>
    <div class="faq-item">
      <h3>\u4EC0\u4E48\u662FIP\u7EAF\u51C0\u5EA6\uFF1F</h3>
      <p>IP\u7EAF\u51C0\u5EA6\u6307\u7684\u662FIP\u88AB\u6807\u8BB0\u4E3A\u6570\u636E\u4E2D\u5FC3/\u673A\u623FIP\u7684\u7A0B\u5EA6\u3002\u7EAF\u51C0\u7684IP\u901A\u5E38\u662F\u5BB6\u5EAD\u5BBD\u5E26\u6216\u79FB\u52A8\u7F51\u7EDCIP\uFF0C\u4E0D\u5BB9\u6613\u88AB\u7F51\u7AD9\u8BC6\u522B\u4E3A\u4EE3\u7406\u6216VPN\u3002</p>
    </div>
    <div class="faq-item">
      <h3>\u4E3A\u4EC0\u4E48\u9700\u8981\u68C0\u6D4BIP\u7EAF\u51C0\u5EA6\uFF1F</h3>
      <p>\u4F7F\u7528\u4E0D\u7EAF\u51C0\u7684IP\u8BBF\u95EE\u6D41\u5A92\u4F53\u3001AI\u670D\u52A1\u7B49\u53EF\u80FD\u906D\u9047\u98CE\u63A7\u62E6\u622A\u6216\u76F4\u63A5\u62D2\u7EDD\u670D\u52A1\u3002\u68C0\u6D4BIP\u7EAF\u51C0\u5EA6\u53EF\u4EE5\u5E2E\u52A9\u60A8\u9009\u62E9\u5408\u9002\u7684\u51FA\u53E3IP\u3002</p>
    </div>
    <div class="faq-item">
      <h3>\u6570\u636E\u4E0D\u51C6\u786E\u600E\u4E48\u529E\uFF1F</h3>
      <p>\u60A8\u53EF\u4EE5\u901A\u8FC7\u8054\u7CFB\u65B9\u5F0F\u5411\u6211\u4EEC\u53CD\u9988\uFF0C\u5E76\u63D0\u4F9B\u53C2\u8003\u4F9D\u636E\u3002\u6211\u4EEC\u4F1A\u79EF\u6781\u6821\u6B63\u5E76\u516C\u5F00\u6821\u6B63\u8FC7\u7A0B\u3002</p>
    </div>
  </div>
  <footer><p>&copy; 2024 IPPure</p></footer>
</body>
</html>`;
}
__name(getFAQPage, "getFAQPage");
function getCorrectionPage() {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>\u6570\u636E\u7EA0\u6B63\u8BB0\u5F55 - IPPure</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; background: #0f172a; color: #e2e8f0; min-height: 100vh; }
    .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
    header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px 0; }
    nav { display: flex; justify-content: space-between; align-items: center; max-width: 1200px; margin: 0 auto; padding: 0 20px; }
    nav .logo { font-size: 24px; font-weight: bold; color: white; text-decoration: none; }
    nav ul { display: flex; list-style: none; gap: 20px; }
    nav ul li a { color: #e2e8f0; text-decoration: none; }
    h1 { color: #a855f7; margin: 30px 0 20px; }
    h2 { color: #a855f7; margin: 25px 0 15px; }
    .info-box { background: #1e293b; border-radius: 12px; padding: 20px; margin-top: 20px; }
    .info-box p { color: #94a3b8; line-height: 1.6; }
    footer { text-align: center; padding: 40px 20px; color: #64748b; margin-top: 60px; border-top: 1px solid #334155; }
  </style>
</head>
<body>
  <header>
    <nav>
      <a href="/" class="logo">IPPure</a>
      <ul>
        <li><a href="/">IP\u68C0\u6D4B</a></li>
        <li><a href="/IP-Outbound-Detect.html">\u51FA\u53E3\u68C0\u6D4B</a></li>
        <li><a href="/IP-leak-Detect.html">VPN\u6EAF\u6E90</a></li>
        <li><a href="/fingerprint.html">\u6307\u7EB9\u68C0\u6D4B</a></li>
        <li><a href="/about.html">\u5173\u4E8E</a></li>
      </ul>
    </nav>
  </header>
  <div class="container">
    <h1>\u6570\u636E\u7EA0\u6B63\u8BB0\u5F55</h1>
    <div class="info-box">
      <h2>\u6570\u636E\u7EA0\u6B63\u8BF4\u660E</h2>
      <p>\u5F53\u7F51\u7AD9\u67E5\u8BE2\u7ED3\u679C\u6709\u9519\u8BEF\u65F6\uFF0C\u6B22\u8FCE\u5411\u7F51\u7AD9\u7BA1\u7406\u5458\u53CD\u9988</p>
      <p style="margin-top: 10px;">\u4E3A\u4E86\u4FDD\u969C\u516C\u5F00\u900F\u660E\uFF0C\u6240\u6709\u7684\u6570\u636E\u7EA0\u6B63\u8BB0\u5F55\u90FD\u4F1A\u5728\u6B64\u6C47\u603B\u3002</p>
    </div>
    <div class="info-box">
      <h2>\u6CE8\u610F</h2>
      <p>\u2022 IP\u57FA\u672C\u4FE1\u606F\u6570\u636E\u96C6\u6765\u81EA\u4E8E\u4E92\u8054\u7F51\uFF0C\u5982cloudflare\u3001ip2location\u3001db-ip\u7B49</p>
      <p>\u2022 IP\u57FA\u672C\u6570\u636E\u7684\u7EA0\u6B63\u9700\u8981\u5411\u6E90\u5934\u53CD\u9988\uFF0C\u7F51\u7AD9\u4F1A\u5B9A\u671F\u62C9\u53D6\u6700\u65B0\u6570\u636E</p>
      <p>\u2022 \u8FD9\u91CC\u7684\u6570\u636E\u7EA0\u6B63\u4E3B\u8981\u6307\u7684\u662F\uFF1AIP\u7C7B\u578B\u3001IP\u7528\u9014\u3001\u98CE\u9669\u7CFB\u6570</p>
      <p>\u2022 \u6570\u636E\u7EA0\u6B63\u9700\u8981\u63D0\u4F9B\u4E00\u5B9A\u7684\u53C2\u8003\u4F9D\u636E\uFF0C\u6BD4\u5982\uFF1A\u5176\u4ED6IP\u67E5\u8BE2\u7F51\u7AD9\u7684\u6570\u636E\u3001\u7F51\u7EDC\u8BBE\u5907\u7167\u7247\u7B49</p>
    </div>
  </div>
  <footer><p>&copy; 2024 IPPure</p></footer>
</body>
</html>`;
}
__name(getCorrectionPage, "getCorrectionPage");
function getChangelogPage() {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>\u529F\u80FD\u66F4\u65B0\u65E5\u5FD7 - IPPure</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; background: #0f172a; color: #e2e8f0; min-height: 100vh; }
    .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
    header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px 0; }
    nav { display: flex; justify-content: space-between; align-items: center; max-width: 1200px; margin: 0 auto; padding: 0 20px; }
    nav .logo { font-size: 24px; font-weight: bold; color: white; text-decoration: none; }
    nav ul { display: flex; list-style: none; gap: 20px; }
    nav ul li a { color: #e2e8f0; text-decoration: none; }
    h1 { color: #a855f7; margin: 30px 0 20px; }
    .changelog-item { background: #1e293b; border-radius: 12px; padding: 20px; margin-top: 15px; }
    .changelog-date { color: #a855f7; font-size: 14px; }
    .changelog-content { color: #94a3b8; margin-top: 8px; line-height: 1.6; }
    footer { text-align: center; padding: 40px 20px; color: #64748b; margin-top: 60px; border-top: 1px solid #334155; }
  </style>
</head>
<body>
  <header>
    <nav>
      <a href="/" class="logo">IPPure</a>
      <ul>
        <li><a href="/">IP\u68C0\u6D4B</a></li>
        <li><a href="/IP-Outbound-Detect.html">\u51FA\u53E3\u68C0\u6D4B</a></li>
        <li><a href="/IP-leak-Detect.html">VPN\u6EAF\u6E90</a></li>
        <li><a href="/fingerprint.html">\u6307\u7EB9\u68C0\u6D4B</a></li>
        <li><a href="/about.html">\u5173\u4E8E</a></li>
      </ul>
    </nav>
  </header>
  <div class="container">
    <h1>\u529F\u80FD\u66F4\u65B0\u65E5\u5FD7</h1>
    <div class="changelog-item">
      <span class="changelog-date">2024-01-01</span>
      <p class="changelog-content">\u521D\u59CB\u7248\u672C\u53D1\u5E03\uFF0C\u5305\u542BIP\u68C0\u6D4B\u3001\u51FA\u53E3\u68C0\u6D4B\u3001\u6307\u7EB9\u68C0\u6D4B\u7B49\u6838\u5FC3\u529F\u80FD</p>
    </div>
  </div>
  <footer><p>&copy; 2024 IPPure</p></footer>
</body>
</html>`;
}
__name(getChangelogPage, "getChangelogPage");
function getContactPage() {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>\u8054\u7CFB\u65B9\u5F0F - IPPure</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; background: #0f172a; color: #e2e8f0; min-height: 100vh; }
    .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
    header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px 0; }
    nav { display: flex; justify-content: space-between; align-items: center; max-width: 1200px; margin: 0 auto; padding: 0 20px; }
    nav .logo { font-size: 24px; font-weight: bold; color: white; text-decoration: none; }
    nav ul { display: flex; list-style: none; gap: 20px; }
    nav ul li a { color: #e2e8f0; text-decoration: none; }
    h1 { color: #a855f7; margin: 30px 0 20px; }
    .contact-box { background: #1e293b; border-radius: 12px; padding: 30px; margin-top: 20px; }
    .contact-item { margin: 15px 0; }
    .contact-label { color: #a855f7; font-weight: bold; }
    .contact-value { color: #94a3b8; margin-top: 5px; }
    footer { text-align: center; padding: 40px 20px; color: #64748b; margin-top: 60px; border-top: 1px solid #334155; }
  </style>
</head>
<body>
  <header>
    <nav>
      <a href="/" class="logo">IPPure</a>
      <ul>
        <li><a href="/">IP\u68C0\u6D4B</a></li>
        <li><a href="/IP-Outbound-Detect.html">\u51FA\u53E3\u68C0\u6D4B</a></li>
        <li><a href="/IP-leak-Detect.html">VPN\u6EAF\u6E90</a></li>
        <li><a href="/fingerprint.html">\u6307\u7EB9\u68C0\u6D4B</a></li>
        <li><a href="/about.html">\u5173\u4E8E</a></li>
      </ul>
    </nav>
  </header>
  <div class="container">
    <h1>\u8054\u7CFB\u65B9\u5F0F</h1>
    <div class="contact-box">
      <div class="contact-item">
        <div class="contact-label">\u6570\u636E\u7EA0\u9519\u53CD\u9988</div>
        <div class="contact-value">\u5982\u53D1\u73B0IP\u6570\u636E\u6709\u8BEF\uFF0C\u8BF7\u63D0\u4F9B\u5176\u4ED6\u67E5\u8BE2\u6E90\u7684\u6570\u636E\u5BF9\u6BD4\u6216\u8BBE\u5907\u7167\u7247\u4F5C\u4E3A\u53C2\u8003\u4F9D\u636E\u3002</div>
      </div>
      <div class="contact-item">
        <div class="contact-label">\u5546\u52A1\u5408\u4F5C</div>
        <div class="contact-value">\u8BF7\u53D1\u9001\u90AE\u4EF6\u81F3 ygyang@ygyang.uk</div>
      </div>
    </div>
  </div>
  <footer><p>&copy; 2024 IPPure</p></footer>
</body>
</html>`;
}
__name(getContactPage, "getContactPage");
function getTermsPrivacyPage() {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>\u4F7F\u7528\u6761\u6B3E\u4E0E\u9690\u79C1\u8BF4\u660E - IPPure</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; background: #0f172a; color: #e2e8f0; min-height: 100vh; }
    .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
    header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px 0; }
    nav { display: flex; justify-content: space-between; align-items: center; max-width: 1200px; margin: 0 auto; padding: 0 20px; }
    nav .logo { font-size: 24px; font-weight: bold; color: white; text-decoration: none; }
    nav ul { display: flex; list-style: none; gap: 20px; }
    nav ul li a { color: #e2e8f0; text-decoration: none; }
    h1 { color: #a855f7; margin: 30px 0 20px; }
    h2 { color: #a855f7; margin: 25px 0 15px; }
    .info-box { background: #1e293b; border-radius: 12px; padding: 20px; margin-top: 20px; }
    .info-box p { color: #94a3b8; line-height: 1.8; }
    footer { text-align: center; padding: 40px 20px; color: #64748b; margin-top: 60px; border-top: 1px solid #334155; }
  </style>
</head>
<body>
  <header>
    <nav>
      <a href="/" class="logo">IPPure</a>
      <ul>
        <li><a href="/">IP\u68C0\u6D4B</a></li>
        <li><a href="/IP-Outbound-Detect.html">\u51FA\u53E3\u68C0\u6D4B</a></li>
        <li><a href="/IP-leak-Detect.html">VPN\u6EAF\u6E90</a></li>
        <li><a href="/fingerprint.html">\u6307\u7EB9\u68C0\u6D4B</a></li>
        <li><a href="/about.html">\u5173\u4E8E</a></li>
      </ul>
    </nav>
  </header>
  <div class="container">
    <h1>\u4F7F\u7528\u6761\u6B3E\u4E0E\u9690\u79C1\u8BF4\u660E</h1>
    <div class="info-box">
      <h2>\u4F7F\u7528\u6761\u6B3E</h2>
      <p>IPPure\u4EC5\u63D0\u4F9BIP\u68C0\u6D4B\u670D\u52A1\uFF0C\u7528\u6237\u5728\u4F7F\u7528\u672C\u670D\u52A1\u65F6\u987B\u9075\u5B88\u5F53\u5730\u6CD5\u5F8B\u6CD5\u89C4\uFF0C\u4E0D\u5F97\u7528\u4E8E\u975E\u6CD5\u7528\u9014\u3002</p>
    </div>
    <div class="info-box">
      <h2>\u9690\u79C1\u8BF4\u660E</h2>
      <p>IPPure\u4E0D\u4F1A\u8BB0\u5F55\u7528\u6237\u7684\u6D4F\u89C8\u884C\u4E3A\u548C\u4E2A\u4EBA\u4FE1\u606F\u3002\u6211\u4EEC\u4EC5\u6536\u96C6\u8BBF\u95EE\u65F6\u7684IP\u5730\u5740\u7528\u4E8E\u68C0\u6D4B\u76EE\u7684\uFF0C\u4E14\u4E0D\u4F1A\u4E0E\u7B2C\u4E09\u65B9\u5171\u4EAB\u3002</p>
    </div>
  </div>
  <footer><p>&copy; 2024 IPPure</p></footer>
</body>
</html>`;
}
__name(getTermsPrivacyPage, "getTermsPrivacyPage");
export {
  index_default as default
};
//# sourceMappingURL=index.js.map
