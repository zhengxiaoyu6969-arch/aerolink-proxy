// Aerolink 零依赖反向代理（非 Cloudflare 出口）
// 用途：绕过 Aerolink WAF 对 Cloudflare 出口 ASN 的封禁（403），
//       以及电信 IPv6 直连的 ECONNRESET。
// 部署：Railway / Fly.io / Render / 任意 VPS（域名不要挂 Cloudflare）。
// 依赖：仅 Node.js 内置 http/https，无需 npm install。
//
// 本地验证：  node aerolink-proxy-node.js   (默认监听 :3000)
// 生产：      平台会注入 PORT 环境变量；VPS 上用 `PORT=3000 node aerolink-proxy-node.js`
//            再套 nginx/caddy 反代 + HTTPS。

const http = require('http');
const https = require('https');

const PORT = process.env.PORT || 3000;
const UPSTREAM_HOST = 'aerolink.lat';

// 过滤掉不应转发的逐跳头部
function filterHeaders(h) {
  const out = {};
  for (const [k, v] of Object.entries(h)) {
    const lk = k.toLowerCase();
    if (lk === 'connection' || lk === 'transfer-encoding' || lk === 'content-length') continue;
    out[k] = v;
  }
  return out;
}

const server = http.createServer((req, res) => {
  const options = {
    method: req.method,
    hostname: UPSTREAM_HOST,
    path: req.url && req.url.length ? req.url : '/',
    headers: {
      'Content-Type': req.headers['content-type'] || 'application/json',
      // 透传 WorkBuddy 发来的 key（Authorization: Bearer aero_live_...）
      'Authorization': req.headers['authorization'] || '',
      'Accept': req.headers['accept'] || 'application/json, text/event-stream',
      // 浏览器指纹头，提高绕过 WAF 的概率
      'User-Agent':
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ' +
        '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
      'Origin': 'https://aerolink.lat',
      'Referer': 'https://aerolink.lat/',
    },
  };
  delete options.headers['host'];
  delete options.headers['connection'];

  const proxyReq = https.request(options, (proxyRes) => {
    res.writeHead(proxyRes.statusCode, filterHeaders(proxyRes.headers));
    proxyRes.pipe(res);
  });

  proxyReq.on('error', (err) => {
    console.error('[aero-proxy] upstream error:', err.message);
    if (!res.headersSent) {
      res.writeHead(502, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'aero_proxy_upstream_error', detail: err.message }));
    } else {
      res.end();
    }
  });

  req.pipe(proxyReq);
});

server.listen(PORT, () => {
  console.log(`[aero-proxy] listening on :${PORT} -> https://${UPSTREAM_HOST}`);
});
