const FILE_PATH = process.env.FILE_PATH || '/tmp';
const intervalInseconds = process.env.TIME || 100;
const SUB_PATH = process.env.SUB_PATH || 'sub';
const PORT = process.env.PORT || 3000;
const CFPORT = process.env.CFPORT || 443;
const CFIP = process.env.CFIP || 'ip.sb';
const KEEPALIVE = process.env.KEEPALIVE || false;
const SUB_URL = process.env.SUB_URL || '';

const UUID = process.env.UUID || '7160b696-dd5e-42e3-a024-145e92cec916';
const XPATH = process.env.XPATH || UUID.slice(0, 8);
const HTTPSTLS = process.env.HTTPSTLS || true;
const NEZHA_VERSION = process.env.NEZHA_VERSION || 'V0';
const NEZHA_SERVER = process.env.NEZHA_SERVER || '';
const NEZHA_PORT = process.env.NEZHA_PORT || '443';
const NEZHA_KEY = process.env.NEZHA_KEY || '';
const SUB_NAME = process.env.SUB_NAME || '';
const MY_DOMAIN = process.env.MY_DOMAIN || '';

const os = require('os');
const fs = require('fs');
const net = require('net');
const path = require("path");
const http = require('http');
const https = require('https');
const axios = require('axios');
const { pipeline } = require('stream/promises');
const { Buffer } = require('buffer');
const exec = require("child_process").exec;
const delay = (ms) => new Promise(resolve => setTimeout(resolve, ms));

const SETTINGS = {
    ['UUID']: UUID,
    ['LOG_LEVEL']: 'none',
    ['BUFFER_SIZE']: '2048',
    ['XPATH']: `%2F${XPATH}`,
    ['MAX_BUFFERED_POSTS']: 30,
    ['MAX_POST_SIZE']: 1000000,
    ['SESSION_TIMEOUT']: 30000,
    ['CHUNK_SIZE']: 1024 * 1024,
    ['TCP_NODELAY']: true,
    ['TCP_KEEPALIVE']: true,
}

function validate_uuid(left, right) {
    for (let i = 0; i < 16; i++) {
        if (left[i] !== right[i]) return false
    }
    return true
}

function concat_typed_arrays(first, ...args) {
    if (!args || args.length < 1) return first
        let len = first.length
        for (let a of args) len += a.length
            const r = new first.constructor(len)
            r.set(first, 0)
            len = first.length
            for (let a of args) {
                r.set(a, len)
                len += a.length
            }
            return r
}

function log(type, ...args) {
    if (SETTINGS.LOG_LEVEL === 'none') return;

    const levels = {
        'debug': 0,
        'info': 1,
        'warn': 2,
        'error': 3
    };

    const colors = {
        'debug': '\x1b[36m',
        'info': '\x1b[32m',
        'warn': '\x1b[33m',
        'error': '\x1b[31m',
        'reset': '\x1b[0m'
    };

    const configLevel = levels[SETTINGS.LOG_LEVEL] || 1;
    const messageLevel = levels[type] || 0;

    if (messageLevel >= configLevel) {
        const time = new Date().toISOString();
        const color = colors[type] || colors.reset;
        console.log(`${color}[${time}] [${type}]`, ...args, colors.reset);
    }
}

function cleanupOldFiles() {
    try {
        if (fs.existsSync(path.join(FILE_PATH))) {
            fs.rmSync(path.join(FILE_PATH), { recursive: true });
            // console.log(`${FILE_PATH} deleted`);
        } else {
            // console.log(`${FILE_PATH} not created`);
        }
    } catch (error) {
        // console.log(`unable to rm ${FILE_PATH}`);
    }
}

function createFolder(folderPath) {
    if (!fs.existsSync(folderPath)) {
        fs.mkdirSync(folderPath);
        // console.log(`${folderPath} is created`);
    } else {
        // console.log(`${folderPath} already exists`);
    }
}

function execPromise(command, options = {}) {
    return new Promise((resolve, reject) => {
        const child = exec(command, options, (error, stdout, stderr) => {
            if (error) {
                const err = new Error(`Command failed: ${error.message}`);
                err.code = error.code;
                err.stderr = stderr.trim();
                reject(err);
            } else {
                resolve(stdout.trim());
            }
        });
    });
}

async function detectProcess(processName) {
    const methods = [
        { cmd: `pidof "${processName}"`, name: 'pidof' },
        { cmd: `pgrep -x "${processName}"`, name: 'pgrep' },
        { cmd: `ps -eo pid,comm | awk -v name="${processName}" '$2 == name {print $1}'`, name: 'ps+awk' }
    ];

    for (const method of methods) {
        try {
            const stdout = await execPromise(method.cmd);
            if (stdout) {
                return stdout.replace(/\n/g, ' ').trim();
            }
        } catch (error) {
            if (error.code !== 127 && error.code !== 1) {
                console.debug(`[detectProcess] ${method.name} error:`, error.message);
            }
        }
    }
    return '';
}

async function killProcess(process_name) {
    console.log(`Attempting to kill process: ${process_name}`);

    try {
        const pids = await detectProcess(process_name);
        if (!pids) {
            console.warn(`Process '${process_name}' not found`);
            return { success: true, message: 'Process not found' };
        }

        await execPromise(`kill -9 ${pids}`);
        const msg = `Killed process (PIDs: ${pids})`;
        console.log(msg);
        return { success: true, message: msg };

    } catch (error) {
        const msg = `Kill failed: ${error.message}`;
        console.error(msg);
        return { success: false, message: msg };
    }
}

function generateRandomString(length) {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * characters.length));
    }
    return result;
}

function getSystemArchitecture() {
    const arch = os.arch();
    if (arch === 'arm' || arch === 'arm64' || arch === 'aarch64') {
        return 'arm';
    } else {
        return 'amd';
    }
}

function getFilesForArchitecture(architecture) {
    const FILE_URLS = {
        app: {
            V0: {
                arm: "https://github.com/kahunama/myfile/releases/download/main/nezha-agent_arm",
                amd: "https://github.com/kahunama/myfile/releases/download/main/nezha-agent"
            },
            V1: {
                arm: "https://github.com/mytcgd/myfiles/releases/download/main/nezha-agentv1_arm",
                amd: "https://github.com/mytcgd/myfiles/releases/download/main/nezha-agentv1"
            }
        }
    };
    if (NEZHA_SERVER && NEZHA_PORT && NEZHA_KEY && NEZHA_VERSION) {
        // const baseFiles = [
        //     { fileName: generateRandomString(5), originalName: "app", fileUrl: FILE_URLS.app[NEZHA_VERSION][architecture] },
        // ];
        const baseFiles = [
            {
                fileName: "tmp" + generateRandomString(5),
                originalName: "app",
                fileUrl: FILE_URLS.app[NEZHA_VERSION][architecture]
            },
        ];
        return baseFiles;
    } else {
        return [];
    }
}

async function download_function(fileName, originalName, fileUrl) {
    const filePath = path.join(FILE_PATH, fileName);
    let downloadSuccess = false;

    try {
        const response = await axios({
            method: 'get',
            url: fileUrl,
            responseType: 'stream',
        });
        await pipeline(response.data, fs.createWriteStream(filePath));
        // console.log(`Download ${originalName} (renamed to ${fileName}) successfully`);
        downloadSuccess = true;
    } catch (err) {
        // console.log(`Download ${originalName} (renamed to ${fileName}) failed: ${err.message}`);
    }

    return { fileName, originalName, filePath, success: downloadSuccess };
}

let fileMapping = {};
async function downloadFiles() {
    try {
        const architecture = getSystemArchitecture();
        if (!architecture) {
            console.log(`Can't determine system architecture.`);
            return fileMapping;
        }

        const filesToDownload = getFilesForArchitecture(architecture);
        if (filesToDownload.length === 0) {
            console.log(`Can't find a file for the current architecture`);
            return fileMapping;
        }

        const downloadPromises = filesToDownload.map(fileInfo =>
        download_function(fileInfo.fileName, fileInfo.originalName, fileInfo.fileUrl)
        );
        const downloadedFilesInfo = await Promise.all(downloadPromises);

        downloadedFilesInfo.forEach(info => {
            if (info.success) {
                try {
                    fs.chmodSync(info.filePath, 0o755);
                    // console.log(`Empowerment success for ${info.fileName}: 755`);
                    fileMapping[info.originalName] = info.fileName;
                } catch (err) {
                    // console.warn(`Empowerment failed for ${info.fileName}: ${err.message}`);
                }
            }
        });

        return fileMapping;
    } catch (err) {
        console.error('Error downloading files:', err);
        return fileMapping;
    }
}

let NEZHA_TLS;
function nezconfig() {
    const tlsPorts = ['443', '8443', '2096', '2087', '2083', '2053'];
    if (NEZHA_VERSION === 'V0') {
        if (tlsPorts.includes(NEZHA_PORT)) {
            NEZHA_TLS = '--tls';
        } else {
            NEZHA_TLS = '';
        }
        return NEZHA_TLS
    } else if (NEZHA_VERSION === 'V1') {
        if (tlsPorts.includes(NEZHA_PORT)) {
            NEZHA_TLS = 'true';
        } else {
            NEZHA_TLS = 'false';
        }
        const nezv1configPath = path.join(FILE_PATH, '/config.yml');
        const v1configData = `client_secret: ${NEZHA_KEY}
debug: false
disable_auto_update: true
disable_command_execute: false
disable_force_update: true
disable_nat: false
disable_send_query: false
gpu: false
insecure_tls: false
ip_report_period: 1800
report_delay: 4
server: ${NEZHA_SERVER}:${NEZHA_PORT}
skip_connection_count: false
skip_procs_count: false
temperature: false
tls: ${NEZHA_TLS}
use_gitee_to_upgrade: false
use_ipv6_country_code: false
uuid: ${UUID}`;
        try {
            fs.writeFileSync(nezv1configPath, v1configData);
            // console.log('config.yml file created and written successfully.');
        } catch (err) {
            // console.error('Error creating or writing config.yml file:', err);
        }
    }
}

async function runapp() {
    if (fileMapping['app'] && fs.existsSync(path.join(FILE_PATH, fileMapping['app']))) {
        if (NEZHA_VERSION === 'V0') {
            const command = `nohup ${FILE_PATH}/${fileMapping['app']} -s ${NEZHA_SERVER}:${NEZHA_PORT} -p ${NEZHA_KEY} ${NEZHA_TLS} --report-delay=4 --skip-conn --skip-procs --disable-auto-update >/dev/null 2>&1 &`;
            try {
                await execPromise(command);
            } catch (error) {
                console.error(`${fileMapping['app']} running error: ${error}`);
            }
        } else if (NEZHA_VERSION === 'V1') {
            const command = `nohup ${FILE_PATH}/${fileMapping['app']} -c ${FILE_PATH}/config.yml >/dev/null 2>&1 &`;
            try {
                await execPromise(command);
            } catch (error) {
                console.error(`${fileMapping['app']} running error: ${error}`);
            }
        }
    } else {
        console.log('app file not found, skip running');
    }
}

async function run() {
    if (NEZHA_VERSION && NEZHA_SERVER && NEZHA_PORT && NEZHA_KEY) {
        nezconfig();
        const appPids = await detectProcess(`${fileMapping['app']}`);
        if (appPids) {
            // console.log(`${fileMapping['app']} is already running. PIDs:`, appPids);
        } else {
            await runapp();
        }
        await delay(1000);
        // console.log(`${fileMapping['app']} is running`);
    } else {
        console.log('Node variable is empty, skip running');
    }
}

async function keep_alive() {
    if (NEZHA_VERSION && NEZHA_SERVER && NEZHA_PORT && NEZHA_KEY) {
        const appPids = await detectProcess(`${fileMapping['app']}`);
        if (appPids) {
            // console.log(`${fileMapping['app']} is already running. PIDs:`, appPids);
        } else {
            // console.log(`${fileMapping['app']} runs again !`);
            await runapp();
        }
    }
}

function parse_uuid(uuid) {
    uuid = uuid.replaceAll('-', '')
    const r = []
    for (let index = 0; index < 16; index++) {
        r.push(parseInt(uuid.substr(index * 2, 2), 16))
    }
    return r
}

async function read_vless_header(reader, cfg_uuid_str) {
    let readed_len = 0
    let header = new Uint8Array()
    let read_result = { value: header, done: false }
    async function inner_read_until(offset) {
        if (read_result.done) {
            throw new Error('header length too short')
        }
        const len = offset - readed_len
        if (len < 1) {
            return
        }
        read_result = await read_atleast(reader, len)
        readed_len += read_result.value.length
        header = concat_typed_arrays(header, read_result.value)
    }

    await inner_read_until(1 + 16 + 1)

    const version = header[0]
    const uuid = header.slice(1, 1 + 16)
    const cfg_uuid = parse_uuid(cfg_uuid_str)
    if (!validate_uuid(uuid, cfg_uuid)) {
        throw new Error(`invalid UUID`)
    }
    const pb_len = header[1 + 16]
    const addr_plus1 = 1 + 16 + 1 + pb_len + 1 + 2 + 1
    await inner_read_until(addr_plus1 + 1)

    const cmd = header[1 + 16 + 1 + pb_len]
    const COMMAND_TYPE_TCP = 1
    if (cmd !== COMMAND_TYPE_TCP) {
        throw new Error(`unsupported command: ${cmd}`)
    }

    const port = (header[addr_plus1 - 1 - 2] << 8) + header[addr_plus1 - 1 - 1]
    const atype = header[addr_plus1 - 1]

    const ADDRESS_TYPE_IPV4 = 1
    const ADDRESS_TYPE_STRING = 2
    const ADDRESS_TYPE_IPV6 = 3
    let header_len = -1
    if (atype === ADDRESS_TYPE_IPV4) {
        header_len = addr_plus1 + 4
    } else if (atype === ADDRESS_TYPE_IPV6) {
        header_len = addr_plus1 + 16
    } else if (atype === ADDRESS_TYPE_STRING) {
        header_len = addr_plus1 + 1 + header[addr_plus1]
    }
    if (header_len < 0) {
        throw new Error('read address type failed')
    }
    await inner_read_until(header_len)

    const idx = addr_plus1
    let hostname = ''
    if (atype === ADDRESS_TYPE_IPV4) {
        hostname = header.slice(idx, idx + 4).join('.')
    } else if (atype === ADDRESS_TYPE_STRING) {
        hostname = new TextDecoder().decode(
            header.slice(idx + 1, idx + 1 + header[idx]),
        )
    } else if (atype === ADDRESS_TYPE_IPV6) {
        hostname = header
        .slice(idx, idx + 16)
        .reduce(
            (s, b2, i2, a) =>
            i2 % 2 ? s.concat(((a[i2 - 1] << 8) + b2).toString(16)) : s,
                [],
        )
        .join(':')
    }

    if (!hostname) {
        log('error', 'Failed to parse hostname');
        throw new Error('parse hostname failed')
    }

    log('info', `VLESS connection to ${hostname}:${port}`);
    return {
        hostname,
        port,
        data: header.slice(header_len),
        resp: new Uint8Array([version, 0]),
    }
}

async function read_atleast(reader, n) {
    const buffs = []
    let done = false
    while (n > 0 && !done) {
        const r = await reader.read()
        if (r.value) {
            const b = new Uint8Array(r.value)
            buffs.push(b)
            n -= b.length
        }
        done = r.done
    }
    if (n > 0) {
        throw new Error(`not enough data to read`)
    }
    return {
        value: concat_typed_arrays(...buffs),
        done,
    }
}

async function parse_header(uuid_str, client) {
    log('debug', 'Starting to parse VLESS header');
    const reader = client.readable.getReader()
    try {
        const vless = await read_vless_header(reader, uuid_str)
        log('debug', 'VLESS header parsed successfully');
        return vless
    } catch (err) {
        log('error', `VLESS header parse error: ${err.message}`);
        throw new Error(`read vless header error: ${err.message}`)
    } finally {
        reader.releaseLock()
    }
}

async function connect_remote(hostname, port) {
    const timeout = 8000;
    try {
        const conn = await timed_connect(hostname, port, timeout);

        conn.setNoDelay(true);
        conn.setKeepAlive(true, 1000);

        conn.bufferSize = parseInt(SETTINGS.BUFFER_SIZE) * 1024;

        log('info', `Connected to ${hostname}:${port}`);
        return conn;
    } catch (err) {
        log('error', `Connection failed: ${err.message}`);
        throw err;
    }
}

function timed_connect(hostname, port, ms) {
    return new Promise((resolve, reject) => {
        const conn = net.createConnection({ host: hostname, port: port })
        const handle = setTimeout(() => {
            reject(new Error(`connect timeout`))
        }, ms)
        conn.on('connect', () => {
            clearTimeout(handle)
            resolve(conn)
        })
        conn.on('error', (err) => {
            clearTimeout(handle)
            reject(err)
        })
    })
}

function pipe_relay() {
    async function pump(src, dest, first_packet) {
        const chunkSize = parseInt(SETTINGS.CHUNK_SIZE);

        if (first_packet.length > 0) {
            if (dest.write) {
                dest.cork();
                dest.write(first_packet);
                process.nextTick(() => dest.uncork());
            } else {
                const writer = dest.writable.getWriter();
                try {
                    await writer.write(first_packet);
                } finally {
                    writer.releaseLock();
                }
            }
        }

        try {
            if (src.pipe) {
                src.pause();
                src.pipe(dest, {
                    end: true,
                    highWaterMark: chunkSize
                });
                src.resume();
            } else {
                await src.readable.pipeTo(dest.writable, {
                    preventClose: false,
                    preventAbort: false,
                    preventCancel: false,
                    signal: AbortSignal.timeout(SETTINGS.SESSION_TIMEOUT)
                });
            }
        } catch (err) {
            if (!err.message.includes('aborted')) {
                log('error', 'Relay error:', err.message);
            }
            throw err;
        }
    }
    return pump;
}

function socketToWebStream(socket) {
    let readController;
    let writeController;

    socket.on('error', (err) => {
        log('error', 'Socket error:', err.message);
        readController?.error(err);
        writeController?.error(err);
    });

    return {
        readable: new ReadableStream({
            start(controller) {
                readController = controller;
                socket.on('data', (chunk) => {
                    try {
                        controller.enqueue(chunk);
                    } catch (err) {
                        log('error', 'Read controller error:', err.message);
                    }
                });
                socket.on('end', () => {
                    try {
                        controller.close();
                    } catch (err) {
                        log('error', 'Read controller close error:', err.message);
                    }
                });
            },
            cancel() {
                socket.destroy();
            }
        }),
        writable: new WritableStream({
            start(controller) {
                writeController = controller;
            },
            write(chunk) {
                return new Promise((resolve, reject) => {
                    if (socket.destroyed) {
                        reject(new Error('Socket is destroyed'));
                        return;
                    }
                    socket.write(chunk, (err) => {
                        if (err) reject(err);
                        else resolve();
                    });
                });
            },
            close() {
                if (!socket.destroyed) {
                    socket.end();
                }
            },
            abort(err) {
                socket.destroy(err);
            }
        })
    };
}

function relay(cfg, client, remote, vless) {
    const pump = pipe_relay();
    let isClosing = false;

    const remoteStream = socketToWebStream(remote);

    function cleanup() {
        if (!isClosing) {
            isClosing = true;
            try {
                remote.destroy();
            } catch (err) {
                if (!err.message.includes('aborted') &&
                    !err.message.includes('socket hang up')) {
                    log('error', `Cleanup error: ${err.message}`);
                    }
            }
        }
    }

    const uploader = pump(client, remoteStream, vless.data)
    .catch(err => {
        if (!err.message.includes('aborted') &&
            !err.message.includes('socket hang up')) {
            log('error', `Upload error: ${err.message}`);
            }
    })
    .finally(() => {
        client.reading_done && client.reading_done();
    });

    const downloader = pump(remoteStream, client, vless.resp)
    .catch(err => {
        if (!err.message.includes('aborted') &&
            !err.message.includes('socket hang up')) {
            log('error', `Download error: ${err.message}`);
            }
    });

    downloader
    .finally(() => uploader)
    .finally(cleanup);
}

const sessions = new Map();

class Session {
    constructor(uuid) {
        this.uuid = uuid;
        this.nextSeq = 0;
        this.downstreamStarted = false;
        this.lastActivity = Date.now();
        this.vlessHeader = null;
        this.remote = null;
        this.initialized = false;
        this.responseHeader = null;
        this.headerSent = false;
        this.bufferedData = new Map();
        this.cleaned = false;
        this.pendingPackets = [];
        this.currentStreamRes = null;
        this.pendingBuffers = new Map();
        log('debug', `Created new session with UUID: ${uuid}`);
    }

    async initializeVLESS(firstPacket) {
        if (this.initialized) return true;

        try {
            log('debug', 'Initializing VLESS connection from first packet');
            const readable = new ReadableStream({
                start(controller) {
                    controller.enqueue(firstPacket);
                    controller.close();
                }
            });

            const client = {
                readable: readable,
                writable: new WritableStream()
            };

            this.vlessHeader = await parse_header(SETTINGS.UUID, client);
            log('info', `VLESS header parsed: ${this.vlessHeader.hostname}:${this.vlessHeader.port}`);

            this.remote = await connect_remote(this.vlessHeader.hostname, this.vlessHeader.port);
            log('info', 'Remote connection established');

            this.initialized = true;
            return true;
        } catch (err) {
            log('error', `Failed to initialize VLESS: ${err.message}`);
            return false;
        }
    }

    async processPacket(seq, data) {
        try {
            this.pendingBuffers.set(seq, data);
            log('debug', `Buffered packet seq=${seq}, size=${data.length}`);

            while (this.pendingBuffers.has(this.nextSeq)) {
                const nextData = this.pendingBuffers.get(this.nextSeq);
                this.pendingBuffers.delete(this.nextSeq);

                if (!this.initialized && this.nextSeq === 0) {
                    if (!await this.initializeVLESS(nextData)) {
                        throw new Error('Failed to initialize VLESS connection');
                    }
                    this.responseHeader = Buffer.from(this.vlessHeader.resp);
                    await this._writeToRemote(this.vlessHeader.data);

                    if (this.currentStreamRes) {
                        this._startDownstreamResponse();
                    }
                } else {
                    if (!this.initialized) {
                        log('warn', `Received out of order packet seq=${seq} before initialization`);
                        continue;
                    }
                    await this._writeToRemote(nextData);
                }

                this.nextSeq++;
                log('debug', `Processed packet seq=${this.nextSeq-1}`);
            }

            if (this.pendingBuffers.size > SETTINGS.MAX_BUFFERED_POSTS) {
                throw new Error('Too many buffered packets');
            }

            return true;
        } catch (err) {
            log('error', `Process packet error: ${err.message}`);
            throw err;
        }
    }

    _startDownstreamResponse() {
        if (!this.currentStreamRes || !this.responseHeader) return;

        try {
            const protocol = this.currentStreamRes.socket?.alpnProtocol || 'http/1.1';
            const isH2 = protocol === 'h2';

            if (!this.headerSent) {
                log('debug', `Sending VLESS response header (${protocol}): ${this.responseHeader.length} bytes`);
                this.currentStreamRes.write(this.responseHeader);
                this.headerSent = true;
            }

            if (isH2) {
                this.currentStreamRes.socket.setNoDelay(true);

                const transform = new require('stream').Transform({
                    transform(chunk, encoding, callback) {
                        const size = 16384;
                        for (let i = 0; i < chunk.length; i += size) {
                            this.push(chunk.slice(i, i + size));
                        }
                        callback();
                    }
                });

                this.remote.pipe(transform).pipe(this.currentStreamRes);
            } else {
                this.remote.pipe(this.currentStreamRes);
            }

            this.remote.on('end', () => {
                if (!this.currentStreamRes.writableEnded) {
                    this.currentStreamRes.end();
                }
            });

            this.remote.on('error', (err) => {
                log('error', `Remote error: ${err.message}`);
                if (!this.currentStreamRes.writableEnded) {
                    this.currentStreamRes.end();
                }
            });
        } catch (err) {
            log('error', `Error starting downstream: ${err.message}`);
            this.cleanup();
        }
    }

    startDownstream(res, headers) {
        if (!res.headersSent) {
            res.writeHead(200, headers);
        }

        this.currentStreamRes = res;

        if (this.initialized && this.responseHeader) {
            this._startDownstreamResponse();
        }

        res.on('close', () => {
            log('info', 'Client connection closed');
            this.cleanup();
        });

        return true;
    }

    async _writeToRemote(data) {
        if (!this.remote || this.remote.destroyed) {
            throw new Error('Remote connection not available');
        }

        return new Promise((resolve, reject) => {
            this.remote.write(data, (err) => {
                if (err) {
                    log('error', `Failed to write to remote: ${err.message}`);
                    reject(err);
                } else {
                    resolve();
                }
            });
        });
    }

    _startDownstreamResponse() {
        if (!this.currentStreamRes || !this.responseHeader) return;

        try {
            if (!this.headerSent) {
                this.currentStreamRes.write(this.responseHeader);
                this.headerSent = true;
            }

            this.remote.pipe(this.currentStreamRes);

            this.remote.on('end', () => {
                if (!this.currentStreamRes.writableEnded) {
                    this.currentStreamRes.end();
                }
            });

            this.remote.on('error', (err) => {
                log('error', `Remote error: ${err.message}`);
                if (!this.currentStreamRes.writableEnded) {
                    this.currentStreamRes.end();
                }
            });
        } catch (err) {
            log('error', `Error starting downstream: ${err.message}`);
            this.cleanup();
        }
    }

    cleanup() {
        if (!this.cleaned) {
            this.cleaned = true;
            log('debug', `Cleaning up session ${this.uuid}`);
            if (this.remote) {
                this.remote.destroy();
                this.remote = null;
            }
            this.initialized = false;
            this.headerSent = false;
        }
    }
}

async function getCloudflareMeta() {
    return new Promise((resolve, reject) => {
        const options = {
            hostname: 'speed.cloudflare.com',
            path: '/meta',
            method: 'GET',
        };

        const req = https.request(options, (res) => {
            let data = '';
            res.on('data', (chunk) => {
                data += chunk;
            });
            res.on('end', () => {
                const parsedData = JSON.parse(data);
                resolve(parsedData);
            });
        });

        req.on('error', (error) => {
            reject(error);
        });

        req.end();
    });
}

let UPLOAD_DATA;
async function getipandisp() {
    let data = await getCloudflareMeta();
    let SERVERIP = data.clientIp;

    let fields1 = data.country;
    let fields2 = data.asOrganization;
    ISP = (fields1 + '-' + fields2).replace(/ /g, '_');
    // console.log(ISP);

    let IP = MY_DOMAIN;
    if (!MY_DOMAIN) {
        if (SERVERIP.includes(':')) {
            IP = `[${SERVERIP}]`;
        } else {
            IP = `${SERVERIP}`;
        }
        // console.log(IP);
    }

    if (HTTPSTLS == true) {
        UPLOAD_DATA = `vless://${UUID}@${CFIP}:${CFPORT}?encryption=none&security=tls&sni=${IP}&fp=chrome&allowInsecure=1&type=xhttp&host=${IP}&path=${SETTINGS.XPATH}&mode=packet-up#${ISP}-${SUB_NAME}`;
    } else if (HTTPSTLS == false) {
        UPLOAD_DATA = `vless://${UUID}@${IP}:${PORT}?encryption=none&security=none&sni=${IP}&fp=chrome&allowInsecure=1&type=xhttp&host=${IP}&path=${SETTINGS.XPATH}&mode=packet-up#${ISP}-${SUB_NAME}`;
    }
    return UPLOAD_DATA
}

const server = http.createServer((req, res) => {
    const headers = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST',
        'Cache-Control': 'no-store',
        'X-Accel-Buffering': 'no',
        'X-Padding': generatePadding(100, 1000),
    };

    if (req.url === '/') {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end('Hello, World\n');
        return;
    }

    if (req.url === `/${SUB_PATH}`) {
        const vlessURL = `${UPLOAD_DATA}`;
        const base64Content = Buffer.from(vlessURL).toString('base64');
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end(base64Content + '\n');
        return;
    }

    const pathMatch = req.url.match(new RegExp(`${XPATH}/([^/]+)(?:/([0-9]+))?$`));
    if (!pathMatch) {
        res.writeHead(404);
        res.end();
        return;
    }

    const uuid = pathMatch[1];
    const seq = pathMatch[2] ? parseInt(pathMatch[2]) : null;

    if (req.method === 'GET' && !seq) {
        headers['Content-Type'] = 'application/octet-stream';
        headers['Transfer-Encoding'] = 'chunked';

        let session = sessions.get(uuid);
        if (!session) {
            session = new Session(uuid);
            sessions.set(uuid, session);
            log('info', `Created new session for GET: ${uuid}`);
        }

        session.downstreamStarted = true;

        if (!session.startDownstream(res, headers)) {
            log('error', `Failed to start downstream for session: ${uuid}`);
            if (!res.headersSent) {
                res.writeHead(500);
                res.end();
            }
            session.cleanup();
            sessions.delete(uuid);
        }
        return;
    }

    if (req.method === 'POST' && seq !== null) {
        let session = sessions.get(uuid);
        if (!session) {
            session = new Session(uuid);
            sessions.set(uuid, session);
            log('info', `Created new session for POST: ${uuid}`);

            setTimeout(() => {
                const currentSession = sessions.get(uuid);
                if (currentSession && !currentSession.downstreamStarted) {
                    log('warn', `Session ${uuid} timed out without downstream`);
                    currentSession.cleanup();
                    sessions.delete(uuid);
                }
            }, SETTINGS.SESSION_TIMEOUT);
        }

        let data = [];
        let size = 0;
        let headersSent = false;

        req.on('data', chunk => {
            size += chunk.length;
            if (size > SETTINGS.MAX_POST_SIZE) {
                if (!headersSent) {
                    res.writeHead(413);
                    res.end();
                    headersSent = true;
                }
                return;
            }
            data.push(chunk);
        });

        req.on('end', async () => {
            if (headersSent) return;

            try {
                const buffer = Buffer.concat(data);
                log('info', `Processing packet: seq=${seq}, size=${buffer.length}`);

                await session.processPacket(seq, buffer);

                if (!headersSent) {
                    res.writeHead(200, headers);
                    headersSent = true;
                }
                res.end();

            } catch (err) {
                log('error', `Failed to process POST request: ${err.message}`);
                session.cleanup();
                sessions.delete(uuid);

                if (!headersSent) {
                    res.writeHead(500);
                    headersSent = true;
                }
                res.end();
            }
        });
        return;
    }

    res.writeHead(404);
    res.end();
});

server.on('secureConnection', (socket) => {
    log('debug', `New secure connection using: ${socket.alpnProtocol || 'http/1.1'}`);
});

function generatePadding(min, max) {
    const length = min + Math.floor(Math.random() * (max - min));
    return Buffer.from(Array(length).fill('X').join('')).toString('base64');
}

server.keepAliveTimeout = 620000;
server.headersTimeout = 625000;

server.on('error', (err) => {
    log('error', `Server error: ${err.message}`);
});

async function uploadSubscription(SUB_NAME, UPLOAD_DATA, SUB_URL) {
    const payload = JSON.stringify({ URL_NAME: SUB_NAME, URL: UPLOAD_DATA });

    const postData = Buffer.from(payload, 'utf8');
    const contentLength = postData.length;
    const parsedUrl = new URL(SUB_URL);
    const options = {
        hostname: parsedUrl.hostname,
        port: parsedUrl.port || 443,
        path: parsedUrl.pathname,
        method: 'POST',
        headers: {
            'Content-Type': 'application/json; charset=utf-8',
            'Content-Length': contentLength
        }
    };

    try {
        const responseBody = await new Promise((resolve, reject) => {
            const req = https.request(options, (res) => {
                if (res.statusCode < 200 || res.statusCode >= 300) {
                    return reject(new Error(`HTTP error! status: ${res.statusCode}, response: ${res.statusMessage}`));
                }
                let responseBody = '';
                res.on('data', (chunk) => responseBody += chunk);
                res.on('end', () => resolve(responseBody));
            });
            req.on('error', (error) => reject(error));
            req.write(postData);
            req.end();
        });
        // console.log('Upload successful:', responseBody);
        return responseBody;
    } catch (error) {
        console.error(`Upload failed:`, error.message);
    }
}

function cleanfiles() {
    setTimeout(() => {
        let filesToDelete;
        if (KEEPALIVE == true) {
            filesToDelete = [];
        } else {
            filesToDelete = [
                `${FILE_PATH}/${fileMapping['app']}`,
                `${FILE_PATH}/config.yml`
            ];
        }

        filesToDelete.forEach(filePath => {
            try {
                if (fs.existsSync(filePath)) {
                    if (fs.lstatSync(filePath).isDirectory()) {
                        fs.rmSync(filePath, { recursive: true });
                    } else {
                        fs.unlinkSync(filePath);
                    }
                    // console.log(`${filePath} deleted`);
                }
            } catch (error) {
                // console.error(`Failed to delete ${filePath}: ${error}`);
            }
        });

        console.clear()
        console.log('App is running');
    }, 60000);
}

server.listen(PORT, async () => {
    // await killProcess("tmp*");
    // await delay(1000);
    await getipandisp();
    cleanupOldFiles();
    createFolder(FILE_PATH);
    if (NEZHA_SERVER && NEZHA_PORT && NEZHA_KEY && NEZHA_VERSION) {
        await downloadFiles();
        await delay(5000);
    }
    await run();
    cleanfiles();
    console.log(`Server is running on port ${PORT}`);
    if (SUB_URL) {
        try {
            const response = await uploadSubscription(SUB_NAME, UPLOAD_DATA, SUB_URL);
        } catch (error) {
            console.error('upload failed:', error);
        }
    }
    if (KEEPALIVE == true) {
        await keep_alive();
        setInterval(keep_alive, intervalInseconds * 1000);
    }
});
