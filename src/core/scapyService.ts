import { pythonBundle } from './pythonBundle';

declare global {
    interface Window {
        loadPyodide: (config: any) => Promise<any>;
        pyodide: any;
    }
}

type PyodideInterface = any;

export class ScapyService {
    private pyodide: PyodideInterface | null = null;
    private readyPromise: Promise<void> | null = null;
    private session_manager: any = null;

    private async runPython(code: string): Promise<any> {
        if (!this.pyodide) throw new Error("Pyodide not initialized");
        // Definitive defense against null byte errors in Python compiler
        // eslint-disable-next-line no-control-regex
        const cleanCode = code.replace(/\0/g, '');
        return await this.pyodide.runPythonAsync(cleanCode);
    }

    async init() {
        if (this.readyPromise) return this.readyPromise;
        this.readyPromise = (async () => {
            try {
                if (!window.loadPyodide) throw new Error("Pyodide script not loaded");
                
                this.pyodide = await window.loadPyodide({
                    indexURL: "./pyodide/", 
                    checkIntegrity: false,
                    stdout: (text: string) => console.log("%c[Python]", "color: green", text),
                    stderr: (text: string) => console.warn("%c[Python Error]", "color: red", text)
                });
                window.pyodide = this.pyodide;

                // 1. ENVIRONMENT MOCKS
                await this.runPython(`
import sys, socket
from types import ModuleType
socket.AF_INET6 = 10
socket.has_ipv6 = True
socket.inet_pton = lambda af, addr: bytes(16) if af == 10 else bytes(4)
socket.inet_ntop = lambda af, addr: "::" if af == 10 else "0.0.0.0"
class MockSocket:
    def __init__(self, *a, **k): pass
    def setsockopt(self, *a): pass
    def bind(self, *a): pass
    def connect(self, *a): pass
    def close(self, *a): pass
    def fileno(self): return 1
    def send(self, *a): return 0
    def sendto(self, *a): return 0
    def recv(self, *a): return b""
    def recvfrom(self, *a): return (b"", ("127.0.0.1", 0))
    def getsockname(self): return ("127.0.0.1", 0)
socket.socket = MockSocket

def provide_full_mocks():
    if 'hashlib' in sys.modules and hasattr(sys.modules['hashlib'], 'sha224'): return
    class DummyHash:
        def __init__(self, name, data=b''): self.name = name; self.data = data
        def update(self, data): self.data += data
        def hexdigest(self): return "00" * 64
        def digest(self): return b"\\x00" * 64
    h = ModuleType('hashlib')
    h.sha256 = lambda d=b'': DummyHash('sha256', d)
    h.sha224 = lambda d=b'': DummyHash('sha224', d)
    h.sha384 = lambda d=b'': DummyHash('sha384', d)
    h.sha512 = lambda d=b'': DummyHash('sha512', d)
    h.sha1 = lambda d=b'': DummyHash('sha1', d)
    h.md5 = lambda d=b'': DummyHash('md5', d)
    h.algorithms_guaranteed = {'sha256', 'sha224', 'sha384', 'sha512', 'sha1', 'md5'}
    h.algorithms_available = h.algorithms_guaranteed
    sys.modules['hashlib'] = h
    if 'ssl' not in sys.modules:
        s = ModuleType('ssl')
        s.CertificateError = type('CertificateError', (Exception,), {})
        s.SSLError = type('SSLError', (Exception,), {})
        s.HAS_SNI = True
        sys.modules['ssl'] = s
provide_full_mocks()
                `);

                // 2. LOAD EXTERNAL LIBRARIES
                const baseUrl = window.location.href.substring(0, window.location.href.lastIndexOf('/') + 1);
                const pyodideUrl = new URL("./pyodide/", baseUrl).href;
                await this.pyodide.loadPackage(`${pyodideUrl}micropip-0.11.0-py3-none-any.whl`);

                await this.runPython(`
import micropip
try:
    import micropip.wheelinfo
    micropip.wheelinfo._validate_sha256_checksum = lambda data, expected: None
except: pass
await micropip.install(["${pyodideUrl}bitstring-4.3.1-py3-none-any.whl", "${pyodideUrl}pycrate-0.7.11-py2.py3-none-any.whl", "${pyodideUrl}scapy-2.7.0-py3-none-any.whl"])
from scapy.config import conf
conf.verb = 0; conf.ipv6_enabled = False; conf.L3socket = None
                `);

                // 3. FILESYSTEM DEPLOYMENT
                const pythonDir = "/home/pyodide/python";
                const templatesDir = "/home/pyodide/Templates";
                const libDir = pythonDir + "/pycrate_asn1dir";
                [pythonDir, pythonDir + "/handlers", pythonDir + "/core_utils", templatesDir, libDir].forEach(d => {
                    try { this.pyodide.FS.mkdir(d); } catch(e) {}
                });

                // Deploy authoritative logic from BUNDLE (Guarantees 1:1 console parity)
                const deploy = (files: any, target: string) => {
                    Object.entries(files).forEach(([name, b64]: [string, any]) => {
                        const binStr = atob(b64);
                        const arr = new Uint8Array(binStr.length);
                        for (let i = 0; i < binStr.length; i++) {
                            arr[i] = binStr.charCodeAt(i);
                        }
                        this.pyodide.FS.writeFile(`${target}/${name}`, arr);
                    });
                };
                deploy(pythonBundle.core, pythonDir);
                deploy(pythonBundle.handlers, pythonDir + "/handlers");
                deploy(pythonBundle.core_utils, pythonDir + "/core_utils");
                deploy(pythonBundle.templates, templatesDir);

                // Fetch Large Library Dependencies over network
                const fetchAndWrite = async (file: string, targetDir: string, urlPath: string) => {
                    try {
                        const res = await fetch(new URL(`./python/${urlPath}${file}?t=${Date.now()}`, baseUrl).href);
                        if (res.ok) {
                            const buffer = await res.arrayBuffer();
                            this.pyodide.FS.writeFile(`${targetDir}/${file}`, new Uint8Array(buffer));
                        }
                    } catch (e) { console.error(`Failed to fetch lib: ${file}`, e); }
                };

                const libRes = await fetch(new URL(`./python/pycrate_asn1dir/index.json?t=${Date.now()}`, baseUrl).href);
                if (libRes.ok) {
                    const files = await libRes.json();
                    await Promise.all(files.map((f: string) => fetchAndWrite(f, libDir, "pycrate_asn1dir/")));
                }

                await this.runPython(`
import sys
if "${pythonDir}" not in sys.path: sys.path.append("${pythonDir}")
if "${templatesDir}" not in sys.path: sys.path.append("${templatesDir}")
from session import session_manager
                `);

                this.session_manager = this.pyodide.pyimport("session").session_manager;

            } catch (err) {
                console.error("Initialization CRITICAL FAILURE:", err);
                this.readyPromise = null;
                throw err;
            }
        })();
        return this.readyPromise;
    }

    async dissect(hex: string, wsInfo: any, debug: boolean = false): Promise<any> {
        await this.init();
        if (!this.session_manager) throw new Error("Python backend unavailable");
        // eslint-disable-next-line no-control-regex
        const cleanHex = hex.replace(/\x00/g, '');
        const jsonStr = this.session_manager.dissect(cleanHex, "pkt", JSON.stringify(wsInfo), 1, debug);
        return JSON.parse(jsonStr);
    }

    async runScript(hex: string, script: string, wsInfo: any, debug: boolean = false): Promise<string> { 
        await this.init();
        if (!this.session_manager) throw new Error("Python backend unavailable");
        // eslint-disable-next-line no-control-regex
        const cleanScript = script.replace(/\x00/g, '');
        const newHex = this.session_manager.run_script(hex, cleanScript, JSON.stringify(wsInfo), 1, debug);
        if (newHex.startsWith("{") && newHex.includes('"error":')) { // Check for JSON error object
            const errorObj = JSON.parse(newHex);
            if (errorObj.error) {
                console.error("Python Script Execution Error:", errorObj.error);
                if (errorObj.script) console.error("--- Executed Script ---", errorObj.script);
                if (errorObj.stdout) console.error("--- Script stdout ---", errorObj.stdout);
                if (errorObj.stderr) console.error("--- Script stderr ---", errorObj.stderr);
                if (errorObj.trace) console.error("--- Python Traceback ---", errorObj.trace);
                throw new Error(errorObj.error.split('\n')[0]); // Re-throw concise message for UI
            }
        }
        return newHex;
    }
}

export const scapyService = new ScapyService();
