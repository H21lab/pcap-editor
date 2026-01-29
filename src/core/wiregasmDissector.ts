
// @ts-ignore
import loadWiregasm from '@goodtools/wiregasm/dist/wiregasm';
import { PcapParser, PcapPacket } from '../utils/pcapParser';
import { PcapWriter } from '../utils/pcapWriter';

export class WiregasmDissector {
  private wg: any = null;
  private currentSess: any = null;
  private currentPackets: PcapPacket[] = [];
  private currentParser: PcapParser | null = null;
  private currentFilename: string | null = null;
  private operationLock: Promise<any> = Promise.resolve();
  private initPromise: Promise<void> | null = null;

  async init(locateFilePath?: (path: string, prefix: string) => string) {
    if (this.initPromise) return this.initPromise;
    this.initPromise = (async () => {
        if (this.wg) return;
        const locateFile = locateFilePath || ((path: string, prefix: string) => {
          if (path.endsWith(".data")) return "./wiregasm.data";
          if (path.endsWith(".wasm")) return "./wiregasm.wasm";
          return prefix + path;
        });
        this.wg = await loadWiregasm({ locateFile });
        this.wg.init();
        if (this.wg.conf_all_protocols_enabled) this.wg.conf_all_protocols_enabled(true);
        if (this.wg.init_epan) this.wg.init_epan();
    })();
    return this.initPromise;
  }

  private getVal(obj: any, name: string): any {
      if (!obj || typeof obj !== 'object') return undefined;
      try {
          const prop = obj[name];
          if (typeof prop === 'function' && prop.length === 0) return prop.call(obj);
          return typeof prop !== 'function' ? prop : undefined;
      } catch (e) { return undefined; }
  }

  private call(obj: any, method: string, ...args: any[]): any {
      if (!obj || typeof obj[method] !== 'function') return undefined;
      try {
          return obj[method](...args.map(a => typeof a === 'number' ? (a | 0) : a));
      } catch (e) { throw e; }
  }

  private safeDelete(obj: any) {
      if (obj && typeof obj.delete === 'function') {
          try { obj.delete(); } catch(e) {}
      }
  }

  private async runLocked<T>(op: () => Promise<T>): Promise<T> {
      const current = this.operationLock;
      let resolve: any;
      this.operationLock = new Promise(r => resolve = r);
      await current;
      try {
          return await op();
      } finally {
          resolve();
      }
  }

  async dissectSinglePacket(hex: string, originalPacket: any): Promise<any> {
    return this.runLocked(async () => {
        if (!this.wg) await this.init();
        const writer = new PcapWriter(this.getNetworkType());
        let ts = Date.now() / 1000;
        const originalSummary = originalPacket?._summary || {};
        const tVal = originalSummary.t;
        if (tVal !== undefined) ts = Number(tVal);

        writer.writePacket(hex, ts);
        const pcapData = writer.getUint8Array();
        const filename = "/temp_single.pcap";
        try { if (this.wg.FS.analyzePath(filename).exists) this.wg.FS.unlink(filename); } catch(e) {}
        this.wg.FS.writeFile(filename, pcapData);
        
        const sess = new this.wg.DissectSession(filename);
        try {
            const ret = sess.load(); this.safeDelete(ret);
            const framesResp = sess.getFrames("", 0, 1); 
            try {
                const framesVec = this.getVal(framesResp, 'frames');
                try {
                    if (Number(this.getVal(framesVec, 'size') || 0) === 0) throw new Error("No frames in single dissection");
                    const summaryWasm = this.call(framesVec, 'get', 0);
                    try {
                        const frameIdx = parseInt(String(this.getVal(summaryWasm, 'num') || 1), 10);
                        const detail = sess.getFrame(frameIdx);
                        try {
                            const packetData = new Uint8Array(hex.match(/.{1,2}/g)!.map(byte => parseInt(byte, 16)));
                            const result = this.convertWiregasmToInternal(detail, summaryWasm, packetData);
                            // Preserve the original frame number and exact timestamps
                            const origSummary = originalPacket?._summary || {};
                            result._summary.num = Number(origSummary.num || 1);
                            result._summary.sec = origSummary.sec;
                            result._summary.usec = origSummary.usec;
                            return result;
                        } finally { this.safeDelete(detail); }
                    } finally { this.safeDelete(summaryWasm); }
                } finally { this.safeDelete(framesVec); }
            } finally { this.safeDelete(framesResp); }
        } finally { this.safeDelete(sess); }
    });
  }

  async dissect(data: Uint8Array, filename: string, filter: string = ""): Promise<any[]> {
    return this.runLocked(async () => {
        if (!this.wg) await this.init();
        if (this.currentSess) { this.safeDelete(this.currentSess); this.currentSess = null; }

        this.currentParser = new PcapParser(data.buffer);
        this.currentPackets = this.currentParser.parse();

        this.currentFilename = "/uploads/" + filename;
        if (!this.wg.FS.analyzePath("/uploads").exists) this.wg.FS.mkdir("/uploads");
        this.wg.FS.writeFile(this.currentFilename, data);
        
        this.currentSess = new this.wg.DissectSession(this.currentFilename);
        const ret = this.call(this.currentSess, 'load');
        this.safeDelete(ret);
        return this.getFramesInternal(filter);
    });
  }

  private async getFramesInternal(filter: string): Promise<any[]> {
    if (!this.currentSess) return [];
    const framesResp = this.call(this.currentSess, 'getFrames', filter, 0, 0); 
    try {
        const framesVec = this.getVal(framesResp, 'frames');
        try {
            const size = Number(this.getVal(framesVec, 'size') || 0);
            const packets: any[] = [];
            for (let i = 0; i < size; i++) {
                const f = this.call(framesVec, 'get', i);
                try {
                    const columnsVec = this.getVal(f, 'columns');
                    try {
                        const colsSize = Number(this.getVal(columnsVec, 'size') || 0);
                        const columns: string[] = [];
                        for (let j = 0; j < colsSize; j++) columns.push(String(this.call(columnsVec, 'get', j)));
                        
                        const rawNum = this.getVal(f, 'num');
                        const numFromCol = parseInt(columns[0], 10);
                        const num = !isNaN(numFromCol) ? numFromCol : ((rawNum !== undefined && rawNum !== null && !isNaN(Number(rawNum))) ? Number(rawNum) : (i + 1));
                        
                        const t = Number(this.getVal(f, 't') || 0);
                        let sec = Math.floor(t);
                        let usec = Math.round((t - sec) * 1000000);

                        // Try to get exact values from original PCAP header
                        if (this.currentPackets[num - 1]) {
                            sec = this.currentPackets[num - 1].header.ts_sec;
                            usec = this.currentPackets[num - 1].header.ts_usec;
                        }
                        
                        packets.push({_summary: { num, t, sec, usec, c: columns }, _incomplete: true });
                    } finally { this.safeDelete(columnsVec); }
                } finally { this.safeDelete(f); }
            }
            return packets;
        } finally { this.safeDelete(framesVec); }
    } finally { this.safeDelete(framesResp); }
  }

  async getFrames(filter: string = ""): Promise<any[]> {
      return this.runLocked(() => this.getFramesInternal(filter));
  }

  async updateSession(pcapBuffer: Uint8Array) {
      return this.runLocked(async () => {
          if (!this.wg) await this.init();
          const filename = "/temp_edited.pcap";
          this.wg.FS.writeFile(filename, pcapBuffer);
          if (this.currentSess) { this.safeDelete(this.currentSess); }
          this.currentSess = new this.wg.DissectSession(filename);
          const ret = this.call(this.currentSess, 'load');
          this.safeDelete(ret);
          this.currentFilename = filename;
          this.currentParser = new PcapParser(pcapBuffer.buffer);
          this.currentPackets = this.currentParser.parse();
      });
  }

  async getRawBytes(packetIndex: number): Promise<Uint8Array | null> {
      if (this.currentParser && this.currentPackets[packetIndex]) {
          return this.currentParser.getPacketData(this.currentPackets[packetIndex]);
      }
      return null;
  }

  async getRawHex(packetIndex: number): Promise<string> {
      const data = await this.getRawBytes(packetIndex);
      return data ? Array.from(data).map(b => b.toString(16).padStart(2, '0')).join('') : "";
  }

  getNetworkType(): number {
      return this.currentParser ? this.currentParser.getNetworkType() : 1;
  }

  async getPacketFull(originalPacket: any, packetIndex: number): Promise<any> {
    return this.runLocked(async () => {
        if (!this.wg || !this.currentSess) throw new Error("No active session");
        const summary = originalPacket._summary || {};
        const frameNum = Number(summary.num || (packetIndex + 1));

        const detail = this.call(this.currentSess, 'getFrame', frameNum);
        try {
            if (!detail) throw new Error("getFrame returned null for frame #" + frameNum);
            let packetData = null;
            if (this.currentParser && this.currentPackets[frameNum - 1]) {
                packetData = this.currentParser.getPacketData(this.currentPackets[frameNum - 1]);
            }
            return this.convertWiregasmToInternal(detail, summary, packetData);
        } finally { this.safeDelete(detail); }
    });
}

  private convertWiregasmToInternal(detail: any, summary: any, packetData: Uint8Array | null): any {
    const layers: any = {};
    const stack: any[] = [];
    const state = { count: 0 };
    
    const rawNum = this.getVal(summary, 'num');
    const frameNum = (rawNum !== undefined && rawNum !== null && !isNaN(Number(rawNum))) ? Number(rawNum) : 1;
    if (packetData) {
        layers['frame_raw'] = [Array.from(packetData).map(b => b.toString(16).padStart(2, '0')).join(''), 0, packetData.length, 0, 1];
        layers['frame'] = { 'frame.len': packetData.length, 'frame.number': frameNum, 'frame.time_epoch': Number(this.getVal(summary, 't') || 0) };
    }
    
    const treeVec = this.getVal(detail, 'tree');
    try {
        const treeNodes = this.vectorToArray(treeVec);
        for (const node of treeNodes) {
            this.traverseTreeRecursive(node, layers, layers, stack, packetData, 0, state);
            this.safeDelete(node);
        }
    } finally { this.safeDelete(treeVec); }
    
    let columns: string[] = [];
    const colsVec = this.getVal(summary, 'columns');
    try {
        if (colsVec) {
            const size = Number(this.call(colsVec, 'size') || 0);
            for (let i = 0; i < size; i++) columns.push(String(this.call(colsVec, 'get', i)));
        } else if (Array.isArray(summary.c)) {
            columns = summary.c.map((c: any) => String(c));
        }
    } finally { this.safeDelete(colsVec); }

    return { 
        _source: { layers }, 
        _stack: stack,
        _summary: { 
            num: frameNum, 
            t: Number(this.getVal(summary, 't') || 0), 
            sec: summary.sec,
            usec: summary.usec,
            c: columns 
        } 
    };
  }

  private vectorToArray(vec: any): any[] {
      if (!vec) return [];
      if (Array.isArray(vec)) return vec;
      const arr = [];
      const size = Number(this.call(vec, 'size') || 0);
      for (let i = 0; i < size; i++) arr.push(this.call(vec, 'get', i));
      return arr;
  }

  private addValueToLayer(layer: any, key: string, value: any) {
    if (layer[key] === undefined) { layer[key] = value; } 
    else {
        if (!Array.isArray(layer[key]) || (layer[key].length > 0 && typeof layer[key][0] === 'string')) {
            layer[key] = [layer[key]];
        }
        layer[key].push(value);
    }
  }

  private cleanFilter(filter: string): string {
      if (!filter) return "";
      let cleaned = String(filter);
      if (cleaned.includes(' == ')) cleaned = cleaned.split(' == ')[0];
      if (cleaned.includes(' eq ')) cleaned = cleaned.split(' eq ')[0];
      return cleaned.trim();
  }

  private traverseTreeRecursive(node: any, rootLayers: any, currentLayer: any, stack: any[], packetData: Uint8Array | null, depth: number, state: { count: number }) {
    if (!node || state.count > 5000 || depth > 100) return;
    state.count++;

    const filter = String(this.getVal(node, 'filter') || "");
    const label = String(this.getVal(node, 'label') || "");
    const type = String(this.getVal(node, 'type') || "");
    const start = this.getVal(node, 'start');
    const length = this.getVal(node, 'length');

    const isProto = type === 'proto' && filter;
    let nextLayer = currentLayer;

    if (isProto) {
        const name = this.cleanFilter(filter);
        // Protocol Stack Extraction (PDML-like)
        if (!stack.some(s => s.name === name && s.pos === Number(start || 0))) {
            stack.push({
                name: name,
                pos: Number(start || 0),
                size: Number(length || 0)
            });
        }
        
        // Internal Layer representation
        if (rootLayers[name] === undefined) {
            rootLayers[name] = { '_description': label };
        } else if (typeof rootLayers[name] !== 'object') {
            rootLayers[name] = { '_description': label, '_original_val': rootLayers[name] };
        }
        nextLayer = rootLayers[name];
    } else if (filter || label) {
        const key = this.cleanFilter(filter) || label;
        this.addValueToLayer(currentLayer, key, label);
    }

    // Add raw data reference for the node
    if (start !== undefined && length !== undefined && packetData) {
        const s = Number(start); const l = Number(length);
        if (s >= 0) {
            const actualLen = Math.min(l, packetData.length - s);
            if (actualLen > 0) {
                const slice = packetData.slice(s, s + actualLen);
                const hex = Array.from(slice).map(b => b.toString(16).padStart(2, '0')).join('');
                const rawKey = (isProto ? this.cleanFilter(filter) : (this.cleanFilter(filter) || label)) + '_raw';
                // Always put protocol raw at root for DissectionEngine
                const target = isProto ? rootLayers : currentLayer;
                if (!target[rawKey]) target[rawKey] = [hex, s, actualLen, 0, 1];
            }
        }
    }

    const treeVec = this.getVal(node, 'tree') || this.getVal(node, 'n') || this.getVal(node, 'nodes');
    if (treeVec) {
        const size = Number(this.call(treeVec, 'size') || 0);
        for (let i = 0; i < size; i++) {
            const child = this.call(treeVec, 'get', i);
            this.traverseTreeRecursive(child, rootLayers, nextLayer, stack, packetData, depth + 1, state);
            this.safeDelete(child);
        }
    }
  }
}
