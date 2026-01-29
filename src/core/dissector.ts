import { PcapParser } from '../utils/pcapParser';
import { SimpleDissector } from './simpleDissector';
import { WiregasmDissector } from './wiregasmDissector';

export class WasmDissector {
  private wiregasm = new WiregasmDissector();
  private isFileLoaded: boolean = false;

  private isFallback: boolean = false;
  private fallbackPackets: any[] = [];
  private fallbackParser: PcapParser | null = null;
  private cachedPcapPackets: any[] | null = null;

  private async ensureDecompressed(file: File): Promise<Uint8Array> {
    const buffer = await file.arrayBuffer();
    const arr = new Uint8Array(buffer);
    if (arr.length > 2 && arr[0] === 0x1f && arr[1] === 0x8b) {
        try {
            const ds = new (window as any).DecompressionStream('gzip');
            const decompressedStream = file.stream().pipeThrough(ds);
            const decompressedBuffer = await new Response(decompressedStream).arrayBuffer();
            return new Uint8Array(decompressedBuffer);
        } catch (e) {
            console.warn("Native decompression failed, using raw buffer:", e);
        }
    }
    return arr;
  }

  async dissect(file: File, filter: string = ""): Promise<any[]> {
    this.isFileLoaded = false;
    this.isFallback = false;
    this.cachedPcapPackets = null;

    const data = await this.ensureDecompressed(file);
    
    // Try Wiregasm first
    try {
        const packets = await this.wiregasm.dissect(data, file.name, filter);
        this.isFileLoaded = true;
        return packets;
    } catch (e) {
        console.warn("Wiregasm failed, falling back to simple JS dissector:", e);
    }

    // Fallback to Simple JS Dissector
    try {
        this.fallbackParser = new PcapParser(data.buffer);
        this.cachedPcapPackets = this.fallbackParser.parse();
        const dissector = new SimpleDissector();
        const result = dissector.dissect(this.cachedPcapPackets, this.fallbackParser);
        this.fallbackPackets = result;
        this.isFileLoaded = true;
        this.isFallback = true;
        return result;
    } catch (e: any) {
        throw new Error("Failed to parse PCAP (Simple): " + e.message);
    }
  }

  async getFrames(filter: string): Promise<any[]> {
      if (!this.isFileLoaded) return [];
      if (this.isFallback) return this.fallbackPackets;
      return this.wiregasm.getFrames(filter);
  }

  async reDissect(filter: string): Promise<any[]> {
      if (!this.isFileLoaded) return [];
      if (this.isFallback) return this.fallbackPackets;
      return this.wiregasm.getFrames(filter);
  }

  async getPacketFull(originalPacket: any, packetIndex: number): Promise<any> {
      if (this.isFallback) return this.fallbackPackets[packetIndex];
      return this.wiregasm.getPacketFull(originalPacket, packetIndex);
  }

  async getRawHex(packetIndex: number): Promise<string> {
      const bytes = await this.getRawBytes(packetIndex);
      return bytes ? Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('') : "";
  }

  async getRawBytes(packetIndex: number): Promise<Uint8Array | null> {
      if (this.isFallback && this.fallbackParser) {
          if (!this.cachedPcapPackets) this.cachedPcapPackets = this.fallbackParser.parse();
          if (this.cachedPcapPackets[packetIndex]) {
              return this.fallbackParser.getPacketData(this.cachedPcapPackets[packetIndex]);
          }
          return null;
      }
      return this.wiregasm.getRawBytes(packetIndex);
  }

  getNetworkType(): number {
      if (this.isFallback && this.fallbackParser) return this.fallbackParser.getNetworkType();
      return this.wiregasm.getNetworkType();
  }

  async updateSession(pcapBuffer: Uint8Array): Promise<void> {
      if (this.isFallback) {
          this.fallbackParser = new PcapParser(pcapBuffer.buffer);
          this.cachedPcapPackets = this.fallbackParser.parse();
          const dissector = new SimpleDissector();
          this.fallbackPackets = dissector.dissect(this.cachedPcapPackets, this.fallbackParser);
          return;
      }
      return this.wiregasm.updateSession(pcapBuffer);
  }

  async dissectSinglePacket(hex: string, originalPacket: any): Promise<any> {
      if (this.isFallback) {
          // Simple mock for single packet dissection in fallback
          const origSummary = originalPacket?._summary || {};
          return {
              _source: { layers: { frame_raw: [hex] } },
              _summary: { 
                  ...origSummary,
                  num: origSummary.num,
                  sec: origSummary.sec,
                  usec: origSummary.usec
              }
          };
      }
      return this.wiregasm.dissectSinglePacket(hex, originalPacket);
  }
}