export interface PcapPacket {
  header: {
    ts_sec: number;
    ts_usec: number;
    incl_len: number;
    orig_len: number;
  };
  offset: number; 
}

export class PcapParser {
  private buffer: ArrayBuffer;
  private view: DataView;
  private offset: number = 0;
  private littleEndian: boolean = true;
  private networkType: number = 1; // Default to Ethernet
  private isPcapNg: boolean = false;

  constructor(buffer: ArrayBuffer) {
    this.buffer = buffer;
    this.view = new DataView(buffer);
    this.detectFormat();
  }

  private detectFormat() {
    if (this.view.byteLength < 24) return;
    const magic = this.view.getUint32(0, true);
    if (magic === 0xa1b2c3d4) {
      this.littleEndian = true;
      this.isPcapNg = false;
      this.networkType = this.view.getUint32(20, true);
    } else if (magic === 0xd4c3b2a1) {
      this.littleEndian = false;
      this.isPcapNg = false;
      this.networkType = this.view.getUint32(20, false);
    } else if (magic === 0x0a0d0d0a) {
      this.isPcapNg = true;
      // PCAPNG magic is symmetric, but BOM at offset 8 tells us the endianness
      if (this.view.byteLength >= 12) {
        const bom = this.view.getUint32(8, true);
        if (bom === 0x1a2b3c4d) {
          this.littleEndian = true;
        } else if (bom === 0x4d3c2b1a) {
          this.littleEndian = false;
        }
      }
    }
  }

  getNetworkType(): number {
    return this.networkType;
  }

  parse(): PcapPacket[] {
    if (this.isPcapNg) return this.parsePcapNg();
    return this.parseClassicPcap();
  }

  private parseClassicPcap(): PcapPacket[] {
    this.offset = 24; 
    const packets: PcapPacket[] = [];
    while (this.offset < this.view.byteLength) {
      if (this.offset + 16 > this.view.byteLength) break;
      const ts_sec = this.view.getUint32(this.offset, this.littleEndian);
      const ts_usec = this.view.getUint32(this.offset + 4, this.littleEndian);
      const incl_len = this.view.getUint32(this.offset + 8, this.littleEndian);
      const orig_len = this.view.getUint32(this.offset + 12, this.littleEndian);
      this.offset += 16;
      if (this.offset + incl_len > this.view.byteLength) break;
      packets.push({ header: { ts_sec, ts_usec, incl_len, orig_len }, offset: this.offset });
      this.offset += incl_len;
    }
    return packets;
  }

  private parsePcapNg(): PcapPacket[] {
    this.offset = 0;
    const packets: PcapPacket[] = [];
    const interfaces: { linkType: number }[] = [];

    while (this.offset < this.view.byteLength) {
      if (this.offset + 8 > this.view.byteLength) break;
      const blockType = this.view.getUint32(this.offset, this.littleEndian);
      const blockTotalLength = this.view.getUint32(this.offset + 4, this.littleEndian);
      if (blockTotalLength < 12 || this.offset + blockTotalLength > this.view.byteLength) break;

      if (blockType === 0x0a0d0d0a) { // Section Header Block
          const bom = this.view.getUint32(this.offset + 8, true);
          if (bom === 0x1a2b3c4d) this.littleEndian = true;
          else if (bom === 0x4d3c2b1a) this.littleEndian = false;
      } else if (blockType === 0x00000001) { // Interface Description Block
          const linkType = this.view.getUint16(this.offset + 8, this.littleEndian);
          interfaces.push({ linkType });
          if (interfaces.length === 1) this.networkType = linkType;
      } else if (blockType === 0x00000006) { // Enhanced Packet Block
          if (blockTotalLength >= 32) {
              const tsHigh = this.view.getUint32(this.offset + 12, this.littleEndian);
              const tsLow = this.view.getUint32(this.offset + 16, this.littleEndian);
              const inclLen = this.view.getUint32(this.offset + 20, this.littleEndian);
              const origLen = this.view.getUint32(this.offset + 24, this.littleEndian);
              
              // Simplistic timestamp conversion (assuming 10^-6 precision)
              const ts = (BigInt(tsHigh) << 32n) + BigInt(tsLow);
              const ts_sec = Number(ts / 1000000n);
              const ts_usec = Number(ts % 1000000n);

              packets.push({
                  header: { ts_sec, ts_usec, incl_len: inclLen, orig_len: origLen },
                  offset: this.offset + 28
              });
          }
      } else if (blockType === 0x00000003) { // Simple Packet Block
          const origLen = this.view.getUint32(this.offset + 8, this.littleEndian);
          packets.push({
              header: { ts_sec: 0, ts_usec: 0, incl_len: blockTotalLength - 16, orig_len: origLen },
              offset: this.offset + 12
          });
      }

      this.offset += blockTotalLength;
    }
    return packets;
  }

  getPacketData(pkt: PcapPacket): Uint8Array {
      return new Uint8Array(this.buffer, pkt.offset, pkt.header.incl_len);
  }
}
