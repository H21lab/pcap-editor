export class PcapWriter {
  chunks: Uint8Array[] = [];
  private networkType: number;

  constructor(networkType: number = 1) {
    this.networkType = networkType;
    this.writeGlobalHeader();
  }

  private writeGlobalHeader() {
    const buffer = new ArrayBuffer(24);
    const view = new DataView(buffer);

    view.setUint32(0, 0xa1b2c3d4, true); 
    view.setUint16(4, 2, true);
    view.setUint16(6, 4, true);
    view.setInt32(8, 0, true);
    view.setUint32(12, 0, true);
    view.setUint32(16, 65535, true);
    view.setUint32(20, this.networkType, true);

    this.chunks.push(new Uint8Array(buffer));
  }

  writePacket(hexData: string, timestamp?: number) {
    let cleanHex = hexData.replace(/[^0-9a-fA-F]/g, '');
    if (cleanHex.length % 2 !== 0) {
      console.warn("Attempting to write packet with odd-length hex string. Padding with zero.");
      cleanHex += '0';
    }
    const len = cleanHex.length / 2;
    const buffer = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      buffer[i] = parseInt(cleanHex.substring(i * 2, i * 2 + 2), 16);
    }
    
    if (timestamp !== undefined) {
      const sec = Math.floor(timestamp);
      const usec = Math.round((timestamp - sec) * 1000000);
      this.writeRawPacketWithIntegers(buffer, sec, usec);
    } else {
      this.writeRawPacket(buffer);
    }
  }

  writeRawPacket(data: Uint8Array, timestamp?: number) {
    let sec = 0;
    let usec = 0;

    if (timestamp !== undefined) {
        sec = Math.floor(timestamp);
        usec = Math.round((timestamp - sec) * 1000000);
    } else {
        const now = Date.now();
        sec = Math.floor(now / 1000);
        usec = (now % 1000) * 1000;
    }
    this.writeRawPacketWithIntegers(data, sec, usec);
  }

  writeRawPacketWithIntegers(data: Uint8Array, sec: number, usec: number) {
    const headerBuf = new ArrayBuffer(16);
    const view = new DataView(headerBuf);

    view.setUint32(0, sec, true);
    view.setUint32(4, usec, true);
    view.setUint32(8, data.length, true);
    view.setUint32(12, data.length, true);

    this.chunks.push(new Uint8Array(headerBuf));
    this.chunks.push(new Uint8Array(data));
  }

  getUint8Array(): Uint8Array {
    const totalLength = this.chunks.reduce((acc, chunk) => acc + chunk.length, 0);
    const result = new Uint8Array(totalLength);
    let offset = 0;
    for (const chunk of this.chunks) {
      result.set(chunk, offset);
      offset += chunk.length;
    }
    return result;
  }

  getBlob(): Blob {
    return new Blob(this.chunks, { type: 'application/vnd.tcpdump.pcap' });
  }
}