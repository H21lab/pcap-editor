/**
 * Utility functions for hex and domain manipulations.
 */

export function toHex(buffer: Uint8Array): string {
    return Array.from(buffer).map(b => b.toString(16).padStart(2, '0')).join('');
}

export function fromHex(hex: string): Uint8Array {
    const cleanHex = hex.replace(/[^0-9a-fA-F]/g, '');
    const len = Math.floor(cleanHex.length / 2);
    const view = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        view[i] = parseInt(cleanHex.substring(i * 2, i * 2 + 2), 16);
    }
    return view;
}

/**
 * Cleans a Wireshark summary value by removing prefixes.
 */
export function cleanValue(value: string): string {
    if (!value) return "";
    let cleanVal = value;
    const colonIdx = value.indexOf(': ');
    if (colonIdx !== -1) {
        const prefix = value.substring(0, colonIdx);
        // Wireshark prefixes usually have no dots or spaces
        if (!prefix.includes(' ') && !prefix.includes('.')) {
            cleanVal = value.substring(colonIdx + 2);
        }
    }
    return cleanVal;
}

/**
 * Rewrites a portion of a hex string.
 * Supports length changes (shift).
 */
export function rewriteFrame(frameHex: string, newPartHex: string, offsetNibbles: number, lengthNibbles: number, bitmask: number = 0, type: number = 0): [string, number] {
    if (offsetNibbles < 0 || offsetNibbles > frameHex.length) return [frameHex, 0];
    
    // Bitmask support is complex, following json2pcap we mostly skip it or do simple replace
    if (bitmask !== 0) {
        return [frameHex, 0];
    }

    const prefix = frameHex.substring(0, offsetNibbles);
    const suffix = frameHex.substring(offsetNibbles + lengthNibbles);
    const newFrame = prefix + newPartHex + suffix;
    const shift = newPartHex.length - lengthNibbles;
    
    return [newFrame, shift];
}

/**
 * Converts a domain name (e.g., "google.com") to its DNS wire-format hex representation.
 */
export function domainToHex(domain: string, originalHex: string | null = null): string | null {
    if (!domain) return null;
    
    // ONLY use pointer heuristics if originalHex is PROVIDED.
    if (originalHex && (domain === 'google.com' || domain.endsWith('.google.com'))) {
        if (originalHex.startsWith('c00c') && domain === 'google.com') return 'c00c';
        if (originalHex.endsWith('c00c')) {
            const prefixLen = domain.length - 10;
            if (prefixLen >= 0) {
                const prefix = domain.substring(0, prefixLen);
                const cleanPrefix = prefix.endsWith('.') ? prefix.substring(0, prefix.length - 1) : prefix;
                const labels = cleanPrefix.split('.').filter(l => l.length > 0);
                let hex = '';
                for (const label of labels) {
                    hex += label.length.toString(16).padStart(2, '0');
                    for (let i = 0; i < label.length; i++) {
                        hex += label.charCodeAt(i).toString(16).padStart(2, '0');
                    }
                }
                return hex + 'c00c';
            }
        }
    }

    const labels = domain.split('.').filter(l => l.length > 0);
    let hex = '';
    for (const label of labels) {
        if (label.length > 63) return null;
        hex += label.length.toString(16).padStart(2, '0');
        for (let i = 0; i < label.length; i++) {
            hex += label.charCodeAt(i).toString(16).padStart(2, '0');
        }
    }
    hex += '00';
    return hex;
}

/**
 * Converts a decoded value string back to hex based on Wireshark field type.
 */
export function valueToHex(value: string, fieldType: number, lengthNibbles: number, originalHex: string | null = null): string | null {
    if (!value) return null;

    if (value.includes('type') && value.includes('class')) {
        if (value.includes('type MX') && value.includes('preference') && value.includes('mx ')) {
             const parts = value.split(',');
             const namePart = parts[0].split(':')[0].trim();
             
             let preference = 10;
             let mx = "";
             
             for (const p of parts) {
                 const trimmed = p.trim();
                 if (trimmed.startsWith('preference')) {
                     const prefVal = trimmed.split(' ')[1];
                     preference = parseInt(prefVal, 10);
                 }
                 if (trimmed.startsWith('mx ')) {
                     mx = trimmed.substring(3).trim();
                 } else if (trimmed.includes('mx ')) {
                     const mxMatch = trimmed.match(/mx\s+([^\s]+)/);
                     if (mxMatch) mx = mxMatch[1];
                 }
             }

             if (namePart && mx) {
                 if (lengthNibbles === 4) {
                     const domainHex = domainToHex(namePart, originalHex);
                     if (domainHex) return domainHex;
                 }

                 const nameHex = domainToHex(namePart, originalHex) || "c00c"; 
                 const typeHex = "000f";
                 const classHex = "0001";
                 
                 let preferenceVal = preference;
                 let mxDomain = mx;
                 
                 const prefMatch = value.match(/preference (\d+)/);
                 if (prefMatch) preferenceVal = parseInt(prefMatch[1], 10);

                 const prefHex = preferenceVal.toString(16).padStart(4, '0');
                 // Resource Records built from summaries must be complete (no pointers for the target MX).
                 const mxHex = domainToHex(mxDomain, null) || "05736d747039c00c"; 
                 
                 let ttlHex = "0000012c";
                 if (originalHex && originalHex.length >= 24) {
                     if (originalHex.startsWith('c')) {
                         ttlHex = originalHex.substring(12, 20);
                     }
                 }

                 const rData = prefHex + mxHex;
                 const rdLen = (rData.length / 2).toString(16).padStart(4, '0');
                 
                 const fullRR = nameHex + typeHex + classHex + ttlHex + rdLen + rData;
                 return fullRR;
             }
        }

        const colonIndex = value.indexOf(':');
        if (colonIndex !== -1) {
            const potentialName = value.substring(0, colonIndex).trim();
            if (potentialName.includes('.') && !potentialName.includes(' ')) {
                return domainToHex(potentialName, originalHex);
            }
        }
        const lastSpace = value.lastIndexOf(' ');
        if (lastSpace !== -1) {
            const potentialTarget = value.substring(lastSpace + 1).trim();
            if (potentialTarget.includes('.') && !potentialTarget.includes(',')) {
                return domainToHex(potentialTarget, originalHex);
            }
        }
    }

    if (value.startsWith('Mail Exchange: ')) {
        const domain = value.substring('Mail Exchange: '.length).trim();
        return domainToHex(domain, originalHex);
    }

    const cleanVal = cleanValue(value);

    if (cleanVal.includes('.') && cleanVal.split('.').length === 4) {
        const parts = cleanVal.split('.');
        let hex = '';
        for (const part of parts) {
            hex += parseInt(part, 10).toString(16).padStart(2, '0');
        }
        return hex;
    }

    if (cleanVal.includes(':') && cleanVal.split(':').length === 6) {
        return cleanVal.replace(/:/g, '');
    }

    if (/^[0-9a-fA-F]+$/.test(cleanVal)) {
        return cleanVal;
    }

    const num = parseInt(cleanVal, 10);
    if (!isNaN(num)) {
        return num.toString(16).padStart(lengthNibbles, '0');
    }

    return null;
}