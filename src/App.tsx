import React, { useState, useCallback, memo } from 'react';
import {
  AppBar, Toolbar, Typography, Paper, Box, Button,
  CircularProgress, IconButton, Snackbar, Alert, InputBase, Divider
} from '@mui/material';
import DownloadIcon from '@mui/icons-material/Download';
import CloudUploadIcon from '@mui/icons-material/CloudUpload';
import FilterListIcon from '@mui/icons-material/FilterList';
import ClearIcon from '@mui/icons-material/Clear';
import { Panel, Group as PanelGroup, Separator as PanelResizeHandle } from "react-resizable-panels";
import { WasmDissector } from './core/dissector';
import { PacketList } from './components/PacketList';
import { PacketDetail } from './components/PacketDetail';
import { PcapWriter } from './utils/pcapWriter';
import { fromHex } from './utils/hexUtils';
import packageJson from '../package.json';

const dissector = new WasmDissector();
const MemoizedPacketList = memo(PacketList);

function App() {
  const [allPackets, setAllPackets] = useState<any[]>([]); 
  const [packets, setPackets] = useState<any[]>([]);       
  const [loading, setLoading] = useState(false);
  const [fileLoaded, setFileLoaded] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedPacketIndex, setSelectedPacketIndex] = useState<number>(0);
  const [detailsLoading, setDetailsLoading] = useState(false);
  const [filterInput, setFilterInput] = useState('');
  const [filterStatus, setFilterStatus] = useState<'idle' | 'valid' | 'invalid'>('idle');

  const handleSelectPacket = useCallback(async (index: number) => {
      setSelectedPacketIndex(index);
      const originalPacket = packets[index];
      if (originalPacket?._incomplete) {
          setDetailsLoading(true);
          try {
              const fullPacket = await dissector.getPacketFull(originalPacket, index);
              setPackets(prev => {
                  const next = [...prev];
                  next[index] = fullPacket;
                  return next;
              });
              // Also update master list
              setAllPackets(prev => {
                  const next = [...prev];
                  const masterIdx = fullPacket._summary.num - 1;
                  if (next[masterIdx]) next[masterIdx] = fullPacket;
                  return next;
              });
          } catch (e: any) {
              setError("Failed to load details: " + e.message);
          } finally {
              setDetailsLoading(false);
          }
      }
  }, [packets]);

  const processFile = async (file: File, filter: string = "") => {
    setLoading(true);
    setFileLoaded(false);
    try {
      const data = await dissector.dissect(file, ""); 
      setAllPackets(data);
      if (filter) {
          const filtered = await dissector.getFrames(filter);
          setPackets(filtered);
          setFilterStatus('valid');
      } else {
          setPackets(data);
          setFilterStatus('idle');
      }
      setSelectedPacketIndex(0);
      setFileLoaded(true);
    } catch (err) {
      setError("Failed to parse file: " + String(err));
    } finally {
      setLoading(false);
    }
  };

  const handleApplyFilter = async () => {
    setLoading(true);
    try {
        const data = await dissector.getFrames(filterInput);
        setPackets(data);
        setSelectedPacketIndex(0);
        setFilterStatus(filterInput ? (data.length > 0 ? 'valid' : 'invalid') : 'idle');
    } catch (err) {
        setFilterStatus('invalid');
        setError("Filter error: " + String(err));
    } finally {
        setLoading(false);
    }
  };

  const handleClearFilter = () => {
      setFilterInput('');
      setPackets(allPackets);
      setFilterStatus('idle');
  };

  const handleReplacePacket = useCallback(async (displayedIndex: number, newHex: string) => {
    setLoading(true);
    try {
        const displayedPacket = packets[displayedIndex];

        const newPacketStructure = await dissector.dissectSinglePacket(newHex, displayedPacket);
        const updatedPacket = { ...newPacketStructure, _incomplete: false };

        const masterIdx = updatedPacket._summary.num - 1;
        const nextAllPackets = [...allPackets];
        nextAllPackets[masterIdx] = updatedPacket;

        const writer = new PcapWriter(dissector.getNetworkType());
        for (let i = 0; i < nextAllPackets.length; i++) {
            const p = nextAllPackets[i];
            const hex = p._source?.layers?.frame_raw?.[0];
            const { sec, usec, t: timestamp } = p._summary || {};

            if (hex) {
                if (sec !== undefined && usec !== undefined) {
                    writer.writeRawPacketWithIntegers(fromHex(String(hex)), sec, usec);
                } else {
                    writer.writePacket(String(hex), timestamp);
                }
            } else {
                const bytes = await dissector.getRawBytes(i);
                if (bytes) {
                    if (sec !== undefined && usec !== undefined) {
                        writer.writeRawPacketWithIntegers(bytes, sec, usec);
                    } else {
                        writer.writeRawPacket(bytes, timestamp);
                    }
                } else {
                }
            }
        }
        await dissector.updateSession(writer.getUint8Array());
        
        // Re-fetch all packets to ensure master list is in sync with the new session
        const refreshedAll = await dissector.getFrames("");
        setAllPackets(refreshedAll);

        let nextPackets = refreshedAll;
        if (filterInput) {
            nextPackets = await dissector.getFrames(filterInput);
        }
        setPackets(nextPackets);

        // CRITICAL: Re-fetch full details for the currently selected packet so the UI doesn't show incomplete data
        const updatedSelectedPacket = nextPackets[displayedIndex];
        if (updatedSelectedPacket) {
            setDetailsLoading(true);
            try {
                const fullPacket = await dissector.getPacketFull(updatedSelectedPacket, displayedIndex);
                setPackets(prev => {
                    const next = [...prev];
                    next[displayedIndex] = fullPacket;
                    return next;
                });
            } catch (e) {
                console.error("Failed to re-fetch packet details after update:", e);
            } finally {
                setDetailsLoading(false);
            }
        }
        
        setDetailsLoading(false);
    } catch(e: any) {
        setError("Failed to update packet: " + e.message);
    } finally {
        setLoading(false);
    }
}, [allPackets, packets, filterInput]);

  const handleDownload = async () => {
    if (packets.length === 0) return;
    setLoading(true);
    setError(null);
    try {
        const writer = new PcapWriter(dissector.getNetworkType());
        const totalToExport = packets.length;
        let exportedCount = 0;

        for (let i = 0; i < packets.length; i++) {
            const pkt = packets[i];
            if (!pkt?._summary || isNaN(pkt._summary.num)) {
                console.error(`Packet at display index ${i} missing summary or has NaN num:`, pkt);
                const details = pkt?._summary ? `num=${pkt._summary.num}` : "no summary";
                throw new Error(`Critical Export Error: Packet at display index ${i} has invalid metadata (${details}).`);
            }
            const masterIdx = pkt._summary.num - 1;
            const { sec, usec, t: timestamp } = pkt._summary;

            // Direct fetch of raw bytes from the dissector session
            const bytes = await dissector.getRawBytes(masterIdx);
            if (bytes) {
                if (sec !== undefined && usec !== undefined) {
                    writer.writeRawPacketWithIntegers(bytes, sec, usec);
                } else {
                    writer.writeRawPacket(bytes, timestamp);
                }
                exportedCount++;
            } else {
                // Fallback to hex if bytes fetch fails
                const hexData = pkt._source?.layers?.frame_raw?.[0] || allPackets[masterIdx]?._source?.layers?.frame_raw?.[0];
                if (hexData) {
                    if (sec !== undefined && usec !== undefined) {
                        writer.writeRawPacketWithIntegers(fromHex(String(hexData)), sec, usec);
                    } else {
                        writer.writePacket(String(hexData), timestamp);
                    }
                    exportedCount++;
                } else {
                    throw new Error(`Critical Export Error: Could not find data for packet #${pkt._summary.num} (Index ${masterIdx}). Export aborted to prevent corrupt output.`);
                }
            }
        }
        
        if (exportedCount !== totalToExport) {
            throw new Error(`Export mismatch: Expected ${totalToExport} packets, but only processed ${exportedCount}.`);
        }

        const blob = writer.getBlob();
        if (blob.size <= 24) {
            throw new Error("Generated PCAP is empty or contains no valid packets.");
        }

        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filterInput ? `filtered_${totalToExport}_pkts.pcap` : `edited_${totalToExport}_pkts.pcap`;
        a.style.display = 'none';
        document.body.appendChild(a);
        a.click();
        
        setTimeout(() => {
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        }, 1000); 
    } catch (e: any) {
        console.error("Export failure detail:", e);
        setError(e.message || "Export failed for an unknown reason.");
    } finally {
        setLoading(false);
    }
  };

  return (
    <Box sx={{ height: '100vh', display: 'flex', flexDirection: 'column', bgcolor: '#f5f5f5', overflow: 'hidden' }}>
      <AppBar position="static" sx={{ flexShrink: 0 }}>
        <Toolbar>
            <Typography variant="h6" component="div" sx={{ flexGrow: 1 }}>PCAP Editor</Typography>
            {fileLoaded && (
                <Box sx={{ display: 'flex', gap: 1 }}>
                    <Button color="inherit" startIcon={<ClearIcon />} onClick={() => {
                        setFileLoaded(false);
                        setAllPackets([]);
                        setPackets([]);
                        setSelectedPacketIndex(0);
                        setFilterInput('');
                        setFilterStatus('idle');
                    }}>
                        Close PCAP
                    </Button>
                    <Button color="inherit" startIcon={<DownloadIcon />} onClick={handleDownload} disabled={loading}>
                        Download PCAP
                    </Button>
                </Box>
            )}
        </Toolbar>
      </AppBar>

      <Box sx={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden', p: 2 }}>
        {fileLoaded && (
            <Paper component="form" onSubmit={(e) => { e.preventDefault(); handleApplyFilter(); }} sx={{ p: '2px 4px', display: 'flex', alignItems: 'center', mb: 2, bgcolor: filterStatus === 'invalid' ? '#ffebee' : (filterStatus === 'valid' ? '#e8f5e9' : 'white') }}>
                <FilterListIcon sx={{ p: '10px' }} />
                <InputBase sx={{ ml: 1, flex: 1, fontFamily: 'monospace' }} placeholder="Wireshark filter..." value={filterInput} onChange={(e) => setFilterInput(e.target.value)} />
                {filterInput && <IconButton size="small" onClick={handleClearFilter}><ClearIcon fontSize="small" /></IconButton>}
                <Divider sx={{ height: 28, m: 0.5 }} orientation="vertical" />
                <Button size="small" variant="contained" onClick={handleApplyFilter} disabled={loading} sx={{ mx: 1 }}>Apply</Button>
            </Paper>
        )}

        {!fileLoaded && !loading && (
          <Paper sx={{ p: 6, textAlign: 'center', cursor: 'pointer', border: '2px dashed #ccc', '&:hover': { bgcolor: '#f0f0f0' }, flex: 1, display: 'flex', flexDirection: 'column', justifyContent: 'center', alignItems: 'center' }} onDrop={(e) => { e.preventDefault(); const file = e.dataTransfer.files[0]; if (file) processFile(file); }} onDragOver={e => e.preventDefault()} onClick={() => document.getElementById('file-input')?.click()}>
            <input id="file-input" type="file" style={{ display: 'none' }} onChange={(e) => { if (e.target.files && e.target.files[0]) processFile(e.target.files[0]); }} />
            <CloudUploadIcon sx={{ fontSize: 60, color: '#aaa', mb: 2 }} />
            <Typography variant="h5" color="textSecondary">Drag & Drop PCAP file here or Click to Browse</Typography>
            <Typography variant="body2" color="textSecondary" sx={{ mt: 1 }}>
                (All processing happens locally in your browser memory)
            </Typography>
          </Paper>
        )}

        {loading && !fileLoaded && <Box sx={{ flex: 1, display: 'flex', justifyContent: 'center', alignItems: 'center' }}><CircularProgress /></Box>}

        {fileLoaded && (
          <Box sx={{ flex: 1, minHeight: 0 }}>
            <PanelGroup orientation="vertical" id="main-layout" style={{ height: '100%' }}>
              <Panel defaultSize={40} minSize={20}>
                <MemoizedPacketList packets={packets} selectedIndex={selectedPacketIndex} onSelect={handleSelectPacket} />
              </Panel>
              <PanelResizeHandle style={{ height: '8px', cursor: 'row-resize', backgroundColor: '#ddd', margin: '4px 0', borderRadius: '4px', border: '1px solid #ccc' }} />
              <Panel defaultSize={60} minSize={20}>
                <Box sx={{ height: '100%', overflow: 'hidden', position: 'relative' }}>
                    {detailsLoading && (
                        <Box sx={{ position: 'absolute', top: 0, left: 0, right: 0, bottom: 0, bgcolor: 'rgba(255,255,255,0.7)', zIndex: 10, display: 'flex', justifyContent: 'center', alignItems: 'center' }}>
                            <CircularProgress size={24} />
                        </Box>
                    )}
                    {packets[selectedPacketIndex] && (
                        <PacketDetail 
                            packet={packets[selectedPacketIndex]} 
                            packetIndex={selectedPacketIndex}
                            onReplacePacket={handleReplacePacket}
                        />
                    )}
                </Box>
              </Panel>
            </PanelGroup>
          </Box>
        )}
      </Box>

      <Box component="footer" sx={{ py: 0.5, px: 2, bgcolor: 'white', borderTop: '1px solid #ddd', mt: 'auto', flexShrink: 0, textAlign: 'center' }}>
        <Typography variant="caption" color="textSecondary" sx={{ fontSize: '0.7rem' }}>
          <strong>PCAP Editor v{packageJson.version}</strong> &nbsp; | &nbsp;
          <strong>Privacy:</strong> This application is entirely client-based. Your PCAP files are processed locally and are never uploaded to any server. &nbsp; | &nbsp;
          <strong>Disclaimer:</strong> This software is provided "as is" without warranty of any kind. Review your exported PCAPs carefully. Source code is available under GNU GPLv2 at <a href="https://github.com/H21lab/pcap-editor" target="_blank" rel="noopener noreferrer" style={{color: 'inherit'}}>https://github.com/H21lab/pcap-editor</a>. &nbsp; | &nbsp;
          Copyright H21 lab.
        </Typography>
      </Box>

      <Snackbar open={!!error} autoHideDuration={6000} onClose={() => setError(null)}><Alert severity="error">{error}</Alert></Snackbar>
    </Box>
  );
}

export default App;
