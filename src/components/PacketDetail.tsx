import React, { useState, useMemo, useEffect, useRef, memo, useCallback } from 'react';
import { Box, Typography, Button, IconButton, Tooltip } from '@mui/material';
import { Panel, Group as PanelGroup, Separator as PanelResizeHandle } from "react-resizable-panels";
import { Virtuoso, VirtuosoHandle } from 'react-virtuoso';
import SaveIcon from '@mui/icons-material/Save';
import AddIcon from '@mui/icons-material/Add';
import DeleteIcon from '@mui/icons-material/Delete';
import RestartAltIcon from '@mui/icons-material/RestartAlt';
import { ScapyPacketEditor } from './ScapyPacketEditor';
import { FormControlLabel, Switch, CircularProgress, Alert } from '@mui/material';
import { scapyService } from '../core/scapyService';

interface PacketDetailProps {
  packet: any;
  packetIndex: number;
  onReplacePacket: (packetIndex: number, newHex: string) => void;
}

interface HighlightInfo {
    start: number;
    len: number;
    label: string;
}

const HexRow = memo(({ 
    index, 
    bytes, 
    highlightRange, 
    selectedByte, 
    editBuffer, 
    onByteClick,
    onAppendByte
}: { 
    index: number, 
    bytes: string[],
    highlightRange: { start: number, len: number } | null,
    selectedByte: number | null,
    editBuffer: string,
    onByteClick: (index: number) => void,
    onAppendByte: () => void
}) => {
    const startIdx = index * 16;
    
    const isHighlighted = (idx: number) => {
        if (!highlightRange) return false;
        return idx >= highlightRange.start && idx < highlightRange.start + highlightRange.len;
    };

    return (
        <div style={{ display: 'flex', alignItems: 'center', fontSize: '0.85rem', whiteSpace: 'nowrap', height: '24px', padding: '0 8px' }}>
            <div style={{ color: '#858585', width: '50px', flexShrink: 0, fontFamily: 'monospace' }}>
                {startIdx.toString(16).padStart(4, '0')}
            </div>
            <div style={{ display: 'flex', gap: '4px', marginLeft: '16px' }}>
                {Array.from({ length: 16 }).map((_, byteIdx) => {
                    const globalIdx = startIdx + byteIdx;
                    const byte = bytes[globalIdx];
                    const isExisting = globalIdx < bytes.length;
                    const highlighted = isHighlighted(globalIdx);
                    const isSelected = selectedByte === globalIdx;
                    
                    return (
                        <div 
                            key={byteIdx} 
                            onClick={(e) => { e.stopPropagation(); isExisting ? onByteClick(globalIdx) : onByteClick(-1); }}
                            onDoubleClick={(e) => { e.stopPropagation(); if (!isExisting) onAppendByte(); }}
                            style={{ 
                                width: '24px', textAlign: 'center', cursor: isExisting ? 'pointer' : 'default', borderRadius: '2px',
                                fontFamily: 'monospace',
                                backgroundColor: isSelected ? '#f1c40f' : (highlighted ? '#264f78' : 'transparent'),
                                color: isSelected ? '#000' : (highlighted ? '#ffffff' : (isExisting ? 'inherit' : '#444')),
                                border: isSelected ? '1px solid white' : 'none',
                                boxSizing: 'border-box'
                            }}
                        >
                            {isExisting ? ((isSelected && editBuffer) ? (editBuffer.padEnd(2, '_')) : byte) : '..'}
                        </div>
                    );
                })}
            </div>
            <div style={{ color: '#ce9178', marginLeft: '24px', display: 'flex', fontFamily: 'monospace' }}>
                {Array.from({ length: 16 }).map((_, byteIdx) => {
                    const globalIdx = startIdx + byteIdx;
                    const byte = bytes[globalIdx];
                    const isExisting = globalIdx < bytes.length;
                    const char = isExisting ? parseInt(byte, 16) : 0;
                    const displayChar = isExisting ? ((char >= 32 && char <= 126) ? String.fromCharCode(char) : '.') : ' ';
                    const highlighted = isHighlighted(globalIdx);
                    const isSelected = selectedByte === globalIdx;
                    return (
                        <span 
                            key={byteIdx} 
                            style={{ 
                                backgroundColor: isSelected ? '#f1c40f' : (highlighted ? '#264f78' : 'transparent'), 
                                color: isSelected ? '#000' : (highlighted ? '#ffffff' : 'inherit'),
                                width: '9px',
                                textAlign: 'center'
                            }}
                        >
                            {displayChar}
                        </span>
                    );
                })}
            </div>
        </div>
    );
});

const HexViewer = memo(({ 
    hex, 
    highlightRange, 
    onByteClick,
    onHexChange,
    selectedByte,
    setSelectedByte
}: { 
    hex: string, 
    highlightRange: { start: number, len: number } | null,
    onByteClick: (index: number) => void,
    onHexChange: (newHex: string) => void,
    selectedByte: number | null,
    setSelectedByte: (index: number | null) => void
}) => {
    const [editBuffer, setEditValue] = useState("");
    const virtuosoRef = useRef<VirtuosoHandle>(null);

    const bytes = useMemo(() => {
        const b = [];
        for (let i = 0; i < hex.length; i += 2) {
            b.push(hex.substring(i, i + 2));
        }
        return b;
    }, [hex]);

    const handleInsertByte = useCallback((atPos?: number) => {
        const pos = atPos !== undefined ? atPos : (selectedByte !== null ? selectedByte : bytes.length);
        const newHex = hex.substring(0, pos * 2) + "00" + hex.substring(pos * 2);
        onHexChange(newHex);
        setSelectedByte(pos);
        setEditValue("");
    }, [hex, selectedByte, bytes.length, onHexChange, setSelectedByte]);

    const handleDeleteByte = useCallback(() => {
        if (selectedByte === null || selectedByte >= bytes.length) return;
        const newHex = hex.substring(0, selectedByte * 2) + hex.substring(selectedByte * 2 + 2);
        onHexChange(newHex);
        if (selectedByte >= Math.floor(newHex.length / 2)) {
            setSelectedByte(Math.max(0, Math.floor(newHex.length / 2) - 1));
        }
        setEditValue("");
    }, [hex, selectedByte, bytes.length, onHexChange, setSelectedByte]);

    const handleKeyDown = (e: React.KeyboardEvent) => {
        if (selectedByte === null) return;

        if (e.key === 'Escape' || e.key === 'Enter') {
            setEditValue("");
        } else if (e.key === 'Delete' || e.key === 'Backspace') {
            handleDeleteByte();
        } else if (e.key === 'Insert') {
            handleInsertByte();
        } else if (/^[0-9a-fA-F]$/i.test(e.key)) {
            const newVal = (editBuffer + e.key).toLowerCase();
            if (newVal.length === 2) {
                const newHex = hex.substring(0, selectedByte * 2) + newVal + hex.substring(selectedByte * 2 + 2);
                onHexChange(newHex);
                setEditValue("");
                if (selectedByte < bytes.length - 1) {
                    setSelectedByte(selectedByte + 1);
                }
            } else {
                setEditValue(newVal);
            }
        }
    };

    useEffect(() => {
        if (highlightRange && virtuosoRef.current) {
            const row = Math.floor(highlightRange.start / 16);
            virtuosoRef.current.scrollToIndex({ index: row, align: 'center', behavior: 'smooth' });
        }
    }, [highlightRange]);

    const rowCount = Math.max(1, Math.ceil((bytes.length + 1) / 16));

    return (
        <Box 
            sx={{ 
                bgcolor: '#1e1e1e', color: '#d4d4d4', 
                height: '100%', outline: 'none',
                display: 'flex', flexDirection: 'column'
            }}
            onKeyDown={handleKeyDown}
            onDoubleClick={(e) => { if (e.target === e.currentTarget) handleInsertByte(bytes.length); }}
            tabIndex={0}
        >
            <Box sx={{ p: 0.5, bgcolor: '#333', borderBottom: '1px solid #444', display: 'flex', gap: 1, flexShrink: 0 }}>
                <Tooltip title="Insert Byte (00) at selection [Insert]">
                    <IconButton size="small" sx={{ color: '#aaa' }} onClick={() => handleInsertByte()}>
                        <AddIcon fontSize="small" />
                    </IconButton>
                </Tooltip>
                <Tooltip title="Delete selected byte [Del/Backspace]">
                    <span>
                        <IconButton
                            size="small"
                            sx={{ color: '#aaa' }}
                            disabled={selectedByte === null || selectedByte >= bytes.length}
                            onClick={handleDeleteByte}
                        >
                            <DeleteIcon fontSize="small" />
                        </IconButton>
                    </span>
                </Tooltip>
                <Box sx={{ flex: 1 }} />
                <Typography variant="caption" sx={{ color: '#666', mr: 1, alignSelf: 'center' }}>
                    {bytes.length} bytes
                </Typography>
            </Box>
            <Box sx={{ flex: 1, minHeight: 0 }}>
                <Virtuoso
                    ref={virtuosoRef}
                    style={{ height: '100%' }}
                    totalCount={rowCount}
                    itemContent={(index) => (
                        <HexRow 
                            index={index} 
                            bytes={bytes}
                            highlightRange={highlightRange}
                            selectedByte={selectedByte}
                            editBuffer={editBuffer}
                            onByteClick={(idx) => { 
                                if (idx === -1) setSelectedByte(null);
                                else { onByteClick(idx); setSelectedByte(idx); }
                                setEditValue(""); 
                            }}
                            onAppendByte={() => handleInsertByte(bytes.length)}
                        />
                    )}
                />
            </Box>
        </Box>
    );
});

const DetailNode = memo(({ 
    label, value, level, parent, onHighlight, highlightedRange, activePath, rawDataOverride
}: { 
    label: string, value: any, level: number, parent: any,
    onHighlight: (range: { start: number, len: number } | null, path: string) => void,
    highlightedRange: { start: number, len: number } | null,
    activePath: string | null,
    rawDataOverride?: any
}) => {
    const nodeRef = useRef<HTMLDivElement>(null);
    const isObject = typeof value === 'object' && value !== null && !Array.isArray(value);
    
    const rawDataRaw = rawDataOverride || (parent ? parent[label + '_raw'] : null);
    const hasMultipleRaw = Array.isArray(rawDataRaw) && rawDataRaw.length > 0 && Array.isArray(rawDataRaw[0]);
    const rawData = hasMultipleRaw ? null : rawDataRaw;
    const hasOffset = Array.isArray(rawData) && rawData.length >= 3;
    
    const isActive = activePath === label;
    const isRangeMatched = highlightedRange && hasOffset && 
                           highlightedRange.start === rawData[1] && 
                           highlightedRange.len === rawData[2];

    useEffect(() => {
        if (isActive && nodeRef.current) {
            nodeRef.current.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        }
    }, [isActive]);

    if (label.endsWith('_raw')) return null;

    if (Array.isArray(value) && !hasOffset && !hasMultipleRaw) {
        return (
            <div style={{ display: 'flex', flexDirection: 'column' }}>
                {value.map((v, i) => (
                    <DetailNode 
                        key={`${label}-${i}`} label={`${label}[${i}]`} value={v} level={level} parent={parent}
                        onHighlight={onHighlight} highlightedRange={highlightedRange}
                        activePath={activePath}
                        rawDataOverride={Array.isArray(rawDataRaw) ? rawDataRaw[i] : null}
                    />
                ))}
            </div>
        );
    }

    // Clean up label: if value starts with something that looks like the label, strip it
    const displayValue = String(value);
    let finalValue = displayValue;
    
    if (!isObject) {
        const colonIdx = displayValue.indexOf(':');
        if (colonIdx > 0 && colonIdx < 40) {
            const prefix = displayValue.substring(0, colonIdx).trim();
            // Match if prefix is the same as label, or is the part of the filter after the last dot
            if (prefix.toLowerCase() === label.toLowerCase() || 
                label.toLowerCase().endsWith('.' + prefix.toLowerCase())) {
                finalValue = displayValue.substring(colonIdx + 1).trim();
            }
        }
    }

    if (Array.isArray(value)) {
        return (
            <div style={{ display: 'flex', flexDirection: 'column' }}>
                {value.map((v, i) => (
                    <DetailNode 
                        key={`${label}-${i}`} label={`${label}[${i}]`} value={v} level={level} parent={parent}
                        onHighlight={onHighlight} highlightedRange={highlightedRange}
                        activePath={activePath}
                        rawDataOverride={Array.isArray(rawDataRaw) && Array.isArray(rawDataRaw[0]) ? rawDataRaw[i] : (hasOffset ? rawData : null)}
                    />
                ))}
            </div>
        );
    }

    return (
        <div 
            ref={nodeRef}
            style={{ 
                marginLeft: level * 16, borderLeft: level > 0 ? '1px solid #eee' : 'none', 
                paddingLeft: level > 0 ? 8 : 0, cursor: hasOffset ? 'pointer' : 'default',
                backgroundColor: isRangeMatched ? '#fff9c4' : 'transparent',
                display: 'flex',
                flexDirection: 'column',
                color: isRangeMatched ? '#d32f2f' : (hasOffset ? '#1976d2' : '#333')
            }}
            onClick={(e) => {
                e.stopPropagation();
                if (hasOffset) onHighlight({ start: rawData[1], len: rawData[2] }, label);
            }}
        >
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, height: '20px' }}>
                <div style={{ 
                    fontFamily: 'monospace', fontSize: '0.85rem', display: 'flex', gap: 4,
                    fontWeight: (hasOffset || isRangeMatched) ? 'bold' : 'normal', 
                    textDecoration: isActive ? 'underline' : 'none'
                }}>
                    <span style={{ color: 'inherit' }}>{label}</span>
                    {(!isObject) && (
                        <span style={{ color: hasOffset ? 'inherit' : '#666', fontWeight: 'normal' }}>: {finalValue}</span>
                    )}
                </div>
            </div>
            
            {isObject && (
                <div>
                    {Object.entries(value).map(([k, v]) => (
                        <DetailNode 
                            key={k} label={k} value={v} level={level + 1} parent={value}
                            onHighlight={onHighlight} highlightedRange={highlightedRange}
                            activePath={activePath}
                        />
                    ))}
                </div>
            )}
        </div>
    );
});

export const PacketDetail: React.FC<PacketDetailProps> = ({ packet, packetIndex, onReplacePacket }) => {
  const [isScapyEditing, setIsScapyEditing] = useState(false);
  const [highlightedRange, setHighlightedRange] = useState<{ start: number, len: number } | null>(null);
  const [activePath, setActivePath] = useState<string | null>(null);
  const [scapyScript, setScapyScript] = useState("");
  const [scapyError, setScapyError] = useState<string | null>(null);
  const [isApplying, setIsApplying] = useState(false);
  
  const layers = useMemo(() => packet._source?.layers || {}, [packet]);
  const rawFrameData = layers['frame_raw'];
  const packetHex = rawFrameData ? rawFrameData[0] : "";

  const [localHex, setLocalHex] = useState(packetHex);
  const [selectedByte, setSelectedByte] = useState<number | null>(null);

  // Sync localHex when packet prop changes (e.g. after save) or index changes
  useEffect(() => { 
      setLocalHex(packetHex); 
      setSelectedByte(null);
  }, [packetIndex, packetHex]);

  const findFieldAtOffset = useCallback((offset: number) => {
      let found: HighlightInfo | null = null;
      const traverse = (obj: any) => {
          for (const [key, value] of Object.entries(obj)) {
              if (key.endsWith('_raw')) {
                  const items = Array.isArray(value) && Array.isArray(value[0]) ? value : [value];
                  for (const raw of items) {
                      if (Array.isArray(raw) && raw.length >= 3) {
                          const start = raw[1]; const len = raw[2];
                          if (offset >= start && offset < start + len) {
                              if (!found || len <= found.len) {
                                  found = { start, len, label: key.replace('_raw', '') };
                              }
                          }
                      }
                  }
              }
              if (typeof value === 'object' && value !== null && !Array.isArray(value)) traverse(value);
          }
      };
      traverse(layers);
      const target = found as HighlightInfo | null;
      if (target) { 
          setHighlightedRange({ start: target.start, len: target.len }); 
          setActivePath(target.label); 
      }
  }, [layers]);

  const handleApplyChanges = () => {
      onReplacePacket(packetIndex, localHex);
  };

  const handleApplyScapyChanges = async () => {
      setIsApplying(true);
      setScapyError(null);
      try {
          const newHex = await scapyService.runScript(packetHex, scapyScript, wsInfo);
          onReplacePacket(packetIndex, newHex);
          setIsScapyEditing(false);
      } catch (e: any) {
          setScapyError(e.message);
      } finally {
          setIsApplying(false);
      }
  };

  const wsInfo = useMemo(() => {
      // Use the _stack provided by WiregasmDissector which mirrors top-level PDML protos
      return packet._stack || [];
  }, [packet._stack]);

  const handleScapyScriptChange = useCallback((script: string) => {
      setScapyScript(script);
  }, []);

  const handleScapyError = useCallback((error: string | null) => {
      setScapyError(error);
  }, []);

  const hasChanges = localHex !== packetHex;

  return (
    <Box sx={{ height: '100%', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
        <Box sx={{ p: 1, borderBottom: '1px solid #ddd', display: 'flex', justifyContent: 'space-between', alignItems: 'center', bgcolor: 'white', flexShrink: 0 }}>
            <Box sx={{ display: 'flex', gap: 1, alignItems: 'center' }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 'bold' }}>Packet #{(packetIndex + 1)}</Typography>
                {!isScapyEditing && hasChanges && (
                    <Button size="small" variant="contained" color="success" startIcon={<SaveIcon />} onClick={handleApplyChanges}>
                        Apply Changes
                    </Button>
                )}
                {!isScapyEditing && hasChanges && (
                    <Button size="small" variant="outlined" color="error" startIcon={<RestartAltIcon />} onClick={() => setLocalHex(packetHex)}>
                        Reset
                    </Button>
                )}
                {isScapyEditing && (
                    <Button 
                        size="small" 
                        variant="contained" 
                        color="primary" 
                        onClick={handleApplyScapyChanges}
                        disabled={isApplying}
                        startIcon={isApplying ? <CircularProgress size={14} color="inherit" /> : <SaveIcon />}
                    >
                        Apply Script
                    </Button>
                )}
                {isScapyEditing && (
                    <Button size="small" variant="outlined" onClick={() => setIsScapyEditing(false)} disabled={isApplying}>
                        Cancel
                    </Button>
                )}
            </Box>
            <FormControlLabel 
                control={<Switch size="small" checked={isScapyEditing} onChange={e => setIsScapyEditing(e.target.checked)} />} 
                label="Python Editor" 
            />
        </Box>

        {scapyError && isScapyEditing && <Alert severity="error" sx={{ py: 0 }}>{scapyError}</Alert>}

        <Box sx={{ flex: 1, minHeight: 0 }}>
            {isScapyEditing ? (
                <ScapyPacketEditor 
                    packetHex={packetHex} 
                    wsInfo={wsInfo}
                    onScriptChange={handleScapyScriptChange}
                    onError={handleScapyError}
                />
            ) : (
                <PanelGroup orientation="horizontal" style={{ height: '100%' }}>
                    <Panel defaultSize={60} minSize={30}>
                        <Box sx={{ height: '100%', overflow: 'auto', p: 2, bgcolor: 'white', display: 'flex', flexDirection: 'column' }}>
                            <div style={{ flex: 1, paddingBottom: '200px' }}> 
                                {Object.entries(layers).map(([key, value]) => (
                                    <DetailNode 
                                        key={key} label={key} value={value} level={0} parent={layers}
                                        onHighlight={(range, path) => { setHighlightedRange(range); setActivePath(path); }}
                                        highlightedRange={highlightedRange} activePath={activePath}
                                    />
                                ))}
                            </div>
                        </Box>
                    </Panel>

                    <PanelResizeHandle style={{ width: '8px', cursor: 'col-resize', backgroundColor: '#ddd', border: '1px solid #ccc' }} />

                    <Panel defaultSize={40} minSize={20}>
                        <HexViewer 
                            hex={localHex} 
                            highlightRange={highlightedRange} 
                            onByteClick={findFieldAtOffset}
                            onHexChange={setLocalHex}
                            selectedByte={selectedByte}
                            setSelectedByte={setSelectedByte}
                        />
                    </Panel>
                </PanelGroup>
            )}
        </Box>
    </Box>
  );
};