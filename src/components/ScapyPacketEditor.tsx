import React, { useState, useEffect, useRef } from 'react';
import { Box, CircularProgress } from '@mui/material';
import { scapyService } from '../core/scapyService';

interface ScapyPacketEditorProps {
    packetHex: string;
    wsInfo: any[];
    onScriptChange: (script: string) => void;
    onError: (error: string | null) => void;
}

/**
 * A ultra-lightweight wrapper component that uses a raw textarea for the Python script.
 * This ensures perfect scrolling performance and zero overhead.
 */
export const ScapyPacketEditor: React.FC<ScapyPacketEditorProps> = ({ packetHex, wsInfo, onScriptChange, onError }) => {
    const [loading, setLoading] = useState(true);
    const [script, setScript] = useState("");
    const textareaRef = useRef<HTMLTextAreaElement>(null);

    useEffect(() => {
        let mounted = true;
        const loadPacket = async () => {
            try {
                setLoading(true);
                const data = await scapyService.dissect(packetHex, wsInfo);
                if (mounted) {
                    setScript(data.command);
                    onScriptChange(data.command);
                    onError(null);
                }
            } catch (err: any) {
                if (mounted) onError("Dissection failed: " + err.message);
            } finally {
                if (mounted) setLoading(false);
            }
        };
        loadPacket();
        return () => { mounted = false; };
    }, [packetHex, wsInfo, onScriptChange, onError]);

    if (loading) {
        return (
            <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100%', bgcolor: '#1e1e1e' }}>
                <CircularProgress size={30} />
            </Box>
        );
    }

    return (
        <Box sx={{ height: '100%', width: '100%', bgcolor: '#1e1e1e' }}>
            <textarea
                ref={textareaRef}
                data-testid="python-editor-input"
                value={script}
                onChange={(e) => {
                    const val = e.target.value;
                    setScript(val);
                    onScriptChange(val);
                }}
                spellCheck={false}
                style={{
                    width: '100%',
                    height: '100%',
                    backgroundColor: '#1e1e1e',
                    color: '#d4d4d4',
                    border: 'none',
                    outline: 'none',
                    fontFamily: 'monospace',
                    fontSize: '13px',
                    padding: '10px',
                    resize: 'none',
                    lineHeight: '1.5',
                    overflow: 'auto',
                    boxSizing: 'border-box'
                }}
            />
        </Box>
    );
};