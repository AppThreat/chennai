const express = require('express');
const { exec } = require('child_process');

const router = express.Router();

/**
 * Ping endpoint: runs a network ping to a user-supplied host.
 * VULNERABLE: user input is concatenated directly into the command string.
 */
router.get('/ping', (req, res) => {
    const host = req.query.host || 'localhost';

    // Line 12: vulnerable exec() call — no input sanitization
    exec(`ping -c 3 ${host}`, (error, stdout, stderr) => {
        if (error) {
            return res.status(500).json({ error: stderr });
        }
        res.json({ output: stdout });
    });
});

/**
 * Safe version using spawn with argument array (no shell injection).
 */
router.get('/safe-ping', (req, res) => {
    const host = req.query.host || 'localhost';
    const { spawn } = require('child_process');
    const ping = spawn('ping', ['-c', '3', host]);
    let output = '';
    ping.stdout.on('data', (data) => { output += data; });
    ping.on('close', () => res.json({ output }));
});

module.exports = router;
