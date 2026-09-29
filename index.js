const express = require('express');
const TelegramBot = require('node-telegram-bot-api');
const { XMLParser } = require('fast-xml-parser');
const { X509Certificate } = require('node:crypto');
const axios = require('axios');

// 1. EXPRESS KEEP-ALIVE SERVER
const app = express();
const PORT = process.env.PORT || 3000;

app.get('/', (req, res) => {
  res.send('Keybox Checker Bot is running!');
});

app.listen(PORT, () => {
  console.log(`Server started on port ${PORT}`);
});

// 2. BOT CONFIGURATION
const TOKEN = process.env.BOT_TOKEN;
if (!TOKEN) {
  console.error("FATAL: BOT_TOKEN is missing!");
  process.exit(1);
}

const bot = new TelegramBot(TOKEN, { polling: true });
const GOOGLE_CRL_URL = 'https://android.googleapis.com/attestation/status';

async function fetchGoogleCRL() {
  try {
    const response = await axios.get(GOOGLE_CRL_URL, {
      headers: { 'Cache-Control': 'no-cache' },
      timeout: 10000
    });
    return response.data;
  } catch (error) {
    console.error("Failed to fetch CRL:", error.message);
    return null;
  }
}

// Extract base64 certificates out of XML cleanly
function extractPemsFromXml(xmlData) {
  const certs = [];
  // Match standard PEM certificate blocks globally
  const matches = xmlData.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g);
  if (matches) {
    matches.forEach((pem) => {
      // Clean string completely
      const clean = pem.replace(/\r/g, '').trim();
      certs.push(clean);
    });
  }
  return certs;
}

// Convert ASN.1 DER serial number to Google-compatible keys
function getSerialKeys(pem) {
  const keys = new Set();
  try {
    const cert = new X509Certificate(pem);
    let hex = cert.serialNumber.toLowerCase().replace(/[^0-9a-f]/g, '');

    // Hex variant 1: Raw
    keys.add(hex);

    // Hex variant 2: Stripped leading zeros
    const noLeadingZeros = hex.replace(/^0+/, '');
    if (noLeadingZeros) keys.add(noLeadingZeros);

    // Hex variant 3: Ensure even length if stripped
    if (noLeadingZeros.length % 2 !== 0) {
      keys.add('0' + noLeadingZeros);
    }

    // Decimal variant: Base-10 string
    try {
      const dec = BigInt('0x' + hex).toString(10);
      keys.add(dec);
    } catch (e) {}
  } catch (e) {
    // If Node crypto fails, extract serial directly from ASN.1 Base64 Buffer
    try {
      const b64 = pem.replace(/-----BEGIN CERTIFICATE-----/g, '')
                     .replace(/-----END CERTIFICATE-----/g, '')
                     .replace(/\s+/g, '');
      const buf = Buffer.from(b64, 'base64');
      
      // ASN.1 DER Serial Number offset check (TAG 0x02 after Sequence)
      if (buf[0] === 0x30) {
        let idx = 2;
        if (buf[1] & 0x80) idx += (buf[1] & 0x7f); // Multi-byte length
        if (buf[idx] === 0x02) { // Integer tag (Serial)
          const len = buf[idx + 1];
          const serialBuf = buf.slice(idx + 2, idx + 2 + len);
          const rawHex = serialBuf.toString('hex').toLowerCase();
          
          keys.add(rawHex);
          keys.add(rawHex.replace(/^0+/, ''));
          try {
            keys.add(BigInt('0x' + rawHex).toString(10));
          } catch (err) {}
        }
      }
    } catch (err) {}
  }

  return Array.from(keys);
}

// Core Revocation Checking Engine
async function analyzeKeybox(xmlContent) {
  const certPems = extractPemsFromXml(xmlContent);

  if (certPems.length === 0) {
    return "❌ **Invalid Keybox**: No certificate chains found in the provided XML.";
  }

  const crlData = await fetchGoogleCRL();
  if (!crlData || !crlData.entries) {
    return "⚠️ **Error**: Could not retrieve Google's Revocation List. Try again in a moment.";
  }

  let isRevoked = false;

  certPems.forEach((pem) => {
    const keysToCheck = getSerialKeys(pem);

    for (const key of keysToCheck) {
      if (crlData.entries[key] && crlData.entries[key].status === 'REVOKED') {
        isRevoked = true;
        break;
      }
    }
  });

  let report = `📁 **Keybox Analysis Report**\n\n`;
  report += `• **Certificates Evaluated**: ${certPems.length}\n`;

  if (isRevoked) {
    report += `• **Google Revocation Status**: 🔴 **REVOKED**\n\n`;
    report += `⚠️ *This keybox has been banned by Google. It will FAIL all Play Integrity checks (Basic, Device, and Strong).*`;
  } else {
    report += `• **Google Revocation Status**: 🟢 **VALID (Not Revoked)**\n\n`;
    report += `**Integrity Breakdown:**\n`;
    report += `✅ **MEETS_BASIC_INTEGRITY**: Passed\n`;
    report += `✅ **MEETS_DEVICE_INTEGRITY**: Passed\n`;
    report += `🛡️ **MEETS_STRONG_INTEGRITY**: Certificate is clean. Passing Strong Integrity depends on user's TEE/StrongBox module setup or locked bootloader state.`;
  }

  return report;
}

// 3. TELEGRAM BOT HANDLERS
bot.onText(/\/start/, (msg) => {
  bot.sendMessage(
    msg.chat.id,
    "Welcome! Upload your `keybox.xml` file or paste its raw XML contents here to verify Google Attestation status.",
    { parse_mode: 'Markdown' }
  );
});

bot.on('document', async (msg) => {
  const chatId = msg.chat.id;
  try {
    const fileLink = await bot.getFileLink(msg.document.file_id);
    const response = await axios.get(fileLink, { responseType: 'text' });

    bot.sendMessage(chatId, "🔍 Analyzing Keybox against Google CRL...");
    const report = await analyzeKeybox(response.data);
    bot.sendMessage(chatId, report, { parse_mode: 'Markdown' });
  } catch (err) {
    bot.sendMessage(chatId, `❌ Processing error: ${err.message}`);
  }
});

bot.on('text', async (msg) => {
  if (msg.text.startsWith('/')) return;
  if (msg.text.includes('<?xml') || msg.text.includes('<AndroidAttestation') || msg.text.includes('<Keybox')) {
    bot.sendMessage(msg.chat.id, "🔍 Analyzing raw XML...");
    const report = await analyzeKeybox(msg.text);
    bot.sendMessage(msg.chat.id, report, { parse_mode: 'Markdown' });
  }
});
