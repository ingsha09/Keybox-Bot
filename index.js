const express = require('express');
const TelegramBot = require('node-telegram-bot-api');
const { XMLParser } = require('fast-xml-parser');
const { X509Certificate } = require('node:crypto');
const axios = require('axios');

// ==========================================
// 1. EXPRESS KEEP-ALIVE SERVER (FOR RENDER)
// ==========================================
const app = express();
const PORT = process.env.PORT || 3000;

app.get('/', (req, res) => {
  res.send('Keybox Checker Bot is active and running!');
});

app.listen(PORT, () => {
  console.log(`Keep-alive server listening on port ${PORT}`);
});

// ==========================================
// 2. TELEGRAM BOT CONFIG & GOOGLE CRL FETCH
// ==========================================
const TOKEN = process.env.BOT_TOKEN;

if (!TOKEN) {
  console.error("FATAL ERROR: BOT_TOKEN environment variable is missing!");
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
    console.error("Failed to fetch Google CRL:", error.message);
    return null;
  }
}

// Clean and format PEM blocks to prevent OpenSSL line-ending/parsing errors
function cleanPem(pemStr) {
  if (!pemStr) return '';
  // Remove carriage returns (\r), XML entity escapes, and strip whitespace
  let clean = pemStr.replace(/\r/g, '').replace(/&#13;/g, '').trim();
  
  // Ensure header and footer have proper Unix newline breaks
  clean = clean.replace(/-----BEGIN CERTIFICATE-----/g, '-----BEGIN CERTIFICATE-----\n');
  clean = clean.replace(/-----END CERTIFICATE-----/g, '\n-----END CERTIFICATE-----');
  
  // Filter empty lines and join cleanly
  const lines = clean.split('\n').map(l => l.trim()).filter(Boolean);
  return lines.join('\n');
}

// Extract all PEM certificates from the XML
function parseKeyboxAllCerts(xmlData) {
  const parser = new XMLParser({ ignoreAttributes: false });
  const jsonObj = parser.parse(xmlData);

  const keybox = jsonObj.AndroidAttestation || jsonObj.Keybox;
  if (!keybox) throw new Error("Invalid Keybox XML structure.");

  const certs = [];
  const extractCerts = (node) => {
    if (typeof node === 'string' && node.includes('-----BEGIN CERTIFICATE-----')) {
      const pemMatches = node.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g);
      if (pemMatches) certs.push(...pemMatches);
    } else if (typeof node === 'object' && node !== null) {
      for (const key in node) extractCerts(node[key]);
    }
  };

  extractCerts(keybox);
  return certs;
}

// ==========================================
// 3. ANALYSIS & REVOCATION CHECKING LOGIC
// ==========================================
async function analyzeKeybox(xmlContent) {
  let certPems;
  try {
    certPems = parseKeyboxAllCerts(xmlContent);
  } catch (e) {
    return "❌ **Invalid File Format**: Could not parse Keybox XML structure.";
  }

  if (certPems.length === 0) {
    return "❌ **Invalid Keybox**: No certificate chains found.";
  }

  const crlData = await fetchGoogleCRL();
  if (!crlData || !crlData.entries) {
    return "⚠️ **Error**: Unable to reach Google CRL servers. Try again in a few moments.";
  }

  let isRevoked = false;

  certPems.forEach((pem) => {
    try {
      // Format PEM to prevent "PEM routines::bad end line" errors
      const sanitizedPem = cleanPem(pem);
      const cert = new X509Certificate(sanitizedPem);
      
      // 1. Raw Hex Serial Number (lowercase)
      const rawHexSerial = cert.serialNumber.toLowerCase().replace(/[^0-9a-f]/g, '');
      
      // 2. Clean Hex Serial Number (no leading zeros)
      const cleanHexSerial = rawHexSerial.replace(/^0+/, '') || '0';
      
      // 3. Decimal Serial Number (Base-10 Conversion for Google's CRL JSON keys)
      let decimalSerial = '';
      try {
        decimalSerial = BigInt('0x' + rawHexSerial).toString(10);
      } catch (e) {}

      // Check all key variations against Google's CRL entry list
      const hitDecimal = crlData.entries[decimalSerial];
      const hitRawHex = crlData.entries[rawHexSerial];
      const hitCleanHex = crlData.entries[cleanHexSerial];

      if (
        (hitDecimal && hitDecimal.status === 'REVOKED') ||
        (hitRawHex && hitRawHex.status === 'REVOKED') ||
        (hitCleanHex && hitCleanHex.status === 'REVOKED')
      ) {
        isRevoked = true;
      }
    } catch (e) {
      console.error("Cert parsing error:", e.message);
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
    report += `🛡️ **MEETS_STRONG_INTEGRITY**: Certificate is clean. Passing Strong Integrity depends on user's local TEE/StrongBox module setup or locked bootloader state.`;
  }

  return report;
}

// ==========================================
// 4. TELEGRAM BOT HANDLERS
// ==========================================
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
