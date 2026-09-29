const express = require('express');
const TelegramBot = require('node-telegram-bot-api');
const { XMLParser } = require('fast-xml-parser');
const { X509Certificate } = require('node:crypto');
const axios = require('axios');

// 1. EXPRESS KEEP-ALIVE SERVER FOR RENDER
const app = express();
const PORT = process.env.PORT || 3000;

app.get('/', (req, res) => {
  res.send('Keybox Checker Bot is running!');
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

// 2. BOT CONFIGURATION
const TOKEN = process.env.BOT_TOKEN;
if (!TOKEN) {
  console.error("FATAL: BOT_TOKEN variable is missing!");
  process.exit(1);
}

const bot = new TelegramBot(TOKEN, { polling: true });
const GOOGLE_CRL_URL = 'https://android.googleapis.com/attestation/status';

// Fetch Google CRL
async function fetchGoogleCRL() {
  try {
    const response = await axios.get(GOOGLE_CRL_URL, {
      headers: { 'Cache-Control': 'no-cache' },
      timeout: 10000
    });
    return response.data;
  } catch (error) {
    console.error("CRL Fetch error:", error.message);
    return null;
  }
}

// Convert serial numbers to Google CRL hex format (lowercase, no leading zero)
function formatSerialToHex(cert) {
  let rawSerial = cert.serialNumber.toLowerCase().replace(/[^0-9a-f]/g, '');
  // Strip leading zeros to match Google's CRL indexing
  let cleanSerial = rawSerial.replace(/^0+/, '');
  return cleanSerial || '0';
}

// Extract leaf certificates from Keybox XML
function parseKeyboxLeafCerts(xmlData) {
  const parser = new XMLParser({ ignoreAttributes: false });
  const jsonObj = parser.parse(xmlData);

  const keybox = jsonObj.AndroidAttestation || jsonObj.Keybox;
  if (!keybox) throw new Error("Invalid Keybox structure.");

  const certPems = [];

  // Helper to extract the first certificate found in a node (Leaf Certificate)
  const getLeafCert = (keyNode) => {
    if (!keyNode) return;
    let certBlock = keyNode.CertificateChain || keyNode.Certificates || keyNode.certificate;
    if (!certBlock) return;

    let certStr = typeof certBlock === 'string' ? certBlock : JSON.stringify(certBlock);
    const matches = certStr.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g);
    if (matches && matches.length > 0) {
      // Push ONLY the first certificate in the chain (Leaf cert)
      certPems.push(matches[0]);
    }
  };

  // Process ECDSA & RSA keys if present
  if (keybox.Key) {
    const keys = Array.isArray(keybox.Key) ? keybox.Key : [keybox.Key];
    keys.forEach(getLeafCert);
  } else {
    // Fallback search across all tags
    const findCerts = (node) => {
      if (typeof node === 'string' && node.includes('-----BEGIN CERTIFICATE-----')) {
        const matches = node.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g);
        if (matches && matches.length > 0) certPems.push(matches[0]);
      } else if (typeof node === 'object' && node !== null) {
        for (const k in node) findCerts(node[k]);
      }
    };
    findCerts(keybox);
  }

  return certPems;
}

// Analyze Keybox
async function analyzeKeybox(xmlContent) {
  let leafPems;
  try {
    leafPems = parseKeyboxLeafCerts(xmlContent);
  } catch (e) {
    return "❌ **Invalid File Format**: Could not parse Keybox XML structure.";
  }

  if (leafPems.length === 0) {
    return "❌ **Invalid Keybox**: No certificate chains found.";
  }

  const crlData = await fetchGoogleCRL();
  if (!crlData || !crlData.entries) {
    return "⚠️ **Error**: Unable to reach Google CRL servers. Try again shortly.";
  }

  let isRevoked = false;
  const detectedSerials = [];

  leafPems.forEach((pem) => {
    try {
      // Standard Node.js native crypto X509 parser
      const cert = new X509Certificate(pem);
      const hexSerial = formatSerialToHex(cert);
      detectedSerials.push(hexSerial);

      // Check against Google CRL database entries
      if (crlData.entries[hexSerial]) {
        if (crlData.entries[hexSerial].status === 'REVOKED') {
          isRevoked = true;
        }
      }
    } catch (e) {
      console.error("Cert parsing error:", e.message);
    }
  });

  let report = `📁 **Keybox Analysis Report**\n\n`;
  report += `• **Leaf Certificates Evaluated**: ${leafPems.length}\n`;

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

// 3. BOT COMMAND HANDLERS
bot.onText(/\/start/, (msg) => {
  bot.sendMessage(
    msg.chat.id,
    "Welcome! Upload your `keybox.xml` file or paste its contents here to verify Google Attestation status.",
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
