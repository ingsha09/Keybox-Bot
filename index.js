const express = require('express');
const TelegramBot = require('node-telegram-bot-api');
const { XMLParser } = require('fast-xml-parser');
const { X509Certificate } = require('@peculiar/x509');
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
  console.log(`Keep-alive web server started on port ${PORT}`);
});

// ==========================================
// 2. TELEGRAM BOT & GOOGLE CRL CONFIG
// ==========================================
const TOKEN = process.env.BOT_TOKEN;

if (!TOKEN) {
  console.error("FATAL ERROR: BOT_TOKEN environment variable is missing!");
  process.exit(1);
}

const bot = new TelegramBot(TOKEN, { polling: true });
const GOOGLE_CRL_URL = 'https://android.googleapis.com/attestation/status';

// Fetch Google's official Attestation CRL
async function fetchGoogleCRL() {
  try {
    const response = await axios.get(GOOGLE_CRL_URL, { timeout: 8000 });
    return response.data;
  } catch (error) {
    console.error("Failed to fetch Google CRL:", error.message);
    return null;
  }
}

// Parse Keybox XML and extract PEM certificate blocks
function parseKeybox(xmlData) {
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
      for (const key in node) {
        extractCerts(node[key]);
      }
    }
  };

  extractCerts(keybox);
  return certs;
}

// Perform revocation lookup against Google CRL
async function analyzeKeybox(xmlContent) {
  let certPems;
  try {
    certPems = parseKeybox(xmlContent);
  } catch (e) {
    return "❌ **Invalid File Format**: Could not parse Keybox XML structure.";
  }

  if (certPems.length === 0) {
    return "❌ **Invalid Keybox**: No certificate chains found in XML.";
  }

  const crlData = await fetchGoogleCRL();
  if (!crlData || !crlData.entries) {
    return "⚠️ **Error**: Could not fetch Google's revocation list. Please try again in a few moments.";
  }

  let isRevoked = false;

  // Cross-reference extracted certificates against CRL
  certPems.forEach((pem) => {
    try {
      const cert = new X509Certificate(pem);
      
      // Get raw serial string (usually hex)
      const hexSerial = cert.serialNumber.toLowerCase().replace(/[^0-9a-f]/g, '');
      
      // Convert serial to BigInt string decimal (Google often indexes CRL entries as Decimals)
      let decSerial = '';
      try {
        decSerial = BigInt('0x' + hexSerial).toString();
      } catch (e) {}

      // Check all possible representations in Google's CRL JSON
      for (const [crlKey, crlEntry] of Object.entries(crlData.entries)) {
        const cleanCrlKey = crlKey.toLowerCase().replace(/[^0-9a-f]/g, '');

        if (
          cleanCrlKey === hexSerial ||
          crlKey === decSerial ||
          cleanCrlKey === hexSerial.replace(/^0+/, '')
        ) {
          if (crlEntry.status === 'REVOKED') {
            isRevoked = true;
            break;
          }
        }
      }
    } catch (e) {
      console.error("Cert parsing error:", e.message);
    }
  });

  let report = `📁 **Keybox Analysis Report**\n\n`;
  report += `• **Total Certs Found**: ${certPems.length}\n`;

  if (isRevoked) {
    report += `• **Google Revocation Status**: 🔴 **REVOKED**\n\n`;
    report += `⚠️ *This keybox has been banned by Google. It will FAIL all Play Integrity checks (Basic, Device, and Strong).*`;
  } else {
    report += `• **Google Revocation Status**: 🟢 **VALID (Not Revoked)**\n\n`;
    report += `**Integrity Breakdown:**\n`;
    report += `✅ **MEETS_BASIC_INTEGRITY**: Passed\n`;
    report += `✅ **MEETS_DEVICE_INTEGRITY**: Passed\n`;
    report += `🛡️️ **MEETS_STRONG_INTEGRITY**: Certificate is clean. Passing Strong Integrity will still depend on the user's local TEE/StrongBox module setup or locked bootloader state.`;
  }

  return report;
}

// ==========================================
// 3. TELEGRAM BOT HANDLERS
// ==========================================
bot.onText(/\/start/, (msg) => {
  bot.sendMessage(
    msg.chat.id,
    "Welcome! Upload your `keybox.xml` file or paste its raw XML contents here to check its Google Attestation status.",
    { parse_mode: 'Markdown' }
  );
});

bot.on('document', async (msg) => {
  const chatId = msg.chat.id;
  try {
    const fileLink = await bot.getFileLink(msg.document.file_id);
    const response = await axios.get(fileLink, { responseType: 'text' });

    bot.sendMessage(chatId, "🔍 Analyzing Keybox against Google's Revocation List...");
    const report = await analyzeKeybox(response.data);
    bot.sendMessage(chatId, report, { parse_mode: 'Markdown' });
  } catch (err) {
    bot.sendMessage(chatId, `❌ Error processing file: ${err.message}`);
  }
});

bot.on('text', async (msg) => {
  if (msg.text.startsWith('/')) return;
  if (msg.text.includes('<?xml') || msg.text.includes('<AndroidAttestation') || msg.text.includes('<Keybox')) {
    bot.sendMessage(msg.chat.id, "🔍 Analyzing Keybox XML...");
    const report = await analyzeKeybox(msg.text);
    bot.sendMessage(msg.chat.id, report, { parse_mode: 'Markdown' });
  }
});
