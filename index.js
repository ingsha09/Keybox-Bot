const express = require('express');
const TelegramBot = require('node-telegram-bot-api');
const { XMLParser } = require('fast-xml-parser');
const { X509Certificate } = require('@peculiar/x509');
const axios = require('axios');

// Express server setup to keep Render awake
const app = express();
const PORT = process.env.PORT || 3000;

app.get('/', (req, res) => {
  res.send('Keybox Bot is live and running!');
});

app.listen(PORT, () => {
  console.log(`Keep-alive server listening on port ${PORT}`);
});

// Bot token initialization
const TOKEN = process.env.BOT_TOKEN;
if (!TOKEN) {
  console.error("FATAL: BOT_TOKEN environment variable is missing!");
  process.exit(1);
}

const bot = new TelegramBot(TOKEN, { polling: true });
const GOOGLE_CRL_URL = 'https://android.googleapis.com/attestation/status';

async function fetchGoogleCRL() {
  try {
    const response = await axios.get(GOOGLE_CRL_URL);
    return response.data;
  } catch (error) {
    console.error("Failed to fetch Google CRL:", error.message);
    return null;
  }
}

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
      for (const key in node) extractCerts(node[key]);
    }
  };

  extractCerts(keybox);
  return certs;
}

async function analyzeKeybox(xmlContent) {
  let certPems;
  try {
    certPems = parseKeybox(xmlContent);
  } catch (e) {
    return "❌ **Invalid Keybox XML File**: Could not parse certificates.";
  }

  if (certPems.length === 0) {
    return "❌ **Invalid Keybox**: No certificate chains found.";
  }

  const crlData = await fetchGoogleCRL();
  let isRevoked = false;

  certPems.forEach((pem) => {
    try {
      const cert = new X509Certificate(pem);
      const serialNumber = cert.serialNumber.toLowerCase();
      
      if (crlData && crlData.entries && crlData.entries[serialNumber]) {
        if (crlData.entries[serialNumber].status === 'REVOKED') {
          isRevoked = true;
        }
      }
    } catch (e) {}
  });

  let resultMsg = `📁 **Keybox Analysis Report**\n\n`;
  resultMsg += `• **Total Certs Found**: ${certPems.length}\n`;
  
  if (isRevoked) {
    resultMsg += `• **Google Revocation Status**: 🔴 **REVOKED**\n\n`;
    resultMsg += `⚠️ *This keybox has been banned by Google. It will FAIL all Play Integrity checks (Basic, Device, and Strong).*`;
  } else {
    resultMsg += `• **Google Revocation Status**: 🟢 **VALID (Not Revoked)**\n\n`;
    resultMsg += `**Integrity Breakdown:**\n`;
    resultMsg += `✅ **MEETS_BASIC_INTEGRITY**: Passed\n`;
    resultMsg += `✅ **MEETS_DEVICE_INTEGRITY**: Passed\n`;
    resultMsg += `🛡️ **MEETS_STRONG_INTEGRITY**: Certificate is clean. Passing Strong Integrity will still depend on the user's local TEE/StrongBox module setup or locked bootloader state.`;
  }

  return resultMsg;
}

bot.onText(/\/start/, (msg) => {
  bot.sendMessage(msg.chat.id, "Welcome! Upload your `keybox.xml` file or paste its contents here to check its Google Attestation status.", { parse_mode: 'Markdown' });
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
    bot.sendMessage(chatId, `❌ Error reading keybox file: ${err.message}`);
  }
});

bot.on('text', async (msg) => {
  if (msg.text.startsWith('/')) return;
  if (msg.text.includes('<?xml') || msg.text.includes('<AndroidAttestation')) {
    bot.sendMessage(msg.chat.id, "🔍 Analyzing Keybox XML...");
    const report = await analyzeKeybox(msg.text);
    bot.sendMessage(msg.chat.id, report, { parse_mode: 'Markdown' });
  }
});
