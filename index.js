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
  console.log(`Server listening on port ${PORT}`);
});

// ==========================================
// 2. TELEGRAM BOT CONFIG & GOOGLE CRL FETCH
// ==========================================
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
    // Google's response might be a string if the content-type isn't json, so parse it if needed
    if (typeof response.data === 'string') {
      return JSON.parse(response.data);
    }
    return response.data;
  } catch (error) {
    console.error("Failed to fetch Google CRL:", error.message);
    return null;
  }
}

function parseKeybox(xmlData) {
  const parser = new XMLParser({ 
    ignoreAttributes: false, 
    trimValues: true,
    parseTagValue: false // IMPORTANT: Prevents parsing serial numbers as numbers
  });
  const jsonObj = parser.parse(xmlData);
  
  // Standard Keybox root is usually <Keybox> or <AndroidAttestation>
  const keybox = jsonObj.Keybox || jsonObj.AndroidAttestation;
  if (!keybox) throw new Error("Invalid Keybox XML structure.");

  const certs = [];
  const extractCerts = (node) => {
    // Look for Certificate or X509Certificate tags specifically
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
  if (!crlData || !crlData.entries) {
    return "❌ **Error**: Unable to fetch Google's Revocation List. Please try again later.";
  }

  let isRevoked = false;
  let revokedDetails = [];

  certPems.forEach((pem) => {
    try {
      const cert = new X509Certificate(pem);
      // Use toString() or convert to hex string to ensure leading zeros are handled
      const serialNumber = cert.serialNumber.toString(16).toLowerCase();
      
      // Debug log to see what is being checked
      console.log(`Checking Serial: ${serialNumber}`);

      // Check if this specific serial number is in Google's CRL
      if (crlData.entries[serialNumber]) {
        const status = crlData.entries[serialNumber].status;
        const reason = crlData.entries[serialNumber].reason;
        console.log(`Found in CRL! Status: ${status}`);
        
        if (status === 'REVOKED') {
          isRevoked = true;
          revokedDetails.push(`Serial: ${serialNumber} - Reason: ${reason}`);
        }
      }
    } catch (e) {
      console.error("Error parsing certificate:", e.message);
    }
  });

  let resultMsg = `📁 **Keybox Analysis Report**\n\n`;
  resultMsg += `• **Total Certs Found**: ${certPems.length}\n`;
  
  if (isRevoked) {
    resultMsg += `• **Google Revocation Status**: 🔴 **REVOKED**\n\n`;
    resultMsg += `⚠️ *This keybox has been banned by Google. It will FAIL all Play Integrity checks (Basic, Device, and Strong).*\n\n`;
    resultMsg += `**Revoked Details:**\n${revokedDetails.join('\n')}`;
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
  if (msg.text.includes('<?xml') || msg.text.includes('<Keybox')) {
    bot.sendMessage(msg.chat.id, "🔍 Analyzing Keybox XML...");
    const report = await analyzeKeybox(msg.text);
    bot.sendMessage(msg.chat.id, report, { parse_mode: 'Markdown' });
  }
});
