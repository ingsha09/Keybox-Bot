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
// 2. TELEGRAM BOT CONFIG
// ==========================================
const TOKEN = process.env.BOT_TOKEN;
if (!TOKEN) {
  console.error("FATAL: BOT_TOKEN environment variable is missing!");
  process.exit(1);
}

const bot = new TelegramBot(TOKEN, { polling: true });

// FIX FOR 409 CONFLICT
bot.deleteWebHook().then(() => {
    console.log("Webhook deleted, polling started.");
}).catch(err => {
    console.error("Error deleting webhook:", err.message);
});

const GOOGLE_CRL_URL = 'https://android.googleapis.com/attestation/status';

async function fetchGoogleCRL() {
  try {
    const response = await axios.get(GOOGLE_CRL_URL);
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
    parseTagValue: false 
  });
  const jsonObj = parser.parse(xmlData);
  
  const certs = [];
  
  const extractCerts = (node) => {
    if (typeof node === 'string' && node.includes('-----BEGIN CERTIFICATE-----')) {
      const pemMatches = node.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g);
      if (pemMatches) certs.push(...pemMatches);
    } else if (Array.isArray(node)) {
      node.forEach(item => extractCerts(item));
    } else if (typeof node === 'object' && node !== null) {
      for (const key in node) {
        extractCerts(node[key]);
      }
    }
  };

  extractCerts(jsonObj);
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
  let hasExpiredCert = false;
  let earliestExpiryDate = null;
  let certReports = [];

  certPems.forEach((pem, index) => {
    try {
      const cert = new X509Certificate(pem);
      let serialNumber = cert.serialNumber.toString(16).toLowerCase().replace(/^0x/, '');
      const cleanSerial = serialNumber.replace(/^0+/, '');
      
      // 1. Check Revocation List
      let revoked = false;
      let revokeReason = '';
      if (crlData.entries[serialNumber] || crlData.entries[cleanSerial]) {
        const entry = crlData.entries[serialNumber] || crlData.entries[cleanSerial];
        if (entry.status === 'REVOKED') {
          revoked = true;
          revokeReason = entry.reason || 'Unknown';
          isRevoked = true;
          revokedDetails.push(`Serial: ${serialNumber} - Reason: ${revokeReason}`);
        }
      }

      // 2. Check Expiry Dates
      const notBefore = cert.notBefore;
      const notAfter = cert.notAfter;
      const now = new Date();
      
      const isExpired = now > notAfter;
      const isNotYetValid = now < notBefore;
      
      if (isExpired) hasExpiredCert = true;

      // Track earliest expiry for the whole chain
      if (!earliestExpiryDate || notAfter < earliestExpiryDate) {
        earliestExpiryDate = notAfter;
      }

      // Build detailed string for this certificate
      let certMsg = `🔐 **Certificate ${index} Serial**: \`${serialNumber}\`\n`;
      certMsg += `📅 Valid from: ${notBefore.toLocaleDateString('en-GB')} to: ${notAfter.toLocaleDateString('en-GB')}\n`;
      
      if (isExpired) {
        certMsg += `❌ **Expired certificate**\n`;
      } else if (isNotYetValid) {
        certMsg += `❌ **Certificate not yet valid**\n`;
      } else {
        certMsg += `✅ Certificate within validity period\n`;
      }

      if (revoked) {
        certMsg += `❌ **REVOKED in Google's list** (Reason: ${revokeReason})\n`;
      } else {
        certMsg += `✅ Serial number not found in Google's revoked keybox list\n`;
      }

      certReports.push(certMsg);

    } catch (e) {
      console.error(`Error parsing certificate at index ${index}:`, e.message);
    }
  });

  // Build final report
  let resultMsg = `📁 **Keybox Analysis Report**\n\n`;
  resultMsg += `• **Total Certs Found**: ${certPems.length}\n\n`;
  resultMsg += `--- **Certificate Details** ---\n\n`;
  resultMsg += certReports.join('\n');

  resultMsg += `\n--- **Summary** ---\n`;

  if (isRevoked) {
    resultMsg += `• **Google Revocation Status**: 🔴 **REVOKED**\n`;
    resultMsg += `⚠️ *This keybox has been banned by Google. It will FAIL all Play Integrity checks.*\n`;
    resultMsg += `**Revoked Details:**\n${revokedDetails.join('\n')}\n`;
  } else {
    resultMsg += `• **Google Revocation Status**: 🟢 **VALID (Not Revoked)**\n`;
  }

  if (hasExpiredCert) {
    resultMsg += `\n• **Keybox Expiry Status**: ❌ **EXPIRED**\n`;
    resultMsg += `⌛ Keybox expired on: ${earliestExpiryDate.toLocaleDateString('en-GB')}\n`;
    resultMsg += `🔴 **This keybox CANNOT be used for Strong Integrity due to expired certificates.**\n`;
  } else {
    resultMsg += `\n• **Keybox Expiry Status**: ✅ **VALID**\n`;
    resultMsg += `⌛ Keybox expires on: ${earliestExpiryDate.toLocaleDateString('en-GB')}\n`;
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
  if (msg.text.includes('<?xml') || msg.text.includes('<Keybox') || msg.text.includes('<AndroidAttestation')) {
    bot.sendMessage(msg.chat.id, "🔍 Analyzing Keybox XML...");
    const report = await analyzeKeybox(msg.text);
    bot.sendMessage(msg.chat.id, report, { parse_mode: 'Markdown' });
  }
});
