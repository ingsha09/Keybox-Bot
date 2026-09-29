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

bot.on('polling_error', (error) => {
  console.log(`Polling error: ${error.code} - ${error.message}`);
});

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

// NEW: Aggressive cleaning and re-wrapping of certificates
function formatCertificate(rawString) {
    // 1. Remove all PEM headers if they exist
    let cleaned = rawString.replace(/-----BEGIN CERTIFICATE-----/g, '')
                           .replace(/-----END CERTIFICATE-----/g, '');
    
    // 2. Remove ALL whitespace (spaces, tabs, newlines)
    cleaned = cleaned.replace(/\s/g, '');

    // 3. Re-wrap in standard PEM format (64 chars per line)
    const lines = cleaned.match(/.{1,64}/g) || [];
    return `-----BEGIN CERTIFICATE-----\n${lines.join('\n')}\n-----END CERTIFICATE-----`;
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
    if (typeof node === 'string') {
        // Match both PEM and raw Base64 strings
        if (node.includes('-----BEGIN CERTIFICATE-----') || (node.length > 200 && /^[A-Za-z0-9+/=\s]+$/.test(node))) {
            certs.push(node);
        }
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

function formatDate(date) {
    if (!date) return 'Unknown';
    try {
        return date.toLocaleDateString('en-GB');
    } catch (e) {
        return 'Invalid Date';
    }
}

async function analyzeKeybox(xmlContent) {
  let rawCerts;
  try {
    rawCerts = parseKeybox(xmlContent);
  } catch (e) {
    return "❌ Invalid Keybox XML File: Could not parse certificates.";
  }

  if (rawCerts.length === 0) {
    return "❌ Invalid Keybox: No certificate chains found.";
  }

  const crlData = await fetchGoogleCRL();
  if (!crlData || !crlData.entries) {
    return "❌ Error: Unable to fetch Google's Revocation List. Please try again later.";
  }

  let isRevoked = false;
  let hasExpiredCert = false;
  let earliestExpiryDate = null;
  let certReports = [];
  let parsedCerts = [];

  // Step 1: Parse all certificates first
  rawCerts.forEach((rawCert, index) => {
    try {
      const pemString = formatCertificate(rawCert);
      const cert = new X509Certificate(pemString);
      parsedCerts.push({ index, cert });
    } catch (e) {
      console.error(`Error parsing certificate at index ${index}:`, e.message);
      certReports.push(`🔐 Certificate ${index}: ❌ Could not parse (Invalid format)\n`);
      hasExpiredCert = true;
    }
  });

  // Step 2: Analyze each certificate
  parsedCerts.forEach(({ index, cert }) => {
    const notBefore = cert.notBefore || new Date(0);
    const notAfter = cert.notAfter || new Date(0);
    const now = new Date();
    
    const isExpired = !cert.notAfter || now > notAfter;
    const isNotYetValid = !cert.notBefore || now < notBefore;
    
    if (isExpired) hasExpiredCert = true;

    if (notAfter && notAfter.getTime() > 0) {
      if (!earliestExpiryDate || notAfter < earliestExpiryDate) {
        earliestExpiryDate = notAfter;
      }
    }

    const basicSerial = cert.serialNumber.toString(16).toLowerCase().replace(/^0x/, '');
    const cleanSerial = basicSerial.replace(/^0+/, '');
    
    let subjectSerial = 'Not Found';
    try {
        const skiExt = cert.extensions.find(e => e.type === '2.5.29.14');
        if (skiExt) {
            subjectSerial = skiExt.value.toString('hex').toLowerCase();
        }
    } catch (e) { /* Ignore */ }

    let revoked = false;
    let revokeReason = '';
    if (crlData.entries[basicSerial] || crlData.entries[cleanSerial]) {
      const entry = crlData.entries[basicSerial] || crlData.entries[cleanSerial];
      if (entry.status === 'REVOKED') {
        revoked = true;
        revokeReason = entry.reason || 'Unknown';
        isRevoked = true;
      }
    }

    let certMsg = `🔐 Certificate ${index} Serial: ${basicSerial}\n`;
    certMsg += `ℹ️ Subject Serial: ${subjectSerial}\n`;
    certMsg += `📅 Valid from: ${formatDate(notBefore)} to: ${formatDate(notAfter)}\n`;
    
    if (isExpired) certMsg += `❌ Expired certificate\n`;
    else if (isNotYetValid) certMsg += `❌ Certificate not yet valid\n`;
    else certMsg += `✅ Certificate within validity period\n`;

    if (revoked) certMsg += `❌ REVOKED in Google's list (Reason: ${revokeReason})\n`;
    else certMsg += `✅ Serial number not found in Google's revoked keybox list\n`;

    certReports.push(certMsg);
  });

  let resultMsg = `📁 Keybox Analysis Report\n\n`;
  resultMsg += `• Total Certs Found: ${rawCerts.length}\n\n`;
  resultMsg += `--- Certificate Details ---\n\n`;
  resultMsg += certReports.join('\n');

  resultMsg += `\n--- Summary ---\n`;

  // FIX: Made the summary clearer and less misleading
  if (isRevoked) {
    resultMsg += `• Google Revocation Status: 🔴 REVOKED\n`;
    resultMsg += `⚠️ This keybox has been banned by Google.\n`;
  } else {
    resultMsg += `• Google Revocation Status: 🟢 NOT REVOKED\n`;
  }

  if (hasExpiredCert) {
    resultMsg += `\n• Keybox Expiry Status: ❌ EXPIRED / INVALID\n`;
    if (earliestExpiryDate) {
      resultMsg += `⌛ Keybox expired on: ${formatDate(earliestExpiryDate)}\n`;
    }
    resultMsg += `🔴 THIS KEYBOX CANNOT BE USED FOR STRONG INTEGRITY.\n`;
  } else {
    resultMsg += `\n• Keybox Expiry Status: ✅ VALID\n`;
    resultMsg += `⌛ Keybox expires on: ${formatDate(earliestExpiryDate)}\n`;
    resultMsg += `🛡️ This keybox is clean and can be used for Strong Integrity (assuming local TEE setup is correct).\n`;
  }

  resultMsg += `\n\nNote: Sometimes Google bans a keybox without revoking it. This bot fetches the Google revocation list, but can't know if a keybox is banned via unofficial methods.`;

  return resultMsg;
}

bot.onText(/\/start/, (msg) => {
  bot.sendMessage(msg.chat.id, "Welcome! Upload your keybox.xml file or paste its contents here to check its Google Attestation status.");
});

bot.on('document', async (msg) => {
  const chatId = msg.chat.id;
  try {
    const fileLink = await bot.getFileLink(msg.document.file_id);
    const response = await axios.get(fileLink, { responseType: 'text' });
    
    bot.sendMessage(chatId, "🔍 Analyzing Keybox against Google's Revocation List...");
    const report = await analyzeKeybox(response.data);
    bot.sendMessage(chatId, report);
  } catch (err) {
    bot.sendMessage(chatId, `❌ Error reading keybox file: ${err.message}`);
  }
});

bot.on('text', async (msg) => {
  if (msg.text.startsWith('/')) return;
  if (msg.text.includes('<?xml') || msg.text.includes('<Keybox') || msg.text.includes('<AndroidAttestation')) {
    bot.sendMessage(msg.chat.id, "🔍 Analyzing Keybox XML...");
    const report = await analyzeKeybox(msg.text);
    bot.sendMessage(msg.chat.id, report);
  }
});
