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

// ==========================================
// 3. DATA SOURCES
// ==========================================
const GOOGLE_CRL_URL = 'https://android.googleapis.com/attestation/status';
const PRIVATE_BAN_LIST_URL = 'https://raw.githubusercontent.com/daboynb/autojson/refs/heads/main/banned.txt';

// Known valid Google Hardware Attestation Root names
const VALID_GOOGLE_ROOTS = [
    'Google Hardware Attestation Root',
    'Key Attestation CA1',
    'Droid CA1',
    'Droid CA2'
];

// Known Google intermediates that are still valid but not hardware roots
const KNOWN_GOOGLE_INTERMEDIATES = [
    'Google LLC',
    'Google'
];

let googleCRL = null;
let privateBanList = new Set();

async function fetchGoogleCRL() {
  if (googleCRL) return googleCRL;
  try {
    const response = await axios.get(GOOGLE_CRL_URL);
    googleCRL = typeof response.data === 'string' ? JSON.parse(response.data) : response.data;
    return googleCRL;
  } catch (error) {
    console.error("Failed to fetch Google CRL:", error.message);
    return null;
  }
}

async function fetchPrivateBanList() {
  if (privateBanList.size > 0) return privateBanList;
  try {
    const response = await axios.get(PRIVATE_BAN_LIST_URL);
    const lines = response.data.split('\n');
    for (const line of lines) {
        const serial = line.trim().toLowerCase();
        if (serial) privateBanList.add(serial);
    }
    console.log(`Loaded ${privateBanList.size} banned serials from private list.`);
    return privateBanList;
  } catch (error) {
    console.error("Failed to fetch private ban list:", error.message);
    return null;
  }
}

// ==========================================
// 4. HELPER FUNCTIONS
// ==========================================
function formatCertificate(rawString) {
    let cleaned = rawString.replace(/-----BEGIN CERTIFICATE-----/g, '')
                           .replace(/-----END CERTIFICATE-----/g, '');
    cleaned = cleaned.replace(/\s/g, '');
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

// ==========================================
// 5. MAIN ANALYSIS FUNCTION
// ==========================================
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
  const banList = await fetchPrivateBanList();
  
  if (!crlData || !crlData.entries) {
    return "❌ Error: Unable to fetch Google's Revocation List. Please try again later.";
  }

  let isRevoked = false;
  let isPrivatelyBanned = false;
  let hasExpiredCert = false;
  let earliestExpiryDate = null;
  let certReports = [];
  let parsedCerts = [];
  let hasValidRoot = false;
  let hasKnownIntermediate = false;

  // Step 1: Parse all certificates
  rawCerts.forEach((rawCert, index) => {
    try {
      const pemString = formatCertificate(rawCert);
      const cert = new X509Certificate(pemString);
      parsedCerts.push({ index, cert, isRoot: index === rawCerts.length - 1 });
    } catch (e) {
      console.error(`Error parsing certificate at index ${index}:`, e.message);
      certReports.push(`🔐 Certificate ${index}: ❌ Could not parse (Invalid format)\n`);
      hasExpiredCert = true;
    }
  });

  // Step 2: Analyze each certificate
  parsedCerts.forEach(({ index, cert, isRoot }) => {
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
            subjectSerial = Buffer.from(skiExt.value).toString('hex').toLowerCase();
        }
    } catch (e) { /* Ignore */ }

    // Check Google's CRL
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

    // Check Private Ban List
    let privatelyBanned = false;
    if (banList && subjectSerial !== 'Not Found') {
        const cleanSubjectSerial = subjectSerial.replace(/^04/, '');
        if (banList.has(subjectSerial) || banList.has(cleanSubjectSerial)) {
            privatelyBanned = true;
            isPrivatelyBanned = true;
        }
    }

    // Check Root/Intermediate Certificate
    let rootStatus = '';
    if (isRoot) {
        const subjectName = cert.subjectName ? cert.subjectName.toString() : '';
        
        // Check if it's a known Google Hardware Root
        for (const validRoot of VALID_GOOGLE_ROOTS) {
            if (subjectName.includes(validRoot)) {
                hasValidRoot = true;
                rootStatus = `✅ Google Hardware Attestation Root\n`;
                break;
            }
        }
        
        // If not a hardware root, check if it's a known Google intermediate
        if (!hasValidRoot) {
            for (const intermediate of KNOWN_GOOGLE_INTERMEDIATES) {
                if (subjectName.includes(intermediate)) {
                    hasKnownIntermediate = true;
                    rootStatus = `⚠️ Known Google Intermediate (not a hardware root)\n`;
                    break;
                }
            }
        }
        
        // If neither, it's unknown
        if (!hasValidRoot && !hasKnownIntermediate) {
            rootStatus = `❌ Unknown root certificate\n`;
        }
    }

    let certMsg = `🔐 Certificate ${index} Serial: ${basicSerial}\n`;
    certMsg += `ℹ️ Subject Serial: ${subjectSerial}\n`;
    certMsg += `📅 Valid from: ${formatDate(notBefore)} to: ${formatDate(notAfter)}\n`;
    
    if (isExpired) certMsg += `❌ Expired certificate\n`;
    else if (isNotYetValid) certMsg += `❌ Certificate not yet valid\n`;
    else certMsg += `✅ Certificate within validity period\n`;

    if (revoked) {
      certMsg += `❌ REVOKED in Google's list (Reason: ${revokeReason})\n`;
    } else if (privatelyBanned) {
      certMsg += `❌ This subject serial number is banned (private list).\n`;
    } else {
      certMsg += `✅ Serial number not found in Google's revoked keybox list\n`;
    }

    if (rootStatus) certMsg += rootStatus;

    certReports.push(certMsg);
  });

  // Step 3: Build the final report
  let resultMsg = `📁 Keybox Analysis Report\n\n`;
  resultMsg += `• Total Certs Found: ${rawCerts.length}\n\n`;
  resultMsg += `--- Certificate Details ---\n\n`;
  resultMsg += certReports.join('\n');

  resultMsg += `\n--- Summary ---\n`;

  if (isRevoked) {
    resultMsg += `• Google Revocation Status: 🔴 REVOKED\n`;
  } else {
    resultMsg += `• Google Revocation Status: 🟢 NOT REVOKED\n`;
  }

  if (isPrivatelyBanned) {
    resultMsg += `• Private Ban List: 🔴 BANNED\n`;
  }

  if (hasValidRoot) {
    resultMsg += `• Root Certificate: ✅ VALID GOOGLE ROOT\n`;
  } else if (hasKnownIntermediate) {
    resultMsg += `• Root Certificate: ⚠️ KNOWN INTERMEDIATE (not hardware root)\n`;
  } else {
    resultMsg += `• Root Certificate: ❌ UNKNOWN / INVALID\n`;
  }

  if (hasExpiredCert) {
    resultMsg += `\n• Keybox Expiry Status: ❌ EXPIRED / INVALID\n`;
    if (earliestExpiryDate) {
      resultMsg += `⌛ Keybox expired on: ${formatDate(earliestExpiryDate)}\n`;
    }
  } else {
    resultMsg += `\n• Keybox Expiry Status: ✅ VALID\n`;
    resultMsg += `⌛ Keybox expires on: ${formatDate(earliestExpiryDate)}\n`;
  }

  // Final verdict - only fail if revoked, privately banned, or expired
  resultMsg += `\n`;
  if (isRevoked || isPrivatelyBanned || hasExpiredCert) {
    resultMsg += `🔴 THIS KEYBOX CANNOT BE USED FOR STRONG INTEGRITY.\n`;
  } else if (hasValidRoot) {
    resultMsg += `🛡️ This keybox is clean and can be used for Strong Integrity (assuming local TEE setup is correct).\n`;
  } else if (hasKnownIntermediate) {
    resultMsg += `⚠️ This keybox uses a known Google intermediate. It MIGHT work for Strong Integrity, but is not hardware-backed.\n`;
  } else {
    resultMsg += `⚠️ This keybox has an unknown root. It MIGHT work for Strong Integrity, but is not guaranteed.\n`;
  }

  resultMsg += `\n\nNote: Sometimes Google bans a keybox without revoking it. This bot checks both Google's official CRL and a community-maintained private ban list.`;

  return resultMsg;
}

// ==========================================
// 6. BOT HANDLERS
// ==========================================
bot.onText(/\/start/, (msg) => {
  bot.sendMessage(msg.chat.id, "Welcome! Upload your keybox.xml file or paste its contents here to check its Google Attestation status.");
});

bot.on('document', async (msg) => {
  const chatId = msg.chat.id;
  const fileId = msg.document.file_id;

  async function fetchFileWithRetry(retries = 3) {
    for (let i = 0; i < retries; i++) {
      try {
        const fileLink = await bot.getFileLink(fileId);
        const response = await axios.get(fileLink, { responseType: 'text' });
        return response.data;
      } catch (err) {
        console.log(`Attempt ${i + 1} failed: ${err.message}`);
        if (i === retries - 1) throw err;
        await new Promise(resolve => setTimeout(resolve, 2000)); 
      }
    }
  }

  try {
    bot.sendMessage(chatId, "🔍 Analyzing Keybox against Google's Revocation List...");
    const fileContent = await fetchFileWithRetry();
    const report = await analyzeKeybox(fileContent);
    bot.sendMessage(chatId, report);
  } catch (err) {
    bot.sendMessage(chatId, `❌ Error reading keybox file after multiple attempts: ${err.message}`);
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
