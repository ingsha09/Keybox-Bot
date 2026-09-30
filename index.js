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

const VALID_GOOGLE_ROOTS = [
    'Google Hardware Attestation Root',
    'Key Attestation CA1',
    'Droid CA1',
    'Droid CA2'
];

const KNOWN_GOOGLE_INTERMEDIATES = [
    'Google LLC',
    'Google'
];

async function fetchGoogleCRL() {
  try {
    const response = await axios.get(GOOGLE_CRL_URL, { timeout: 10000 });
    const data = typeof response.data === 'string' ? JSON.parse(response.data) : response.data;
    console.log(`Fetched Google CRL: ${Object.keys(data.entries).length} entries.`);
    return data;
  } catch (error) {
    console.error("Failed to fetch Google CRL:", error.message);
    return null;
  }
}

async function fetchPrivateBanList() {
  try {
    const response = await axios.get(PRIVATE_BAN_LIST_URL, { timeout: 10000 });
    const lines = response.data.split('\n');
    const banSet = new Set();
    for (const line of lines) {
        const serial = line.trim().toLowerCase();
        if (serial) banSet.add(serial);
    }
    console.log(`Loaded ${banSet.size} banned serials from private list.`);
    return banSet;
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
  
  const chains = [];
  
  const findKeys = (node, results) => {
    if (Array.isArray(node)) {
      node.forEach(item => findKeys(item, results));
    } else if (typeof node === 'object' && node !== null) {
      if (node.CertificateChain !== undefined) {
        results.push(node);
      }
      for (const key in node) {
        findKeys(node[key], results);
      }
    }
  };
  
  const keyBlocks = [];
  findKeys(jsonObj, keyBlocks);
  
  keyBlocks.forEach((keyBlock) => {
    const certs = [];
    const algorithm = keyBlock['@_algorithm'] || 'unknown';
    const chain = keyBlock.CertificateChain;
    
    const extractFromChain = (node) => {
      if (!node) return;
      
      if (Array.isArray(node)) {
        node.forEach(item => extractFromChain(item));
        return;
      }
      
      if (typeof node === 'object') {
        if (node['#text'] && typeof node['#text'] === 'string') {
          const text = node['#text'];
          if (text.includes('-----BEGIN CERTIFICATE-----') || 
              (text.length > 200 && /^[A-Za-z0-9+/=\s]+$/.test(text))) {
            certs.push(text);
            return;
          }
        }
        
        for (const key in node) {
          extractFromChain(node[key]);
        }
      }
    };
    
    extractFromChain(chain);
    
    if (certs.length > 0) {
      chains.push({ algorithm, certs });
    }
  });
  
  // Fallback: extract all certs as one chain
  if (chains.length === 0) {
    const allCerts = [];
    const extractAll = (node) => {
      if (typeof node === 'string') {
        if (node.includes('-----BEGIN CERTIFICATE-----') || (node.length > 200 && /^[A-Za-z0-9+/=\s]+$/.test(node))) {
          allCerts.push(node);
        }
      } else if (Array.isArray(node)) {
        node.forEach(item => extractAll(item));
      } else if (typeof node === 'object' && node !== null) {
        for (const key in node) {
          extractAll(node[key]);
        }
      }
    };
    extractAll(jsonObj);
    if (allCerts.length > 0) {
      chains.push({ algorithm: 'unknown', certs: allCerts });
    }
  }
  
  return chains;
}

function formatDate(date) {
    if (!date) return 'Unknown';
    try {
        return date.toLocaleDateString('en-GB');
    } catch (e) {
        return 'Invalid Date';
    }
}

function getSerialVariants(cert) {
    const variants = new Set();
    try {
        let rawSerial = cert.serialNumber.toString().toLowerCase().replace(/^0x/, '');
        variants.add(rawSerial);
        
        if (/^\d+$/.test(rawSerial)) {
            try {
                const hex = BigInt(rawSerial).toString(16);
                variants.add(hex);
                variants.add(hex.replace(/^0+/, ''));
            } catch (e) { /* Ignore */ }
        } else if (/^[0-9a-f]+$/.test(rawSerial)) {
            try {
                const decimal = BigInt('0x' + rawSerial).toString();
                variants.add(decimal);
            } catch (e) { /* Ignore */ }
        }
        
        let hexSerial = cert.serialNumber.toString(16).toLowerCase().replace(/^0x/, '');
        if (hexSerial && hexSerial !== rawSerial) {
            variants.add(hexSerial);
            variants.add(hexSerial.replace(/^0+/, ''));
        }
    } catch (e) {
        console.error("Error generating serial variants:", e.message);
    }
    return Array.from(variants);
}

function getSubjectSerials(cert) {
    const candidates = new Set();
    
    try {
        const dnString = cert.subjectName ? cert.subjectName.toString() : '';
        
        const patterns = [
            /serialNumber\s*=\s*([0-9a-fA-F]+)/i,
            /2\.5\.4\.5\s*=\s*([0-9a-fA-F]+)/i
        ];
        
        for (const pattern of patterns) {
            const match = dnString.match(pattern);
            if (match && match[1]) {
                const val = match[1].toLowerCase();
                candidates.add(val);
                candidates.add(val.replace(/^0+/, ''));
                candidates.add(val.replace(/^04/, ''));
            }
        }
    } catch (e) { /* Ignore */ }
    
    try {
        const subject = cert.subjectName;
        if (subject) {
            for (const name of ['serialNumber', 'SERIALNUMBER', '2.5.4.5']) {
                try {
                    const fields = subject.getField(name);
                    if (fields && fields.length > 0) {
                        for (const field of fields) {
                            let val = '';
                            if (typeof field.value === 'string') {
                                val = field.value;
                            } else if (field.value instanceof ArrayBuffer) {
                                val = Buffer.from(field.value).toString('utf-8');
                            } else if (field.value) {
                                val = field.value.toString();
                            }
                            val = val.trim().toLowerCase();
                            if (val && /^[0-9a-f]+$/.test(val)) {
                                candidates.add(val);
                                candidates.add(val.replace(/^0+/, ''));
                                candidates.add(val.replace(/^04/, ''));
                            }
                        }
                    }
                } catch (e) { /* Try next name */ }
            }
        }
    } catch (e) { /* Ignore */ }
    
    try {
        const skiExt = cert.extensions.find(e => e.type === '2.5.29.14');
        if (skiExt) {
            let rawHex = Buffer.from(skiExt.value).toString('hex').toLowerCase();
            if (rawHex.startsWith('0414')) rawHex = rawHex.substring(4);
            if (rawHex) {
                candidates.add(rawHex);
                candidates.add(rawHex.replace(/^0+/, ''));
            }
        }
    } catch (e) { /* Ignore */ }
    
    return Array.from(candidates);
}

// ==========================================
// 5. MAIN ANALYSIS FUNCTION
// ==========================================
async function analyzeKeybox(xmlContent, fileName = null) {
  let chains;
  try {
    chains = parseKeybox(xmlContent);
  } catch (e) {
    return "❌ Invalid Keybox XML File: Could not parse certificates.";
  }

  if (chains.length === 0) {
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
  let hasValidRoot = false;
  let hasKnownIntermediate = false;
  let rootClassification = 'unknown';

  let resultMsg = `📁 Keybox Analysis Report\n`;
  if (fileName) {
    resultMsg += `📄 File: ${fileName}\n`;
  }
  resultMsg += `\n`;
  
  const totalCerts = chains.reduce((sum, c) => sum + c.certs.length, 0);
  resultMsg += `• Total Chains Found: ${chains.length}\n`;
  resultMsg += `• Total Certs Found: ${totalCerts}\n`;
  chains.forEach((chain, idx) => {
      resultMsg += `  • Chain ${idx + 1} (${chain.algorithm.toUpperCase()}): ${chain.certs.length} certs\n`;
  });
  resultMsg += `\n`;

  for (let chainIdx = 0; chainIdx < chains.length; chainIdx++) {
    const chain = chains[chainIdx];
    const chainCerts = chain.certs;
    
    const parsedCerts = [];
    chainCerts.forEach((rawCert, index) => {
      try {
        const pemString = formatCertificate(rawCert);
        const cert = new X509Certificate(pemString);
        parsedCerts.push({ index, cert, isRoot: index === chainCerts.length - 1 });
      } catch (e) {
        console.error(`Error parsing cert ${index} in chain ${chainIdx}:`, e.message);
      }
    });
    
    if (parsedCerts.length === 0) continue;
    
    const totalCertsInChain = parsedCerts.length;
    
    const chainStatus = {
        hasRevoked: false,
        hasExpired: false
    };
    
    parsedCerts.forEach(({ cert }) => {
        const notAfter = cert.notAfter;
        if (!notAfter || new Date() > notAfter) {
            chainStatus.hasExpired = true;
        }
        
        const serialVariants = getSerialVariants(cert);
        for (const variant of serialVariants) {
            if (crlData.entries[variant] && crlData.entries[variant].status === 'REVOKED') {
                chainStatus.hasRevoked = true;
                break;
            }
        }
    });
    
    resultMsg += `--- Chain ${chainIdx + 1} (${chain.algorithm.toUpperCase()}) ---\n\n`;
    
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

      const serialVariants = getSerialVariants(cert);
      const primarySerial = serialVariants[0];
      
      const subjectSerials = getSubjectSerials(cert);
      const primarySubjectSerial = subjectSerials.length > 0 ? subjectSerials[0] : 'Not Found';

      let revoked = false;
      let revokeReason = '';
      
      for (const variant of serialVariants) {
          if (crlData.entries[variant]) {
              const entry = crlData.entries[variant];
              if (entry.status === 'REVOKED') {
                  revoked = true;
                  revokeReason = entry.reason || 'Unknown';
                  isRevoked = true;
                  break;
              }
          }
      }

      let privatelyBanned = false;
      if (banList) {
          for (const variant of serialVariants) {
              if (banList.has(variant)) {
                  privatelyBanned = true;
                  isPrivatelyBanned = true;
                  break;
              }
          }
          if (!privatelyBanned) {
              for (const subjSerial of subjectSerials) {
                  if (banList.has(subjSerial)) {
                      privatelyBanned = true;
                      isPrivatelyBanned = true;
                      break;
                  }
              }
          }
      }

      let rootStatus = '';
      if (isRoot) {
          const subjectName = cert.subjectName ? cert.subjectName.toString() : '';
          const issuerName = cert.issuerName ? cert.issuerName.toString() : '';
          const subjectTrimmed = subjectName.trim();
          
          let isKnownRoot = false;
          for (const validRoot of VALID_GOOGLE_ROOTS) {
              if (subjectName.includes(validRoot)) {
                  isKnownRoot = true;
                  break;
              }
          }
          
          const isTeeRoot = /^SERIALNUMBER=[0-9a-f]+$/i.test(subjectTrimmed) || 
                           /^2\.5\.4\.5=[0-9a-f]+$/i.test(subjectTrimmed);
          const isTeeIntermediate = /\bT=TEE\b/i.test(subjectName);
          const isSelfSigned = subjectTrimmed === issuerName.trim();
          
          if (chainStatus.hasRevoked) {
              rootClassification = 'chain-broken';
              rootStatus = `❌ Unknown root certificate due to revocation of a certificate\n`;
          } else if (chainStatus.hasExpired) {
              rootClassification = 'chain-broken';
              rootStatus = `❌ Unknown root certificate due to expiration of a certificate\n`;
          } else if (isKnownRoot) {
              rootClassification = 'valid-google-root';
              hasValidRoot = true;
              rootStatus = `✅ Google hardware attestation root certificate\n`;
          } else if (isTeeRoot && isSelfSigned && totalCertsInChain > 1) {
              rootClassification = 'valid-google-root';
              hasValidRoot = true;
              rootStatus = `✅ Google hardware attestation root certificate\n`;
          } else if (isTeeRoot && isSelfSigned && totalCertsInChain === 1) {
              rootClassification = 'custom-root';
              rootStatus = `ℹ️ Custom/self-signed root certificate\n`;
          } else if (isTeeIntermediate) {
              rootClassification = 'custom-root';
              hasKnownIntermediate = true;
              rootStatus = `ℹ️ Known Google Intermediate (not hardware root)\n`;
          } else {
              let foundGoogle = false;
              for (const intermediate of KNOWN_GOOGLE_INTERMEDIATES) {
                  if (subjectName.includes(intermediate)) {
                      rootClassification = 'custom-root';
                      hasKnownIntermediate = true;
                      rootStatus = `ℹ️ Known Google Intermediate (not hardware root)\n`;
                      foundGoogle = true;
                      break;
                  }
              }
              
              if (!foundGoogle) {
                  rootClassification = 'custom-root';
                  rootStatus = `ℹ️ Custom/self-signed root certificate\n`;
              }
          }
      }

      let certMsg = `🔐 Certificate ${index} Serial: ${primarySerial}\n`;
      certMsg += `ℹ️ Subject Serial: ${primarySubjectSerial}\n`;
      certMsg += `📅 Valid from: ${formatDate(notBefore)} to: ${formatDate(notAfter)}\n`;
      
      if (isExpired) certMsg += `❌ Expired certificate\n`;
      else if (isNotYetValid) certMsg += `❌ Certificate not yet valid\n`;
      else certMsg += `✅ Certificate within validity period\n`;

      if (revoked) {
        certMsg += `❌ Serial number found in Google's revoked keybox list\n`;
        certMsg += `🔍 Reason: ${revokeReason}\n`;
      } else if (privatelyBanned) {
        certMsg += `❌ This subject serial number is banned (private list).\n`;
      } else {
        certMsg += `✅ Serial number not found in Google's revoked keybox list\n`;
      }

      if (rootStatus) certMsg += rootStatus;

      resultMsg += certMsg + `\n`;
    });
  }

  resultMsg += `--- Summary ---\n`;

  const isDefinitelyBad = isRevoked || isPrivatelyBanned || hasExpiredCert;

  if (isRevoked) {
    resultMsg += `• Google Revocation Status: 🔴 REVOKED\n`;
    resultMsg += `🔍 This keybox has been officially revoked by Google.\n`;
  } else if (isPrivatelyBanned) {
    resultMsg += `• Private Ban List: 🔴 BANNED\n`;
    resultMsg += `🔍 This keybox is on the community ban list.\n`;
  } else if (hasExpiredCert) {
    resultMsg += `• Certificate Status: ❌ EXPIRED\n`;
    if (earliestExpiryDate) {
      resultMsg += `⌛ Expired on: ${formatDate(earliestExpiryDate)}\n`;
    }
  } else {
    resultMsg += `• Google Revocation Status: 🟢 NOT REVOKED\n`;
    resultMsg += `• Private Ban List: 🟢 NOT BANNED\n`;
    if (rootClassification === 'valid-google-root') {
      resultMsg += `• Root Certificate: ✅ VALID GOOGLE ROOT\n`;
    } else if (hasKnownIntermediate) {
      resultMsg += `• Root Certificate: ℹ️ KNOWN GOOGLE INTERMEDIATE\n`;
    } else {
      resultMsg += `• Root Certificate: ℹ️ CUSTOM / SELF-SIGNED\n`;
    }
    resultMsg += `⌛ Keybox expires on: ${formatDate(earliestExpiryDate)}\n`;
  }

  const cryptographicallyValid = !isRevoked && !hasExpiredCert;
  const basicPasses  = cryptographicallyValid;
  const devicePasses = cryptographicallyValid;
  const strongPasses = cryptographicallyValid && !isPrivatelyBanned && (hasValidRoot || hasKnownIntermediate);
  
  resultMsg += `\n--- Integrity Predictions ---\n`;
  resultMsg += basicPasses
    ? `✅ MEETS_BASIC_INTEGRITY: Expected to pass\n`
    : `❌ MEETS_BASIC_INTEGRITY: Expected to fail\n`;
  resultMsg += devicePasses
    ? `✅ MEETS_DEVICE_INTEGRITY: Expected to pass\n`
    : `❌ MEETS_DEVICE_INTEGRITY: Expected to fail\n`;
  resultMsg += strongPasses
    ? `✅ MEETS_STRONG_INTEGRITY: Expected to pass\n`
    : `❌ MEETS_STRONG_INTEGRITY: Expected to fail\n`;

  resultMsg += `\n`;
  if (isDefinitelyBad) {
    resultMsg += `🔴 THIS KEYBOX CANNOT BE USED FOR STRONG INTEGRITY.\n`;
  } else {
    resultMsg += `🟢 This keybox CAN be used for Strong Integrity.\n`;
  }

  resultMsg += `\n⚠️ Note: Sometimes Google bans a keybox without revoking it, so no bot can detect that ban. This bot checks both Google's official CRL and a community-maintained private ban list.`;

  return resultMsg;
}

// ==========================================
// 6. HELPER: Process and reply
// ==========================================
async function processKeybox(chatId, xmlContent, statusMessageId = null, fileName = null) {
    let messageId = statusMessageId;
    if (!messageId) {
        const statusMsg = await bot.sendMessage(chatId, "🔍 Analyzing Keybox against Google's Revocation List...");
        messageId = statusMsg.message_id;
    }
    
    try {
        const report = await analyzeKeybox(xmlContent, fileName);
        
        try {
            await bot.editMessageText(report, {
                chat_id: chatId,
                message_id: messageId
            });
        } catch (editErr) {
            console.log(`Failed to edit message, sending new one: ${editErr.message}`);
            await bot.sendMessage(chatId, report);
        }
    } catch (err) {
        const errorMsg = `❌ Error analyzing keybox: ${err.message}`;
        try {
            await bot.editMessageText(errorMsg, {
                chat_id: chatId,
                message_id: messageId
            });
        } catch (editErr) {
            await bot.sendMessage(chatId, errorMsg);
        }
    }
}

// ==========================================
// 7. COMMAND HANDLERS
// ==========================================
bot.onText(/\/start/, (msg) => {
    const chatId = msg.chat.id;
    const isGroup = msg.chat.type === 'group' || msg.chat.type === 'supergroup';
    
    if (isGroup) {
        bot.sendMessage(chatId, 
`🤖 *Keybox Checker Bot* is ready.

Upload a \`keybox.xml\` file and I'll analyze it against Google's CRL and the community ban list.

Use /help for details.`,
            { parse_mode: 'Markdown' });
        return;
    }
    
    const text = 
`👋 *Welcome to Keybox Checker Bot!*

I analyze Android keybox XML files and check them against:
• Google's Certificate Revocation List (CRL)
• A community-maintained private ban list
• Certificate expiration dates
• Full chain trust validation

📄 *How to use:*
Just upload your \`keybox.xml\` file, or paste the raw XML contents directly in the chat.

Use /help for detailed information about what I check and my limitations.`;

    bot.sendMessage(chatId, text, {
        parse_mode: 'Markdown',
        reply_markup: {
            inline_keyboard: [
                [{ text: '📖 Help / FAQ', callback_data: 'help' }],
                [{ text: 'ℹ️ About', callback_data: 'about' }],
                [{ text: '📊 Status', callback_data: 'status' }]
            ]
        }
    });
});

bot.onText(/\/help/, (msg) => {
    const chatId = msg.chat.id;
    const text = 
`📖 *Help & FAQ*

*What is a keybox?*
A keybox is an XML file containing cryptographic certificates used to pass Google Play Integrity's checks on Android devices.

*How do I check one?*
Upload a \`keybox.xml\` file or paste the raw XML content. I'll analyze every certificate in every chain.

*What do you check?*
✅ *Google CRL* – Official list of revoked keyboxes
✅ *Private Ban List* – Community-maintained list of unofficially banned keyboxes
✅ *Expiration Dates* – Whether any certificate in the chain has expired
✅ *Chain Trust* – Whether the full chain validates end-to-end

*What do the results mean?*
🟢 *CAN BE USED* – Not revoked, not banned, not expired
🔴 *CANNOT BE USED* – Revoked, banned, or expired

*Integrity Predictions:*
• *Basic/Device* – Pass unless the keybox is revoked or expired
• *Strong* – Requires a valid, unrevoked, unbanned, unexpired keybox with a Google root

*Limitations*
• Google sometimes bans keyboxes *without* revoking them. No bot can detect these bans.
• Predictions are based on public data and real-world behavior — actual results may vary.

*Commands*
/start /help /about /status /source`;

    bot.sendMessage(chatId, text, { parse_mode: 'Markdown' });
});

bot.onText(/\/about/, (msg) => {
    const chatId = msg.chat.id;
    const text = 
`ℹ️ *About Keybox Checker Bot*

A free, community-oriented tool to help you verify the status of Android keybox XML files.

*Version:* 1.0

*Disclaimer:*
This bot does not store your files or any personal data. All analysis is done in-memory and discarded immediately after the report is sent.

*Not affiliated with Google or Android.*

Use /help for usage instructions.`;

    bot.sendMessage(chatId, text, { parse_mode: 'Markdown' });
});

bot.onText(/\/status/, async (msg) => {
    const chatId = msg.chat.id;
    const statusMsg = await bot.sendMessage(chatId, "⏳ Checking system status...");
    
    try {
        const startTime = Date.now();
        const crl = await fetchGoogleCRL();
        const banList = await fetchPrivateBanList();
        const elapsed = Date.now() - startTime;
        
        const crlOk = crl && crl.entries && Object.keys(crl.entries).length > 0;
        const banListOk = banList && banList.size > 0;
        
        let text = `📊 *System Status*\n\n`;
        text += `🟢 *Bot*: Online\n`;
        text += `⏱️ *Response Time*: ${elapsed}ms\n\n`;
        text += `*Data Sources:*\n`;
        text += crlOk ? `✅ Google CRL: ${Object.keys(crl.entries).length} entries\n` : `❌ Google CRL: Unreachable\n`;
        text += banListOk ? `✅ Private Ban List: ${banList.size} serials\n` : `❌ Private Ban List: Unreachable\n`;
        text += `\n${crlOk && banListOk ? '🟢 All systems operational.' : '🟡 Partial service — some checks may fail.'}`;
        
        bot.editMessageText(text, {
            chat_id: chatId,
            message_id: statusMsg.message_id,
            parse_mode: 'Markdown'
        });
    } catch (err) {
        bot.editMessageText(`❌ Status check failed: ${err.message}`, {
            chat_id: chatId,
            message_id: statusMsg.message_id
        });
    }
});

bot.onText(/\/source/, (msg) => {
    bot.sendMessage(msg.chat.id, 
`📚 *Data Sources*

The bot checks two independent lists on every request:

1️⃣ *Google's Official CRL*
\`https://android.googleapis.com/attestation/status\`

2️⃣ *Community Ban List*
\`https://raw.githubusercontent.com/daboynb/autojson/refs/heads/main/banned.txt\`

Both are fetched fresh — no caching — so results reflect the latest published data.

Credits: @antezero for maintaining the community ban list.`,
        { parse_mode: 'Markdown' });
});

bot.on('callback_query', async (query) => {
    const chatId = query.message.chat.id;
    const data = query.data;
    
    let text = '';
    if (data === 'help') {
        text = `📖 Use /help for the full guide.`;
    } else if (data === 'about') {
        text = `ℹ️ Use /about for details about this bot.`;
    } else if (data === 'status') {
        text = `📊 Use /status to check system health.`;
    }
    
    bot.answerCallbackQuery(query.id, { text: 'Opening...' });
    if (text) bot.sendMessage(chatId, text);
});

// ==========================================
// 8. FILE & TEXT HANDLERS
// ==========================================
bot.on('document', async (msg) => {
  const chatId = msg.chat.id;
  const fileId = msg.document.file_id;
  const fileName = msg.document.file_name || '';
  const lowerName = fileName.toLowerCase();

  // Only process files that look like keybox XML files.
  // Silently ignore everything else (ZIPs, APKs, images, PDFs, etc.).
  const isXmlFile = lowerName.endsWith('.xml');
  const hasKeyboxInName = lowerName.includes('keybox');

  if (!isXmlFile && !hasKeyboxInName) {
    return; // Silent ignore
  }

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
    const statusMsg = await bot.sendMessage(chatId, "🔍 Analyzing Keybox against Google's Revocation List...");
    const fileContent = await fetchFileWithRetry();
    await processKeybox(chatId, fileContent, statusMsg.message_id, fileName);
  } catch (err) {
    bot.sendMessage(chatId, `❌ Error reading keybox file after multiple attempts: ${err.message}`);
  }
});

bot.on('text', async (msg) => {
  if (msg.text.startsWith('/')) return;
  if (msg.text.includes('<?xml') || msg.text.includes('<Keybox') || msg.text.includes('<AndroidAttestation')) {
    const statusMsg = await bot.sendMessage(msg.chat.id, "🔍 Analyzing Keybox XML...");
    await processKeybox(msg.chat.id, msg.text, statusMsg.message_id, 'Pasted XML');
  }
});

// ==========================================
// 9. EXPLICITLY DO NOTHING ON NEW MEMBERS
// ==========================================
// This is a safeguard: even if a handler for this event is
// accidentally added in the future, this one prevents any
// unwanted greeting messages in group chats.
bot.on('new_chat_members', () => {
    // Intentionally empty — do not greet new members
});
