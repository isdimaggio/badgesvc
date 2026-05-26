// totem.js
// Cross-platform: Linux / macOS / Windows
// Requires: npm install pcsclite
//
// Behavior:
// - CIE contactless: reads NIS from EF.ID_Servizi
// - CNS/TS contact: reads EF.ID_Carta
// - CNS/TS contactless: tries same path, otherwise falls back to local fingerprint
//
// Notes:
// - Windows: handles SCARD_W_RESET_CARD by reconnecting and retrying once.
// - Keeps the working CIE + CNS contact paths you already validated.

const pcsclite = require('pcsclite');
const crypto = require('crypto');

const pcsc = pcsclite();
const IS_WINDOWS = process.platform === 'win32';

function bufToHex(buf) {
  return buf ? buf.toString('hex').toUpperCase().replace(/(..)/g, '$1 ').trim() : '';
}

function isSwOk(resp) {
  if (!resp || resp.length < 2) return false;
  const sw1 = resp[resp.length - 2];
  const sw2 = resp[resp.length - 1];
  return sw1 === 0x90 && sw2 === 0x00;
}

function swToString(resp) {
  if (!resp || resp.length < 2) return '----';
  const sw1 = resp[resp.length - 2].toString(16).padStart(2, '0');
  const sw2 = resp[resp.length - 1].toString(16).padStart(2, '0');
  return `${sw1}${sw2}`.toUpperCase();
}

function logResp(label, data) {
  console.log(`[apdu] ${label} -> ${bufToHex(data)} | SW=${swToString(data)}`);
}

function sha256Hex(s) {
  return crypto.createHash('sha256').update(s).digest('hex').toUpperCase();
}

function detectCardMode(readerName, atrHexCompact) {
  if (atrHexCompact === '3B8F80018031806549544A344C120FFF82900085') {
    return 'CIE_CONTACTLESS';
  }
  if (atrHexCompact === '3B8B80010031C16408923354009000F3') {
    return 'CNS_CONTACTLESS';
  }
  if (atrHexCompact === '3BFF1800008131FE45006B05052000012101434E5310318079') {
    return 'CNS_CONTACT';
  }
  if (readerName.includes('Contactless')) return 'UNKNOWN_CONTACTLESS';
  return 'UNKNOWN_CONTACT';
}

function isResetCardError(err) {
  if (!err) return false;
  const msg = String(err.message || err);
  return msg.includes('0x80100068') || msg.includes('SCARD_W_RESET_CARD');
}

function connectReader(reader) {
  return new Promise((resolve, reject) => {
    const shareMode = reader.SCARD_SHARE_EXCLUSIVE ?? reader.SCARD_SHARE_SHARED;
    reader.connect({ share_mode: shareMode }, (err, protocol) => {
      if (err) return reject(err);
      resolve(protocol);
    });
  });
}

function disconnectReader(reader) {
  return new Promise((resolve) => {
    reader.disconnect(reader.SCARD_LEAVE_CARD, () => resolve());
  });
}

function rawTransmit(reader, protocol, apdu, label) {
  return new Promise((resolve, reject) => {
    reader.transmit(apdu, 0xff, protocol, (err, data) => {
      if (err) return reject(new Error(`${label}: ${err.message}`));
      resolve(data);
    });
  });
}

async function transmit(reader, protocolRef, apdu, label) {
  try {
    return await rawTransmit(reader, protocolRef.value, apdu, label);
  } catch (err) {
    if (!(IS_WINDOWS && isResetCardError(err))) throw err;

    console.log(`[pcsc] ${label}: Windows reset detected, reconnecting...`);

    await disconnectReader(reader);
    protocolRef.value = await connectReader(reader);

    return await rawTransmit(reader, protocolRef.value, apdu, `${label} (retry)`);
  }
}

async function tx(reader, protocolRef, apdu, label) {
  const data = await transmit(reader, protocolRef, apdu, label);
  logResp(label, data);
  return data;
}

/* =========================
   CIE: NIS / EF.ID_Servizi
   ========================= */

async function tryReadCieNis(reader, protocolRef) {
  const CIE_SELECT_IAS = Buffer.from([
    0x00, 0xA4, 0x04, 0x0C, 0x0D,
    0xA0, 0x00, 0x00, 0x00, 0x30, 0x80, 0x00, 0x00, 0x00, 0x09, 0x81, 0x60, 0x01
  ]);

  const CIE_SELECT_DF_ID_SERVIZI = Buffer.from([
    0x00, 0xA4, 0x04, 0x0C, 0x06,
    0xA0, 0x00, 0x00, 0x00, 0x00, 0x39
  ]);

  const CIE_READ_NIS = Buffer.from([0x00, 0xB0, 0x81, 0x00, 0x0C]);

  let r;

  // Try IAS path first
  r = await tx(reader, protocolRef, CIE_SELECT_IAS, 'CIE SELECT IAS');
  if (isSwOk(r)) {
    r = await tx(reader, protocolRef, CIE_SELECT_DF_ID_SERVIZI, 'CIE SELECT DF.ID_Servizi after IAS');
    if (isSwOk(r)) {
      r = await tx(reader, protocolRef, CIE_READ_NIS, 'CIE READ NIS after IAS');
      if (isSwOk(r)) {
        const data = r.slice(0, -2);
        const ascii = String.fromCharCode(...data);
        return /^[0-9]{8,20}$/.test(ascii) ? ascii : Array.from(data).join('');
      }
    }
  }

  // Keep the direct path that already works on your cards
  r = await tx(reader, protocolRef, CIE_SELECT_DF_ID_SERVIZI, 'CIE SELECT DF.ID_Servizi direct');
  if (!isSwOk(r)) throw new Error(`CIE direct DF.ID_Servizi ${swToString(r)}`);

  r = await tx(reader, protocolRef, CIE_READ_NIS, 'CIE READ NIS direct');
  if (!isSwOk(r)) throw new Error(`CIE READ NIS direct ${swToString(r)}`);

  const data = r.slice(0, -2);
  const ascii = String.fromCharCode(...data);
  return /^[0-9]{8,20}$/.test(ascii) ? ascii : Array.from(data).join('');
}

/* =========================
   CNS / TS contact: EF.ID_Carta
   ========================= */

async function tryReadCnsIdCarta(reader, protocolRef) {
  const SEL_MF_1 = Buffer.from([0x00,0xA4,0x00,0x0C,0x02,0x3F,0x00]);
  const SEL_MF_2 = Buffer.from([0x00,0xA4,0x00,0x00,0x02,0x3F,0x00]);

  const SEL_DF0_1 = Buffer.from([0x00,0xA4,0x00,0x0C,0x02,0x10,0x00]);
  const SEL_DF0_2 = Buffer.from([0x00,0xA4,0x00,0x00,0x02,0x10,0x00]);

  const SEL_EF_1 = Buffer.from([0x00,0xA4,0x00,0x0C,0x02,0x10,0x03]);
  const SEL_EF_2 = Buffer.from([0x00,0xA4,0x02,0x0C,0x02,0x10,0x03]);
  const SEL_EF_3 = Buffer.from([0x00,0xA4,0x00,0x00,0x02,0x10,0x03]);

  const READ16 = Buffer.from([0x00,0xB0,0x00,0x00,0x10]);

  let r;

  r = await tx(reader, protocolRef, SEL_MF_1, 'CNS SELECT MF #1');
  if (!isSwOk(r)) {
    r = await tx(reader, protocolRef, SEL_MF_2, 'CNS SELECT MF #2');
    if (!isSwOk(r)) throw new Error(`SELECT MF failed (${swToString(r)})`);
  }

  r = await tx(reader, protocolRef, SEL_DF0_1, 'CNS SELECT DF0 #1');
  if (!isSwOk(r)) {
    r = await tx(reader, protocolRef, SEL_DF0_2, 'CNS SELECT DF0 #2');
    if (!isSwOk(r)) throw new Error(`SELECT DF0 failed (${swToString(r)})`);
  }

  r = await tx(reader, protocolRef, SEL_EF_1, 'CNS SELECT EF.ID_Carta #1');
  if (!isSwOk(r)) r = await tx(reader, protocolRef, SEL_EF_2, 'CNS SELECT EF.ID_Carta #2');
  if (!isSwOk(r)) r = await tx(reader, protocolRef, SEL_EF_3, 'CNS SELECT EF.ID_Carta #3');
  if (!isSwOk(r)) throw new Error(`SELECT EF.ID_Carta failed (${swToString(r)})`);

  r = await tx(reader, protocolRef, READ16, 'CNS READ BINARY ID_Carta');
  if (!isSwOk(r)) throw new Error(`READ ID_Carta ${swToString(r)}`);

  const data = r.slice(0, -2);
  return String.fromCharCode(...data);
}

/* =========================
   CNS / TS contactless
   ========================= */

async function tryReadCnsContactless(reader, protocolRef, atrHexCompact) {
  try {
    const idCarta = await tryReadCnsIdCarta(reader, protocolRef);
    return {
      kind: 'CNS',
      uuid: idCarta,
      source: 'EF.ID_Carta'
    };
  } catch (err) {
    const fp = sha256Hex(`CNS_CONTACTLESS|${atrHexCompact}`).slice(0, 24);
    return {
      kind: 'CNS_FP',
      uuid: fp,
      source: 'ATR_FINGERPRINT_FALLBACK'
    };
  }
}

/* =========================
   Event loop
   ========================= */

const readerBusy = new Map();

pcsc.on('reader', (reader) => {
  console.log(`[pcsc] New reader: ${reader.name}`);
  readerBusy.set(reader.name, false);

  reader.on('error', (err) => {
    console.error(`[pcsc] Reader error (${reader.name}): ${err.message}`);
  });

  reader.on('end', () => {
    console.log(`[pcsc] Reader removed: ${reader.name}`);
    readerBusy.delete(reader.name);
  });

  reader.on('status', (status) => {
    const changes = reader.state ^ status.state;

    if (changes & reader.SCARD_STATE_PRESENT && status.state & reader.SCARD_STATE_PRESENT) {
      if (readerBusy.get(reader.name)) return;
      readerBusy.set(reader.name, true);

      const atrHexCompact = status.atr ? status.atr.toString('hex').toUpperCase() : '';
      const atrPretty = bufToHex(status.atr);
      const mode = detectCardMode(reader.name, atrHexCompact);

      console.log(`\n[+] Card detected on ${reader.name}`);
      console.log(`    ATR: ${atrPretty || 'n/a'}`);
      console.log(`    MODE: ${mode}`);

      connectReader(reader).then(async (protocol) => {
        const protocolRef = { value: protocol };

        try {
          if (mode === 'CIE_CONTACTLESS') {
            const nis = await tryReadCieNis(reader, protocolRef);
            console.log('FINAL UUID: CIE-' + nis);
            return;
          }

          if (mode === 'CNS_CONTACT') {
            const idCarta = await tryReadCnsIdCarta(reader, protocolRef);
            console.log('FINAL UUID: CNS-' + idCarta);
            return;
          }

          if (mode === 'CNS_CONTACTLESS') {
            const result = await tryReadCnsContactless(reader, protocolRef, atrHexCompact);
            console.log(`FINAL UUID: ${result.kind}-${result.uuid}`);
            console.log(`UUID SOURCE: ${result.source}`);
            return;
          }

          if (mode === 'UNKNOWN_CONTACTLESS') {
            try {
              const nis = await tryReadCieNis(reader, protocolRef);
              console.log('FINAL UUID: CIE-' + nis);
              return;
            } catch (_) {}

            const fp = sha256Hex(`UNKNOWN_CONTACTLESS|${atrHexCompact}`).slice(0, 24);
            console.log('FINAL UUID: FP-' + fp);
            console.log('UUID SOURCE: UNKNOWN_CONTACTLESS_FINGERPRINT');
            return;
          }

          if (mode === 'UNKNOWN_CONTACT') {
            try {
              const idCarta = await tryReadCnsIdCarta(reader, protocolRef);
              console.log('FINAL UUID: CNS-' + idCarta);
              return;
            } catch (_) {}

            const fp = sha256Hex(`UNKNOWN_CONTACT|${atrHexCompact}`).slice(0, 24);
            console.log('FINAL UUID: FP-' + fp);
            console.log('UUID SOURCE: UNKNOWN_CONTACT_FINGERPRINT');
            return;
          }

          console.log('FINAL UUID: UNKNOWN');
        } catch (e) {
          console.log(`[debug] ${mode} failed: ${e.message}`);
          console.log('FINAL UUID: UNKNOWN');
        } finally {
          await disconnectReader(reader);
          readerBusy.set(reader.name, false);
        }
      }).catch((err) => {
        console.error(`[pcsc] connect error on ${reader.name}: ${err.message}`);
        readerBusy.set(reader.name, false);
      });
    }

    if (changes & reader.SCARD_STATE_EMPTY && status.state & reader.SCARD_STATE_EMPTY) {
      console.log(`[pcsc] Card removed from ${reader.name}`);
    }
  });
});

pcsc.on('error', (err) => {
  console.error(`[pcsc] Global error: ${err.message}`);
});
