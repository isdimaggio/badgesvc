// totem.js
const pcsclite = require('pcsclite');
const crypto = require('crypto');

const pcsc = pcsclite();

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

function transmit(reader, protocol, apdu, label) {
  return new Promise((resolve, reject) => {
    reader.transmit(apdu, 0xff, protocol, (err, data) => {
      if (err) return reject(new Error(`${label}: ${err.message}`));
      resolve(data);
    });
  });
}

async function tx(reader, protocol, apdu, label) {
  const data = await transmit(reader, protocol, apdu, label);
  logResp(label, data);
  return data;
}

function sha256Hex(s) {
  return crypto.createHash('sha256').update(s).digest('hex').toUpperCase();
}

function detectCardMode(readerName, atrHexCompact) {
  // Based on your observed working ATRs from pcsc_scan/session
  // CIE contactless
  if (atrHexCompact === '3B8F80018031806549544A344C120FFF82900085') {
    return 'CIE_CONTACTLESS';
  }

  // TS/CNS contactless
  if (atrHexCompact === '3B8B80010031C16408923354009000F3') {
    return 'CNS_CONTACTLESS';
  }

  // TS/CNS contact
  if (atrHexCompact === '3BFF1800008131FE45006B05052000012101434E5310318079') {
    return 'CNS_CONTACT';
  }

  // Fallback by reader naming heuristic
  if (readerName.includes('Contactless')) return 'UNKNOWN_CONTACTLESS';
  return 'UNKNOWN_CONTACT';
}

/* =========================
   CIE: keep working logic
   ========================= */
async function tryReadCieNis(reader, protocol) {
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

  // First attempt: IAS then direct DF.ID_Servizi
  r = await tx(reader, protocol, CIE_SELECT_IAS, 'CIE SELECT IAS');
  if (isSwOk(r)) {
    r = await tx(reader, protocol, CIE_SELECT_DF_ID_SERVIZI, 'CIE SELECT DF.ID_Servizi after IAS');
    if (isSwOk(r)) {
      r = await tx(reader, protocol, CIE_READ_NIS, 'CIE READ NIS after IAS');
      if (isSwOk(r)) {
        const data = r.slice(0, -2);
        const ascii = String.fromCharCode(...data);
        return /^[0-9]{8,20}$/.test(ascii) ? ascii : Array.from(data).join('');
      }
    }
  }

  // Critical fallback: this is the path that works on your CIE
  r = await tx(reader, protocol, CIE_SELECT_DF_ID_SERVIZI, 'CIE SELECT DF.ID_Servizi direct');
  if (!isSwOk(r)) throw new Error(`CIE direct DF.ID_Servizi ${swToString(r)}`);

  r = await tx(reader, protocol, CIE_READ_NIS, 'CIE READ NIS direct');
  if (!isSwOk(r)) throw new Error(`CIE READ NIS direct ${swToString(r)}`);

  const data = r.slice(0, -2);
  const ascii = String.fromCharCode(...data);
  return /^[0-9]{8,20}$/.test(ascii) ? ascii : Array.from(data).join('');
}

/* =========================
   CNS/TS contact: keep working logic
   ========================= */
async function tryReadCnsIdCarta(reader, protocol) {
  const SEL_MF_1 = Buffer.from([0x00,0xA4,0x00,0x0C,0x02,0x3F,0x00]);
  const SEL_MF_2 = Buffer.from([0x00,0xA4,0x00,0x00,0x02,0x3F,0x00]);

  const SEL_DF0_1 = Buffer.from([0x00,0xA4,0x00,0x0C,0x02,0x10,0x00]);
  const SEL_DF0_2 = Buffer.from([0x00,0xA4,0x00,0x00,0x02,0x10,0x00]);

  const SEL_EF_1 = Buffer.from([0x00,0xA4,0x00,0x0C,0x02,0x10,0x03]);
  const SEL_EF_2 = Buffer.from([0x00,0xA4,0x02,0x0C,0x02,0x10,0x03]);
  const SEL_EF_3 = Buffer.from([0x00,0xA4,0x00,0x00,0x02,0x10,0x03]);

  const READ16 = Buffer.from([0x00,0xB0,0x00,0x00,0x10]);

  let r;

  r = await tx(reader, protocol, SEL_MF_1, 'CNS SELECT MF #1');
  if (!isSwOk(r)) {
    r = await tx(reader, protocol, SEL_MF_2, 'CNS SELECT MF #2');
    if (!isSwOk(r)) throw new Error(`SELECT MF failed (${swToString(r)})`);
  }

  r = await tx(reader, protocol, SEL_DF0_1, 'CNS SELECT DF0 #1');
  if (!isSwOk(r)) {
    r = await tx(reader, protocol, SEL_DF0_2, 'CNS SELECT DF0 #2');
    if (!isSwOk(r)) throw new Error(`SELECT DF0 failed (${swToString(r)})`);
  }

  r = await tx(reader, protocol, SEL_EF_1, 'CNS SELECT EF.ID_Carta #1');
  if (!isSwOk(r)) r = await tx(reader, protocol, SEL_EF_2, 'CNS SELECT EF.ID_Carta #2');
  if (!isSwOk(r)) r = await tx(reader, protocol, SEL_EF_3, 'CNS SELECT EF.ID_Carta #3');
  if (!isSwOk(r)) throw new Error(`SELECT EF.ID_Carta failed (${swToString(r)})`);

  r = await tx(reader, protocol, READ16, 'CNS READ BINARY ID_Carta');
  if (!isSwOk(r)) throw new Error(`READ ID_Carta ${swToString(r)}`);

  const data = r.slice(0, -2);
  return String.fromCharCode(...data);
}

/* =========================
   CNS/TS contactless:
   try same path, fallback locally
   ========================= */
async function tryReadCnsContactless(reader, protocol, atrHexCompact) {
  try {
    const idCarta = await tryReadCnsIdCarta(reader, protocol);
    return {
      kind: 'CNS',
      uuid: idCarta,
      source: 'EF.ID_Carta'
    };
  } catch (err) {
    // Temporary local fingerprint only for unresolved contactless TS/CNS path
    // Not a true card UUID; just avoids breaking the workflow.
    const fp = sha256Hex(`CNS_CONTACTLESS|${atrHexCompact}`).slice(0, 24);
    return {
      kind: 'CNS_FP',
      uuid: fp,
      source: 'ATR_FINGERPRINT_FALLBACK'
    };
  }
}

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

      reader.connect({ share_mode: reader.SCARD_SHARE_SHARED }, async (err, protocol) => {
        if (err) {
          console.error(`[pcsc] connect error on ${reader.name}: ${err.message}`);
          readerBusy.set(reader.name, false);
          return;
        }

        try {
          if (mode === 'CIE_CONTACTLESS') {
            const nis = await tryReadCieNis(reader, protocol);
            console.log('FINAL UUID: CIE-' + nis);
            return;
          }

          if (mode === 'CNS_CONTACT') {
            const idCarta = await tryReadCnsIdCarta(reader, protocol);
            console.log('FINAL UUID: CNS-' + idCarta);
            return;
          }

          if (mode === 'CNS_CONTACTLESS') {
            const result = await tryReadCnsContactless(reader, protocol, atrHexCompact);
            console.log(`FINAL UUID: ${result.kind}-${result.uuid}`);
            console.log(`UUID SOURCE: ${result.source}`);
            return;
          }

          // Unknown modes: best-effort routing
          if (mode === 'UNKNOWN_CONTACTLESS') {
            try {
              const nis = await tryReadCieNis(reader, protocol);
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
              const idCarta = await tryReadCnsIdCarta(reader, protocol);
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
          reader.disconnect(reader.SCARD_LEAVE_CARD, () => {
            readerBusy.set(reader.name, false);
          });
        }
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
