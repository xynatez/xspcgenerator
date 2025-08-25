// XSPC-256 Frontend Implementation (per paper spec):
// - Salt 16B
// - PBKDF2-HMAC-SHA256 (100k) -> 256-bit key
// - XOR preprocessing with deterministic HMAC-DRBG stream
// - AES-GCM (IV 12B, tag 128-bit)
// - Dummy insertion (ratio ≈ 0.15), seeded deterministically
// - CRC32 over ciphertext (before dummies)
// - Packaging: salt(16) | iv(12) | count(2) | pos(2*count) | crc32(4) | ct_with_dummies, then Base64URL

// ---------- UI wiring ----------
const $ = (sel) => document.querySelector(sel);

const tabs = document.querySelectorAll('.tab');
tabs.forEach(btn => {
  btn.addEventListener('click', () => {
    tabs.forEach(b => { b.classList.remove('active'); b.setAttribute('aria-selected','false'); });
    document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
    btn.classList.add('active'); btn.setAttribute('aria-selected','true');
    const target = btn.getAttribute('data-target');
    if (target) document.querySelector(target).classList.add('active');
  });
});

$('#btn-clear-enc').addEventListener('click', () => {
  $('#enc-token').value = '';
  $('#enc-pass').value = '';
  $('#enc-out').value = '';
});

$('#btn-clear-dec').addEventListener('click', () => {
  $('#dec-blob').value = '';
  $('#dec-pass').value = '';
  $('#dec-out').value = '';
});

$('#btn-copy-enc').addEventListener('click', () => {
  const v = $('#enc-out').value.trim();
  if (!v) return;
  navigator.clipboard.writeText(v);
});

$('#btn-copy-dec').addEventListener('click', () => {
  const v = $('#dec-out').value;
  if (!v) return;
  navigator.clipboard.writeText(v);
});

$('#btn-download-enc').addEventListener('click', () => {
  const v = $('#enc-out').value.trim();
  if (!v) return;
  const blob = new Blob([v], {type: 'text/plain'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'ciphertext.xspc';
  a.click();
  URL.revokeObjectURL(url);
});

$('#btn-encrypt').addEventListener('click', async () => {
  try {
    const token = $('#enc-token').value;
    const pass = $('#enc-pass').value;
    if (pass.length === 0) throw new Error('Passphrase kosong.');
    const out = await XSPC256.encrypt(token, pass);
    $('#enc-out').value = out;
  } catch (e) {
    $('#enc-out').value = 'Error: ' + (e && e.message ? e.message : String(e));
    console.error(e);
  }
});

$('#btn-decrypt').addEventListener('click', async () => {
  try {
    const blob = $('#dec-blob').value;
    const pass = $('#dec-pass').value;
    if (pass.length === 0) throw new Error('Passphrase kosong.');
    const out = await XSPC256.decrypt(blob, pass);
    $('#dec-out').value = out;
  } catch (e) {
    $('#dec-out').value = 'Error: ' + (e && e.message ? e.message : String(e));
    console.error(e);
  }
});

// ---------- Crypto utils ----------

const DUMMY_RATIO = 0.15;

const te = new TextEncoder();
const td = new TextDecoder();

function concatU8(...arrs) {
  const len = arrs.reduce((a,b)=>a+b.length, 0);
  const out = new Uint8Array(len);
  let off = 0;
  for (const a of arrs) { out.set(a, off); off += a.length; }
  return out;
}

function u32ToBE(n) {
  return new Uint8Array([ (n>>>24)&255, (n>>>16)&255, (n>>>8)&255, n&255 ]);
}
function u16ToBE(n) {
  return new Uint8Array([ (n>>>8)&255, n&255 ]);
}
function beToU16(bytes, off) {
  return (bytes[off]<<8) | bytes[off+1];
}
function beToU32(bytes, off) {
  return (bytes[off]<<24) | (bytes[off+1]<<16) | (bytes[off+2]<<8) | bytes[off+3];
}

function base64UrlEncode(u8) {
  let bin = '';
  const chunk = 0x8000;
  for (let i=0; i<u8.length; i+=chunk) {
    bin += String.fromCharCode.apply(null, u8.subarray(i, i+chunk));
  }
  const b64 = btoa(bin).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
  return b64;
}

function base64UrlDecodeToU8(str) {
  const clean = (str || '').replace(/\s+/g,'').replace(/-/g,'+').replace(/_/g,'/');
  const pad = clean.length % 4 === 2 ? '==' : (clean.length % 4 === 3 ? '=' : '');
  const b64 = clean + pad;
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i=0; i<bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function sha256(bytes) {
  const h = await crypto.subtle.digest('SHA-256', bytes);
  return new Uint8Array(h);
}

async function importHmacKey(raw) {
  return await crypto.subtle.importKey('raw', raw, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
}
async function hmacSha256(keyRaw, data) {
  const key = await importHmacKey(keyRaw);
  const sig = await crypto.subtle.sign('HMAC', key, data);
  return new Uint8Array(sig);
}

// HMAC-DRBG (NIST SP 800-90A style), init with seed, output `length` bytes
async function hmacDRBG(seed, length) {
  let K = new Uint8Array(32); // 0x00 * 32
  let V = new Uint8Array(32); V.fill(0x01);
  // Update with seed (0x00 || seed)
  K = await hmacSha256(K, concatU8(V, new Uint8Array([0x00]), seed));
  V = await hmacSha256(K, V);
  // Update with seed (0x01 || seed)
  K = await hmacSha256(K, concatU8(V, new Uint8Array([0x01]), seed));
  V = await hmacSha256(K, V);
  // Generate
  const out = new Uint8Array(length);
  let off = 0;
  while (off < length) {
    V = await hmacSha256(K, V);
    const take = Math.min(V.length, length - off);
    out.set(V.subarray(0, take), off);
    off += take;
  }
  return out;
}

function xorProcess(a, b) {
  const out = new Uint8Array(a.length);
  for (let i=0; i<a.length; i++) out[i] = a[i] ^ b[i];
  return out;
}

function crc32(bytes) {
  // Standard CRC32 (IEEE 802.3)
  let c = 0 ^ (-1);
  for (let i=0;i<bytes.length;i++) {
    c = (c ^ bytes[i]) >>> 0;
    for (let k=0;k<8;k++) {
      const mask = -(c & 1);
      c = (c >>> 1) ^ (0xEDB88320 & mask);
    }
  }
  return (c ^ (-1)) >>> 0;
}

async function deriveKeyAndBytes(passphrase, salt) {
  const baseKey = await crypto.subtle.importKey('raw', te.encode(passphrase), {name:'PBKDF2'}, false, ['deriveKey']);
  const aesKey = await crypto.subtle.deriveKey(
    {name:'PBKDF2', salt, iterations: 100000, hash: 'SHA-256'},
    baseKey, {name:'AES-GCM', length: 256}, true, ['encrypt','decrypt']
  );
  const raw = new Uint8Array(await crypto.subtle.exportKey('raw', aesKey));
  return { aesKey, raw };
}

async function generateDummyPositions(length, seed) {
  // length bytes -> we create length*4 PRNG bytes to get length 32-bit draws
  const pr = await hmacDRBG(seed, length * 4);
  const posSet = new Set();
  for (let i=0; i<=pr.length-4; i+=4) {
    const v = (pr[i]<<24 | pr[i+1]<<16 | pr[i+2]<<8 | pr[i+3]) >>> 0;
    const val = v / 0xFFFFFFFF;
    if (val < DUMMY_RATIO) {
      let pos = Math.floor(val * length / DUMMY_RATIO);
      if (pos >= length) pos = length - 1;
      posSet.add(pos);
    }
  }
  const arr = Array.from(posSet.values()).sort((a,b)=>a-b);
  return arr;
}

function insertDummies(data, positions) {
  const out = new Uint8Array(data.length + positions.length);
  let j = 0, p = 0;
  for (let i=0; i<out.length; i++) {
    if (p < positions.length && positions[p] === j) {
      // insert one random dummy byte
      out[i] = crypto.getRandomValues(new Uint8Array(1))[0];
      p++;
    } else {
      out[i] = data[j++];
    }
  }
  return out;
}

function removeDummies(data, positions) {
  const pos = positions.slice().sort((a,b)=>b-a); // reverse
  const arr = Array.from(data);
  for (const p of pos) {
    if (p >= 0 && p < arr.length) arr.splice(p, 1);
  }
  return new Uint8Array(arr);
}

// ---------- XSPC-256 main ----------
const XSPC256 = {
  async encrypt(plaintext, passphrase) {
    const tokenBytes = te.encode(plaintext);
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const { aesKey, raw } = await deriveKeyAndBytes(passphrase, salt);

    const prngSeed = await sha256(concatU8(raw, te.encode('xspc256-prng-seed')));
    const prng = await hmacDRBG(prngSeed, tokenBytes.length);
    const pre = xorProcess(tokenBytes, prng);

    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ctBuf = await crypto.subtle.encrypt({name:'AES-GCM', iv}, aesKey, pre);
    const ct = new Uint8Array(ctBuf);

    const dummySeed = await sha256(concatU8(raw, iv, te.encode('xspc256-dummy-seed')));
    const positions = await generateDummyPositions(ct.length, dummySeed);
    const ctWithDummies = insertDummies(ct, positions);

    const sum = crc32(ct);

    // package
    const count = u16ToBE(positions.length);
    const posBytes = new Uint8Array(positions.length * 2);
    for (let i=0; i<positions.length; i++) {
      posBytes.set(u16ToBE(positions[i]), i*2);
    }
    const blob = concatU8(
      salt,
      iv,
      count,
      posBytes,
      u32ToBE(sum),
      ctWithDummies
    );
    return base64UrlEncode(blob);
  },

  async decrypt(b64Blob, passphrase) {
    const data = base64UrlDecodeToU8(b64Blob);
    if (data.length < 16+12+2+4) throw new Error('Blob terlalu pendek.');
    let off = 0;
    const salt = data.subarray(off, off+16); off += 16;
    const iv = data.subarray(off, off+12); off += 12;
    const count = beToU16(data, off); off += 2;
    const pos = new Array(count);
    for (let i=0; i<count; i++) {
      pos[i] = beToU16(data, off); off += 2;
    }
    const checksum = beToU32(data, off); off += 4;
    const payload = data.subarray(off);

    const ct = removeDummies(payload, pos);
    const sum = crc32(ct) >>> 0;
    if (sum !== (checksum >>> 0)) throw new Error('Integrity check failed (CRC32 mismatch).');

    const { aesKey, raw } = await deriveKeyAndBytes(passphrase, salt);
    let pre;
    try {
      pre = new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM', iv}, aesKey, ct));
    } catch (e) {
      throw new Error('Gagal dekripsi AES-GCM (passphrase salah atau data rusak).');
    }

    const prngSeed = await sha256(concatU8(raw, te.encode('xspc256-prng-seed')));
    const prng = await hmacDRBG(prngSeed, pre.length);
    const tokenBytes = xorProcess(pre, prng);
    return td.decode(tokenBytes);
  }
};

// Expose for console tests
window.XSPC256 = XSPC256;
