// crane_bridge.js — Browser API bridge for Crane blog encryption.
// Replaces openpgp_bridge.js.  All crypto is done via the Web Crypto API;
// WebAuthn handles passkey-based reader identity.
//
// Exported global functions (called from OCaml via js_of_ocaml externals):
//   crane_sessionStorageGet(key) -> string
//   crane_sessionStorageSet(key, value) -> void
//   crane_sessionStorageRemove(key) -> void
//   crane_enrollCreateReader(callback)        — WebAuthn + ECDH keygen
//   crane_enrollIsEnrolled(callback)          — check IndexedDB
//   crane_enrollGetPubkeys(callback)          — list enrolled key IDs + pubkeys
//   crane_decryptPost(callback)               — auth + unwrap + decrypt

(function () {
  "use strict";

  const DB_NAME = "crane-blog-v2";
  const DB_VERSION = 1;
  const STORE_NAME = "reader-keys";
  const PASKEY_STORE = "passkeys";

  const HPKE_INFO = new TextEncoder().encode("crane-blog-hpke-v1");
  const WRAP_INFO = new TextEncoder().encode("crane-blog-wrap-v1");

  // ---- sessionStorage helpers (unchanged) ----

  window.crane_sessionStorageGet = function (key) {
    try { return sessionStorage.getItem(key) ?? ""; } catch (_) { return ""; }
  };

  window.crane_sessionStorageSet = function (key, value) {
    try { sessionStorage.setItem(key, value); } catch (_) { }
  };

  window.crane_sessionStorageRemove = function (key) {
    try { sessionStorage.removeItem(key); } catch (_) { }
  };

  // ---- IndexedDB helpers ----

  function _openDB() {
    return new Promise(function (resolve, reject) {
      var req = indexedDB.open(DB_NAME, DB_VERSION);
      req.onupgradeneeded = function () {
        var db = req.result;
        if (!db.objectStoreNames.contains(STORE_NAME)) {
          db.createObjectStore(STORE_NAME, { keyPath: "id" });
        }
        if (!db.objectStoreNames.contains(PASKEY_STORE)) {
          db.createObjectStore(PASKEY_STORE, { keyPath: "credentialId" });
        }
      };
      req.onsuccess = function () { resolve(req.result); };
      req.onerror = function () { reject(req.error); };
    });
  }

  function _dbPut(storeName, value) {
    return _openDB().then(function (db) {
      return new Promise(function (resolve, reject) {
        var tx = db.transaction(storeName, "readwrite");
        var store = tx.objectStore(storeName);
        store.put(value);
        tx.oncomplete = function () { resolve(); };
        tx.onerror = function () { reject(tx.error); };
      });
    });
  }

  function _dbGet(storeName, key) {
    return _openDB().then(function (db) {
      return new Promise(function (resolve, reject) {
        var tx = db.transaction(storeName, "readonly");
        var store = tx.objectStore(storeName);
        var req = store.get(key);
        req.onsuccess = function () { resolve(req.result || null); };
        req.onerror = function () { reject(req.error); };
      });
    });
  }

  function _dbGetAll(storeName) {
    return _openDB().then(function (db) {
      return new Promise(function (resolve, reject) {
        var tx = db.transaction(storeName, "readonly");
        var store = tx.objectStore(storeName);
        var req = store.getAll();
        req.onsuccess = function () { resolve(req.result || []); };
        req.onerror = function () { reject(req.error); };
      });
    });
  }

  // ---- Binary helpers ----

  function _bufToHex(buf) {
    return Array.from(new Uint8Array(buf))
      .map(function (b) { return b.toString(16).padStart(2, "0"); })
      .join("");
  }

  function _hexToBuf(hex) {
    var len = hex.length / 2;
    var buf = new Uint8Array(len);
    for (var i = 0; i < len; i++) {
      buf[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return buf;
  }

  function _concatBufs(a, b) {
    var c = new Uint8Array(a.length + b.length);
    c.set(a, 0);
    c.set(b, a.length);
    return c;
  }

  // Derive key_id from raw public key (hex-encoded SHA-256 truncated to 12 chars)
  async function _keyId(pubkeyRaw) {
    var digest = await crypto.subtle.digest("SHA-256", pubkeyRaw);
    return _bufToHex(digest).substring(0, 12);
  }

  // ---- ECDH P-256 key generation ----

  async function _generateEcdhKeypair() {
    var kp = await crypto.subtle.generateKey(
      { name: "ECDH", namedCurve: "P-256" },
      true, // extractable (we need to store it)
      ["deriveBits"]
    );
    var rawPub = await crypto.subtle.exportKey("raw", kp.publicKey);
    var jwkPriv = await crypto.subtle.exportKey("jwk", kp.privateKey);
    return { publicKey: new Uint8Array(rawPub), privateKeyJwk: jwkPriv };
  }

  // Get key_id from raw public key. Returns hex string.
  async function _pubkeyToKeyId(pubkeyRaw) {
    var compressed = _compressPublicKey(pubkeyRaw);
    return _keyId(compressed);
  }

  // Compress an uncompressed P-256 public key (0x04 || x || y -> 0x02/0x03 || x)
  function _compressPublicKey(rawPub) {
    var len = rawPub.byteLength;
    if (len === 33) return rawPub; // already compressed
    // Uncompressed: 0x04 || x(32) || y(32)
    var x = rawPub.slice(1, 33);
    var y = rawPub.slice(33, 65);
    var prefix = (y[31] & 1) ? 0x03 : 0x02;
    var compressed = new Uint8Array(33);
    compressed[0] = prefix;
    compressed.set(x, 1);
    return compressed;
  }

  // ---- HPKE decrypt using Web Crypto ----

  // HPKE-base decrypt: derive CEK from ECDH(priv, encapsulated_pub), then AES-GCM decrypt.
  // ct_package: nonce(12) || ciphertext || tag(16)
  async function _hpkeDecrypt(privKeyJwk, encPubRaw, ctPackage) {
    var encPub = await crypto.subtle.importKey(
      "raw", encPubRaw,
      { name: "ECDH", namedCurve: "P-256" },
      false, ["deriveBits"]
    );
    var privKey = await crypto.subtle.importKey(
      "jwk", privKeyJwk,
      { name: "ECDH", namedCurve: "P-256" },
      false, ["deriveBits"]
    );

    // ECDH key agreement
    var sharedBits = await crypto.subtle.deriveBits(
      { name: "ECDH", public: encPub },
      privKey,
      256
    );
    var shared = new Uint8Array(sharedBits);

    // HKDF to derive CEK
    var cek = await _hkdfSha256("", shared, HPKE_INFO, 32);

    // AES-GCM decrypt
    var nonce = ctPackage.slice(0, 12);
    var tag = ctPackage.slice(ctPackage.length - 16);
    var ct = ctPackage.slice(12, ctPackage.length - 16);

    return await _aesGcmDecrypt(cek, nonce, ct, tag);
  }

  // HKDF-SHA256: extract-then-expand
  async function _hkdfSha256(saltStr, ikmBytes, infoBytes, length) {
    var ikm = await crypto.subtle.importKey(
      "raw", ikmBytes, "HKDF", false, ["deriveBits"]
    );
    var salt = saltStr === ""
      ? new Uint8Array(32) // zeros
      : new TextEncoder().encode(saltStr);

    return new Uint8Array(await crypto.subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt: salt, info: infoBytes },
      ikm,
      length * 8
    ));
  }

  // AES-256-GCM decrypt
  async function _aesGcmDecrypt(keyBytes, nonce, ciphertext, tag) {
    var key = await crypto.subtle.importKey(
      "raw", keyBytes,
      { name: "AES-GCM", length: 256 },
      false, ["decrypt"]
    );
    var combined = _concatBufs(ciphertext, tag);
    var plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: nonce, tagLength: 128 },
      key,
      combined
    );
    return new Uint8Array(plaintext);
  }

  // ---- Parse base64 with whitespace ----

  function _stripB64Ws(s) {
    return s.replace(/[\s\r\n\t]/g, "");
  }

  function _b64ToBytes(b64) {
    var clean = _stripB64Ws(b64);
    var binary = atob(clean);
    var bytes = new Uint8Array(binary.length);
    for (var i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  // ---- Parse decrypt metadata from the page ----

  // The ciphertext <pre> element contains the raw .eml body.
  // Parse HPKE MIME envelope to extract:
  //   Public-Keys: kid1,kid2,...
  //   Wraps: kid1:ek1hex:wrapped1hex, kid2:ek2hex:wrapped2hex, ...
  //   Ciphertext: base64(nonce||ct||tag)

  function _parseHeaders(text) {
    var headers = {};
    var lines = text.split(/\r?\n/);
    var i = 0;
    var currentKey = null;
    var currentVal = null;
    for (; i < lines.length; i++) {
      var line = lines[i];
      if (line === "") break; // blank line ends headers
      if (line[0] === " " || line[0] === "\t") {
        // line folding
        if (currentKey) {
          currentVal += " " + line.trim();
        }
      } else {
        if (currentKey) {
          headers[currentKey.toLowerCase()] = currentVal.trim();
        }
        var colon = line.indexOf(":");
        if (colon > 0) {
          currentKey = line.substring(0, colon).trim();
          currentVal = line.substring(colon + 1).trim();
        } else {
          currentKey = null;
          currentVal = null;
        }
      }
    }
    if (currentKey) {
      headers[currentKey.toLowerCase()] = currentVal.trim();
    }
    return { headers: headers, bodyStart: i + 1, lines: lines };
  }

  function _extractBoundary(ct) {
    var idx = ct.indexOf("boundary=");
    if (idx < 0) return "";
    var start = idx + 9;
    if (ct[start] === '"') {
      var end = ct.indexOf('"', start + 1);
      return end > start ? ct.substring(start + 1, end) : "";
    }
    var end = start;
    while (end < ct.length && ct[end] !== ";" && ct[end] !== " ") end++;
    return ct.substring(start, end);
  }

  function _splitMultipart(body, boundary) {
    var opening = "--" + boundary;
    var closing = "--" + boundary + "--";
    var lines = body.split(/\r?\n/);
    var parts = [];
    var currentPart = [];
    var inPart = false;
    var prevLine = "";
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i];
      if (line === closing) break;
      if (line === opening) {
        if (inPart && currentPart.length > 0) {
          // Remove trailing blank line before boundary
          while (currentPart.length > 0 && currentPart[currentPart.length - 1] === "") {
            currentPart.pop();
          }
          parts.push(currentPart.join("\n"));
        }
        currentPart = [];
        inPart = true;
        prevLine = line;
        continue;
      }
      if (inPart) {
        currentPart.push(line);
      }
      prevLine = line;
    }
    if (inPart && currentPart.length > 0) {
      while (currentPart.length > 0 && currentPart[currentPart.length - 1] === "") {
        currentPart.pop();
      }
      parts.push(currentPart.join("\n"));
    }
    return parts;
  }

  function _scanBoundary(text) {
    var lines = text.split(/\r?\n/);
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i];
      if (line.length > 4 && line.substring(0, 2) === "--") {
        // Must not be the closing marker "--BOUNDARY--"
        if (line.substring(line.length - 2) !== "--") {
          // Strip leading "--"
          return line.substring(2);
        }
      }
    }
    return "";
  }

  function _parseDecryptMeta(ciphertextElement) {
    var text = ciphertextElement.textContent || "";
    var result = _parseHeaders(text);

    // Get Public-Keys
    var pkeys = result.headers["public-keys"] || "";
    var keyIds = pkeys ? pkeys.split(",").map(function (s) { return s.trim(); }).filter(Boolean) : [];

    // Get Content-Type boundary (from headers, or scan body markers)
    var ct = result.headers["content-type"] || "";
    var boundary = _extractBoundary(ct);
    if (!boundary) {
      boundary = _scanBoundary(text);
    }

    var wraps = {};
    var ctBytes = null;

    function _parseWrapsStr(wrapsStr) {
      wrapsStr.split(",").forEach(function (entry) {
        var c = entry.trim().split(":");
        if (c.length === 3) {
          wraps[c[0].trim()] = {
            ek: _hexToBuf(c[1].trim()),
            wrapped: _hexToBuf(c[2].trim())
          };
        }
      });
    }

    // If Public-Keys not in headers, derive key IDs from Wraps value
    if (keyIds.length === 0 && result.headers["wraps"]) {
      result.headers["wraps"].split(",").forEach(function (entry) {
        var kid = entry.trim().split(":")[0];
        if (kid) keyIds.push(kid.trim());
      });
      _parseWrapsStr(result.headers["wraps"]);
    }

    if (boundary) {
      var bodyText = result.lines.slice(result.bodyStart).join("\n");
      var parts = _splitMultipart(bodyText, boundary);

      for (var p = 0; p < parts.length; p++) {
        var partResult = _parseHeaders(parts[p]);
        var pct = (partResult.headers["content-type"] || "").toLowerCase();
        var partBody = partResult.lines.slice(partResult.bodyStart).join("\n");

        if (pct.indexOf("application/wrapped-keys") >= 0) {
          var wrapsHeader = partResult.headers["wraps"] || "";
          _parseWrapsStr(wrapsHeader);
        } else if (pct.indexOf("application/aes-gcm") >= 0) {
          var cte = (partResult.headers["content-transfer-encoding"] || "").toLowerCase();
          if (cte === "base64") {
            ctBytes = _b64ToBytes(partBody);
          }
        }
      }
    }

    return { keyIds: keyIds, wraps: wraps, ctBytes: ctBytes };
  }

  // ---- Enroll: create passkey + ECDH keypair ----

  window.crane_enrollCreateReader = function (callback) {
    (async function () {
      try {
        // Step 1: Generate ECDH P-256 keypair
        var kp = await _generateEcdhKeypair();
        var compressedPub = _compressPublicKey(kp.publicKey);
        var keyId = await _keyId(compressedPub);

        // Step 2: Create WebAuthn passkey
        var challenge = new TextEncoder().encode("crane-enroll-" + keyId);
        var cred = await navigator.credentials.create({
          publicKey: {
            rp: { name: "wklm.online" },
            user: {
              id: new TextEncoder().encode(keyId),
              name: "reader-" + keyId,
              displayName: "Crane Blog Reader"
            },
            challenge: challenge,
            pubKeyCredParams: [
              { type: "public-key", alg: -7 },  // ES256
              { type: "public-key", alg: -8 }   // EdDSA (for Apple Touch ID)
            ],
            authenticatorSelection: {
              residentKey: "required",
              userVerification: "preferred"
            },
            timeout: 120000
          }
        });

        // Step 3: Store passkey reference
        var rawId = new Uint8Array(cred.rawId);
        await _dbPut(PASKEY_STORE, {
          credentialId: _bufToHex(rawId),
          keyId: keyId
        });

        // Step 4: Store ECDH keypair
        await _dbPut(STORE_NAME, {
          id: keyId,
          pubkey: _bufToHex(compressedPub),
          privkeyJwk: kp.privateKeyJwk,
          created: Date.now()
        });

        // Success: return { keyId, pubkeyHex }
        var result = JSON.stringify({
          keyId: keyId,
          pubkeyHex: _bufToHex(compressedPub)
        });
        try { callback(result); } catch (_) { callback(""); }
      } catch (e) {
        console.error("crane_enrollCreateReader failed:", e);
        var msg = e.name ? (e.name + ": " + e.message) : String(e);
        // Show error directly in the DOM
        var stEl = document.getElementById("enroll-status");
        if (stEl) { stEl.textContent = "Enrollment failed: " + msg; }
        // Also pass to OCaml callback for consistency
        try { callback(JSON.stringify({ error: msg })); } catch (_) { callback(""); }
      }
    })();
  };

  // Check if any reader keys are enrolled
  window.crane_enrollIsEnrolled = function (callback) {
    (async function () {
      try {
        var keys = await _dbGetAll(STORE_NAME);
        var result = JSON.stringify({ enrolled: keys.length > 0, count: keys.length });
        try { callback(result); } catch (_) { callback(""); }
      } catch (e) {
        console.error("crane_enrollIsEnrolled failed:", e);
        try { callback(JSON.stringify({ enrolled: false, error: String(e) })); } catch (_) { callback(""); }
      }
    })();
  };

  // Get all enrolled key IDs and public keys
  window.crane_enrollGetPubkeys = function (callback) {
    (async function () {
      try {
        var keys = await _dbGetAll(STORE_NAME);
        var pubkeys = keys.map(function (k) {
          return { keyId: k.id, pubkeyHex: k.pubkey };
        });
        try { callback(JSON.stringify(pubkeys)); } catch (_) { callback(""); }
      } catch (e) {
        console.error("crane_enrollGetPubkeys failed:", e);
        try { callback(JSON.stringify([])); } catch (_) { callback(""); }
      }
    })();
  };

  // ---- Decrypt: authenticate + unwrap + decrypt ----

  function _showError(msg) {
    var el = document.getElementById("decrypt-error");
    var st = document.getElementById("decrypt-status");
    if (el) { el.style.display = "block"; el.textContent = msg; }
    if (st) { st.textContent = ""; }
  }

  window.crane_decryptPost = function (callback) {
    (async function () {
      var diag = [];  // diagnostic messages
      try {
        var cipherEl = document.getElementById("ciphertext");
        if (!cipherEl) { _showError("No ciphertext element found on page."); try { callback(""); } catch (_) { } return; }

        var meta = _parseDecryptMeta(cipherEl);
        diag.push("keyIds: [" + meta.keyIds.join(",") + "]");
        diag.push("wraps keys: [" + Object.keys(meta.wraps).join(",") + "]");
        diag.push("ctBytes: " + (meta.ctBytes ? meta.ctBytes.length + " bytes" : "null"));

        if (!meta.ctBytes) {
          _showError("No ciphertext found in envelope. " + diag.join("; "));
          try { callback(""); } catch (_) { }
          return;
        }

        var enrolledKeys = await _dbGetAll(STORE_NAME);
        diag.push("enrolled: " + enrolledKeys.length + " keys");
        if (enrolledKeys.length === 0) {
          _showError("No reader key found on this device. Visit the enrollment page to create one. (" + diag.join("; ") + ")");
          try { callback(""); } catch (_) { } return;
        }

        var enrolledIds = enrolledKeys.map(function(k) { return k.id; }).join(",");
        diag.push("enrolled IDs: [" + enrolledIds + "]");

        var matchingKey = null;
        var matchingWrap = null;
        for (var i = 0; i < enrolledKeys.length; i++) {
          var ek = enrolledKeys[i];
          if (meta.keyIds.indexOf(ek.id) >= 0 && meta.wraps[ek.id]) {
            matchingKey = ek;
            matchingWrap = meta.wraps[ek.id];
            break;
          }
        }
        if (!matchingKey) {
          _showError("Your enrolled key is not a recipient for this post. " + diag.join("; "));
          try { callback(""); } catch (_) { } return;
        }
        diag.push("matched: " + matchingKey.id);

        var passkeys = await _dbGetAll(PASKEY_STORE);
        var matchedPasskey = null;
        for (var j = 0; j < passkeys.length; j++) {
          if (passkeys[j].keyId === matchingKey.id) {
            matchedPasskey = passkeys[j];
            break;
          }
        }
        diag.push("passkey: " + (matchedPasskey ? "found" : "none"));

        if (matchedPasskey) {
          try {
            var credId = _hexToBuf(matchedPasskey.credentialId);
            await navigator.credentials.get({
              publicKey: {
                challenge: new TextEncoder().encode("crane-decrypt-challenge"),
                allowCredentials: [{ id: credId, type: "public-key" }],
                timeout: 60000,
                userVerification: "preferred"
              }
            });
          } catch (authErr) {
            diag.push("WebAuthn: " + authErr);
          }
        }

        // 5. Unwrap CEK
        var unwrappedCek = await _hpkeDecrypt(
          matchingKey.privkeyJwk, matchingWrap.ek, matchingWrap.wrapped
        );
        diag.push("CEK unwrapped: " + (unwrappedCek ? unwrappedCek.length + " bytes" : "FAILED"));

        if (!unwrappedCek) {
          _showError("Failed to unwrap the content encryption key. " + diag.join("; "));
          try { callback(""); } catch (_) { } return;
        }

        // 6. Decrypt body using the unwrapped CEK
        var nonce = meta.ctBytes.slice(0, 12);
        var tag = meta.ctBytes.slice(meta.ctBytes.length - 16);
        var ct = meta.ctBytes.slice(12, meta.ctBytes.length - 16);
        var decrypted = await _aesGcmDecrypt(unwrappedCek, nonce, ct, tag);
        diag.push("decrypted: " + (decrypted ? decrypted.length + " bytes" : "FAILED"));

        if (!decrypted) {
          _showError("Failed to decrypt the post body. " + diag.join("; "));
          try { callback(""); } catch (_) { } return;
        }

        var decoder = new TextDecoder();
        var plaintext = decoder.decode(decrypted);
        try { callback(plaintext); } catch (_) { callback(""); }
      } catch (e) {
        _showError("Unexpected error: " + e + ". " + diag.join("; "));
        try { callback(""); } catch (_) { }
      }
    })();
  };

  // ---- HPKE body decrypt (using CEK directly, not wrapped) ----

  window.crane_decryptBody = function (cekHex, ctPackageB64, callback) {
    (async function () {
      try {
        var cek = _hexToBuf(cekHex);
        var ctPackage = _b64ToBytes(ctPackageB64);

        var nonce = ctPackage.slice(0, 12);
        var tag = ctPackage.slice(ctPackage.length - 16);
        var ct = ctPackage.slice(12, ctPackage.length - 16);

        var decrypted = await _aesGcmDecrypt(cek, nonce, ct, tag);
        var decoder = new TextDecoder();
        var plaintext = decoder.decode(decrypted);
        try { callback(plaintext); } catch (_) { callback(""); }
      } catch (e) {
        try { callback(""); } catch (_) { }
      }
    })();
  };

  // ---- jsoo_runtime bridge — copy functions onto the js_of_ocaml runtime ----

  // js_of_ocaml compiles [external ... = "crane_foo"] to
  //   runtime.crane_foo(args)
  // where runtime = globalThis.jsoo_runtime.  The runtime object is a
  // plain literal set by the OCaml-compiled JS at load time.  We
  // keep a permanent getter/setter pair so the sprinkling survives
  // all assignments (the OCaml code may reassign jsoo_runtime in
  // nested scopes).
  (function () {
    var _jsoo = globalThis.jsoo_runtime;
    var _deps = {
      crane_sessionStorageGet:   window.crane_sessionStorageGet,
      crane_sessionStorageSet:   window.crane_sessionStorageSet,
      crane_sessionStorageRemove:window.crane_sessionStorageRemove,
      crane_enrollCreateReader:  window.crane_enrollCreateReader,
      crane_enrollIsEnrolled:    window.crane_enrollIsEnrolled,
      crane_enrollGetPubkeys:    window.crane_enrollGetPubkeys,
      crane_decryptPost:         window.crane_decryptPost,
      crane_decryptBody:         window.crane_decryptBody
    };
    function _sprinkle(rt) {
      for (var k in _deps) {
        if (_deps[k]) rt[k] = _deps[k];
      }
    }
    if (_jsoo) { _sprinkle(_jsoo); }
    Object.defineProperty(globalThis, "jsoo_runtime", {
      configurable: true,
      enumerable: true,
      get: function () { return _jsoo; },
      set: function (v) {
        _sprinkle(v);
        _jsoo = v;
      }
    });
  })();

})();
