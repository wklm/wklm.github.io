// Provides crane_decryptWithCallback, crane_sessionStorageGet,
// crane_sessionStorageSet, crane_sessionStorageRemove.
//
// These are the typed bridge between js_of_ocaml (via OCaml [external]
// declarations) and the browser APIs — no Js.Unsafe is used in the
// OCaml code that calls them.

function crane_sessionStorageGet(key) {
  try { return sessionStorage.getItem(key) ?? ""; } catch (_) { return ""; }
}

function crane_sessionStorageSet(key, value) {
  try { sessionStorage.setItem(key, value); } catch (_) {}
}

function crane_sessionStorageRemove(key) {
  try { sessionStorage.removeItem(key); } catch (_) {}
}

function crane_decryptWithCallback(armoredMessage, armoredKey, callback) {
  if (typeof openpgp === 'undefined') {
    try { callback(""); } catch (_) {}
    return;
  }
  (async function () {
    try {
      var privateKey = await openpgp.readPrivateKey({ armoredKey: armoredKey });
      var message    = await openpgp.readMessage({ armoredMessage: armoredMessage });
      var result     = await openpgp.decrypt({
        message:          message,
        decryptionKeys:   [privateKey],
        format:           'utf8'
      });
      try { callback(result.data); } catch (_) { callback(""); }
    } catch (e) {
      try { callback(""); } catch (_) {}
    }
  })();
}
