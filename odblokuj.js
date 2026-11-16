/*
 * odblokuj.js – wspólny moduł „Odblokuj dane rodziny” dla wszystkich stron (index, galeria, biografie, kontakt, O projekcie).
 *
 * Co robi:
 *  – dodaje kłódkę w prawym górnym rogu ciemnego nagłówka (tylko gdy dane.js zawiera zaszyfrowany blok "locked"),
 *  – pokazuje okienko na hasło, odszyfrowuje dane w przeglądarce (AES-256-GCM, klucz z hasła przez PBKDF2 – Web Crypto),
 *  – zapamiętuje ODBLOKOWANIE (nie hasło!) po to, żeby po przejściu na inną stronę nie trzeba było wpisywać go ponownie:
 *      • domyślnie: do zamknięcia karty/okna przeglądarki (sessionStorage),
 *      • opcjonalnie (zaznaczone pole): na tym urządzeniu przez 30 dni (localStorage).
 *    Zapamiętywany jest wyłącznie klucz pochodny przypisany do konkretnego pliku dane.js (jego „soli”); po ponownym zaszyfrowaniu
 *    danych stary klucz przestaje pasować i strona prosi o hasło od nowa. Przycisk „zablokuj” kasuje zapamiętany klucz.
 *
 * Użycie na stronie (po <script src="dane.js">):
 *   <script src="odblokuj.js"></script>
 *   TutejaLock.ready(function () { ...start strony... });   // czeka na ewentualne odszyfrowanie zapamiętanym kluczem
 *   TutejaLock.onUnlock(function (sec) { ... });             // po wpisaniu hasła (domyślnie: przeładowanie strony)
 */
(function () {
  "use strict";
  var D = window.FAMILY_DATA, LOCKED = D && D.locked;
  var KEY = "tuteja_unlock_v1", DAYS30 = 30 * 24 * 3600 * 1000;
  var unlocked = false, handlers = [], lastFocus = null;
  var api = window.TutejaLock = { locked: !!LOCKED };

  /* ---------- pomocnicze ---------- */
  function fromB64(s) { var b = atob(s), a = new Uint8Array(b.length); for (var i = 0; i < b.length; i++) a[i] = b.charCodeAt(i); return a; }
  function toB64(buf) { var a = new Uint8Array(buf), s = ""; for (var i = 0; i < a.length; i++) s += String.fromCharCode(a[i]); return btoa(s); }
  function get(st, k) { try { return window[st].getItem(k); } catch (e) { return null; } }
  function set(st, k, v) { try { window[st].setItem(k, v); } catch (e) {} }
  function del(st, k) { try { window[st].removeItem(k); } catch (e) {} }
  function clearKey() { del("sessionStorage", KEY); del("localStorage", KEY); }
  function loadKey() {                                          // zapamiętany klucz pochodny dla TEGO pliku dane.js
    var st = ["sessionStorage", "localStorage"];
    for (var i = 0; i < st.length; i++) {
      var raw = get(st[i], KEY); if (!raw) continue;
      try {
        var r = JSON.parse(raw);
        if (r.s === LOCKED.salt && r.k && (!r.exp || r.exp > Date.now())) return r.k;
      } catch (e) {}
      del(st[i], KEY);
    }
    return null;
  }
  function saveKey(k, remember) {
    var rec = { s: LOCKED.salt, k: k };
    set("sessionStorage", KEY, JSON.stringify(rec));
    if (remember) { rec.exp = Date.now() + DAYS30; set("localStorage", KEY, JSON.stringify(rec)); } else del("localStorage", KEY);
  }
  function decryptWith(rawKeyBuf) {
    return crypto.subtle.importKey("raw", rawKeyBuf, "AES-GCM", false, ["decrypt"]).then(function (key) {
      return crypto.subtle.decrypt({ name: "AES-GCM", iv: fromB64(LOCKED.iv) }, key, fromB64(LOCKED.ct));
    }).then(function (buf) { return JSON.parse(new TextDecoder().decode(buf)); });
  }
  function deriveRaw(password) {                                // hasło → 256-bitowy klucz (PBKDF2-SHA256)
    return crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]).then(function (base) {
      return crypto.subtle.deriveBits({ name: "PBKDF2", salt: fromB64(LOCKED.salt), iterations: LOCKED.iter, hash: "SHA-256" }, base, 256);
    });
  }
  function merge(d, sec) {                                      // wstawia odszyfrowane osoby w miejsce pustych kafelków (w pamięci strony)
    var ids = {}; sec.people.forEach(function (p) { ids[p.id] = 1; });
    d.people = d.people.filter(function (p) { return !(p.living && ids[p.id]); }).concat(sec.people);
    var seen = {}; (d.marriages = d.marriages || []).forEach(function (m) { seen[m.a + "-" + m.b] = 1; });
    (sec.marriages || []).forEach(function (m) { if (!seen[m.a + "-" + m.b]) d.marriages.push(m); });
    if (d.gallery && d.gallery.items) (sec.gallery || []).forEach(function (g) {
      d.gallery.items.forEach(function (it) {
        if ((it.id || it.url) !== g.key) return;
        it.people = (it.people || []).concat(g.people.filter(function (id) { return (it.people || []).indexOf(id) === -1; }));
        it.boxes = Object.assign({}, it.boxes, g.boxes);
      });
    });
  }

  /* ---------- interfejs: kłódka w nagłówku + okienko na hasło ---------- */
  var css = document.createElement("style");
  css.textContent =
    "header{position:relative}" +
    ".hdr-lock{position:absolute;top:.9rem;right:1rem;display:inline-flex;align-items:center;gap:.5rem;padding:.5rem .9rem;border:1px solid rgba(255,255,255,.35);border-radius:999px;background:rgba(255,255,255,.08);color:#fff;font:.85rem sans-serif;cursor:pointer;transition:background .15s,border-color .15s}" +
    ".hdr-lock:hover,.hdr-lock:focus-visible{background:rgba(255,255,255,.2);border-color:#fff;outline:none}" +
    ".hdr-lock .lk-open{display:none}.hdr-lock.on{border-color:#6fc28b;background:rgba(111,194,139,.18);color:#b9f0cc}.hdr-lock.on .lk-open{display:block}.hdr-lock.on .lk-closed{display:none}" +
    "@media(max-width:700px){.hdr-lock span{display:none}.hdr-lock{padding:.55rem}}" +
    ".unlock{position:fixed;inset:0;z-index:5000;display:flex;align-items:center;justify-content:center;padding:1rem;background:rgba(8,12,20,.6);font-family:sans-serif}" +
    ".unlock[hidden]{display:none}" +
    ".unlock-box{width:min(420px,100%);background:#fff;border-radius:14px;padding:1.4rem 1.5rem 1.2rem;box-shadow:0 20px 60px rgba(0,0,0,.4);color:#232a36}" +
    ".unlock-box h3{margin:0 0 .5rem;font:normal 1.3rem Georgia,serif}" +
    ".unlock-box p{margin:0 0 .9rem;font-size:.9rem;line-height:1.5;color:#475467}" +
    ".unlock-box label.lbl{display:block;margin-bottom:.3rem;font-size:.8rem;font-weight:600;color:#667085}" +
    ".unlock-box input[type=password]{width:100%;box-sizing:border-box;padding:.65rem .8rem;border:1px solid #cfd4dc;border-radius:10px;font-size:1rem}" +
    ".unlock-box input[type=password]:focus{outline:none;border-color:#d92b57;box-shadow:0 0 0 3px rgba(217,43,87,.15)}" +
    ".unlock-box .rem{display:flex;gap:.5rem;align-items:flex-start;margin:.8rem 0 0;font-size:.82rem;line-height:1.4;color:#475467;cursor:pointer}.unlock-box .rem input{margin-top:.15rem}" +
    ".unlock-box .unlock-err{margin:.6rem 0 0;color:#b42318;font-weight:600}" +
    ".unlock-act{display:flex;justify-content:flex-end;gap:.5rem;margin-top:1rem}" +
    ".unlock-act button{font:600 .9rem sans-serif;padding:.55rem 1.1rem;border-radius:999px;border:1px solid #cfd4dc;background:#fff;color:#232a36;cursor:pointer}" +
    ".unlock-act button.primary{background:#d92b57;border-color:#d92b57;color:#fff}.unlock-act button:disabled{opacity:.6;cursor:default}";
  document.head.appendChild(css);

  var LOCK_SVG = function (open) {
    return '<svg class="' + (open ? "lk-open" : "lk-closed") + '" viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="5" y="11" width="14" height="9" rx="2"/><path d="' + (open ? "M8 11V8a4 4 0 0 1 7.6-1.7" : "M8 11V8a4 4 0 0 1 8 0v3") + '"/><circle cx="12" cy="15.5" r="1.1" fill="currentColor"/></svg>';
  };
  var btn = document.createElement("button");
  btn.type = "button"; btn.className = "hdr-lock"; btn.id = "hdrLock"; btn.hidden = true;
  btn.innerHTML = LOCK_SVG(false) + LOCK_SVG(true) + '<span id="hdrLockTxt">Odblokuj dane rodziny</span>';
  var hdr = document.querySelector("header"); if (hdr) hdr.appendChild(btn);

  var dlg = document.createElement("div");
  dlg.className = "unlock"; dlg.id = "unlock"; dlg.hidden = true; dlg.setAttribute("role", "dialog"); dlg.setAttribute("aria-modal", "true"); dlg.setAttribute("aria-labelledby", "unlockTitle");
  dlg.innerHTML =
    '<form class="unlock-box" id="unlockForm" autocomplete="off">' +
    '<h3 id="unlockTitle">Odblokuj dane rodziny</h3>' +
    '<p>Dane żyjących członków rodziny są zaszyfrowane. Wpisz hasło otrzymane od rodziny – dane odszyfrują się wyłącznie w Twojej przeglądarce i nie są nigdzie wysyłane.</p>' +
    '<label class="lbl" for="unlockPw">Hasło</label>' +
    '<input type="password" id="unlockPw" autocomplete="current-password" spellcheck="false" required>' +
    '<label class="rem"><input type="checkbox" id="unlockRem"> <span>Zapamiętaj na tym urządzeniu przez 30 dni (tylko na własnym komputerze lub telefonie). Bez zaznaczenia dane pozostają odblokowane do zamknięcia przeglądarki.</span></label>' +
    '<p class="unlock-err" id="unlockErr" role="alert" hidden></p>' +
    '<div class="unlock-act"><button type="button" id="unlockCancel">Anuluj</button><button type="submit" class="primary" id="unlockGo">Odblokuj</button></div>' +
    '</form>';
  document.body.appendChild(dlg);
  function $(id) { return document.getElementById(id); }

  function sync() {
    btn.hidden = !LOCKED; btn.classList.toggle("on", unlocked);
    $("hdrLockTxt").textContent = unlocked ? "Dane odblokowane · zablokuj" : "Odblokuj dane rodziny";
    btn.title = unlocked ? "Dane rodziny są odblokowane – kliknij, aby zablokować" : "Odblokuj dane rodziny (hasło)";
  }
  function openDlg() {
    if (!LOCKED || unlocked) return;
    lastFocus = document.activeElement; $("unlockErr").hidden = true; $("unlockPw").value = ""; dlg.hidden = false; $("unlockPw").focus();
  }
  function closeDlg() { dlg.hidden = true; $("unlockPw").value = ""; if (lastFocus && lastFocus.focus) { try { lastFocus.focus(); } catch (e) {} } }
  function lock() { clearKey(); location.reload(); }               // „zablokuj”: kasuje zapamiętany klucz i czyści dane z pamięci strony

  btn.addEventListener("click", function () { if (unlocked) lock(); else openDlg(); });
  $("unlockCancel").addEventListener("click", closeDlg);
  dlg.addEventListener("mousedown", function (e) { if (e.target === dlg) closeDlg(); });
  document.addEventListener("keydown", function (e) { if (e.key === "Escape" && !dlg.hidden) { e.stopPropagation(); closeDlg(); } }, true);
  $("unlockForm").addEventListener("submit", function (e) {
    e.preventDefault();
    var pw = $("unlockPw").value, go = $("unlockGo"), err = $("unlockErr"), rem = $("unlockRem").checked;
    if (!pw) return;
    if (!(window.crypto && crypto.subtle)) { err.textContent = "Ta przeglądarka nie obsługuje szyfrowania (otwórz stronę przez https)."; err.hidden = false; return; }
    go.disabled = true; go.textContent = "Sprawdzam…"; err.hidden = true;
    deriveRaw(pw).then(function (raw) {
      return decryptWith(raw).then(function (sec) { saveKey(toB64(raw), rem); return sec; });
    }).then(function (sec) {
      closeDlg(); unlocked = true; sync();
      if (handlers.length) handlers.forEach(function (h) { h(sec); }); else location.reload();
    }).catch(function () {
      err.textContent = "Nieprawidłowe hasło. Spróbuj ponownie."; err.hidden = false; $("unlockPw").select();
    }).then(function () { go.disabled = false; go.textContent = "Odblokuj"; });
  });

  /* ---------- API ---------- */
  api.open = openDlg;
  api.lock = lock;
  api.isUnlocked = function () { return unlocked; };
  api.setUnlocked = function (v) { unlocked = !!v; sync(); };
  api.onUnlock = function (fn) { handlers.push(fn); };
  api.restore = function () {                                        // Promise: odszyfrowane dane z zapamiętanego klucza albo null
    if (!LOCKED || !(window.crypto && crypto.subtle)) return Promise.resolve(null);
    var k = loadKey(); if (!k) return Promise.resolve(null);
    return decryptWith(fromB64(k)).then(function (sec) { unlocked = true; sync(); return sec; }, function () { clearKey(); return null; });
  };
  api.ready = function (fn) {                                         // dla stron bez własnej obsługi: odszyfruj, wmieszaj w FAMILY_DATA, uruchom stronę
    api.restore().then(function (sec) { if (sec) merge(D, sec); }, function () {}).then(fn);
  };
  sync();
  api.restore();                                                      // stan kłódki na stronach bez własnego startu (kontakt, O projekcie)
})();