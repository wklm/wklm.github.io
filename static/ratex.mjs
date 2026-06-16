// node_modules/ratex-wasm/pkg/ratex_wasm.js
function renderLatex(latex, color) {
  let deferred4_0;
  let deferred4_1;
  try {
    const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
    const ptr0 = passStringToWasm0(latex, wasm.__wbindgen_export, wasm.__wbindgen_export2);
    const len0 = WASM_VECTOR_LEN;
    var ptr1 = isLikeNone(color) ? 0 : passStringToWasm0(color, wasm.__wbindgen_export, wasm.__wbindgen_export2);
    var len1 = WASM_VECTOR_LEN;
    wasm.renderLatex(retptr, ptr0, len0, ptr1, len1);
    var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
    var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
    var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
    var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
    var ptr3 = r0;
    var len3 = r1;
    if (r3) {
      ptr3 = 0;
      len3 = 0;
      throw takeObject(r2);
    }
    deferred4_0 = ptr3;
    deferred4_1 = len3;
    return getStringFromWasm0(ptr3, len3);
  } finally {
    wasm.__wbindgen_add_to_stack_pointer(16);
    wasm.__wbindgen_export3(deferred4_0, deferred4_1, 1);
  }
}
function __wbg_get_imports() {
  const import0 = {
    __proto__: null,
    __wbindgen_cast_0000000000000001: function(arg0, arg1) {
      const ret = getStringFromWasm0(arg0, arg1);
      return addHeapObject(ret);
    }
  };
  return {
    __proto__: null,
    "./ratex_wasm_bg.js": import0
  };
}
function addHeapObject(obj) {
  if (heap_next === heap.length) heap.push(heap.length + 1);
  const idx = heap_next;
  heap_next = heap[idx];
  heap[idx] = obj;
  return idx;
}
function dropObject(idx) {
  if (idx < 1028) return;
  heap[idx] = heap_next;
  heap_next = idx;
}
var cachedDataViewMemory0 = null;
function getDataViewMemory0() {
  if (cachedDataViewMemory0 === null || cachedDataViewMemory0.buffer.detached === true || cachedDataViewMemory0.buffer.detached === void 0 && cachedDataViewMemory0.buffer !== wasm.memory.buffer) {
    cachedDataViewMemory0 = new DataView(wasm.memory.buffer);
  }
  return cachedDataViewMemory0;
}
function getStringFromWasm0(ptr, len) {
  return decodeText(ptr >>> 0, len);
}
var cachedUint8ArrayMemory0 = null;
function getUint8ArrayMemory0() {
  if (cachedUint8ArrayMemory0 === null || cachedUint8ArrayMemory0.byteLength === 0) {
    cachedUint8ArrayMemory0 = new Uint8Array(wasm.memory.buffer);
  }
  return cachedUint8ArrayMemory0;
}
function getObject(idx) {
  return heap[idx];
}
var heap = new Array(1024).fill(void 0);
heap.push(void 0, null, true, false);
var heap_next = heap.length;
function isLikeNone(x) {
  return x === void 0 || x === null;
}
function passStringToWasm0(arg, malloc, realloc) {
  if (realloc === void 0) {
    const buf = cachedTextEncoder.encode(arg);
    const ptr2 = malloc(buf.length, 1) >>> 0;
    getUint8ArrayMemory0().subarray(ptr2, ptr2 + buf.length).set(buf);
    WASM_VECTOR_LEN = buf.length;
    return ptr2;
  }
  let len = arg.length;
  let ptr = malloc(len, 1) >>> 0;
  const mem = getUint8ArrayMemory0();
  let offset = 0;
  for (; offset < len; offset++) {
    const code = arg.charCodeAt(offset);
    if (code > 127) break;
    mem[ptr + offset] = code;
  }
  if (offset !== len) {
    if (offset !== 0) {
      arg = arg.slice(offset);
    }
    ptr = realloc(ptr, len, len = offset + arg.length * 3, 1) >>> 0;
    const view = getUint8ArrayMemory0().subarray(ptr + offset, ptr + len);
    const ret = cachedTextEncoder.encodeInto(arg, view);
    offset += ret.written;
    ptr = realloc(ptr, len, offset, 1) >>> 0;
  }
  WASM_VECTOR_LEN = offset;
  return ptr;
}
function takeObject(idx) {
  const ret = getObject(idx);
  dropObject(idx);
  return ret;
}
var cachedTextDecoder = new TextDecoder("utf-8", { ignoreBOM: true, fatal: true });
cachedTextDecoder.decode();
var MAX_SAFARI_DECODE_BYTES = 2146435072;
var numBytesDecoded = 0;
function decodeText(ptr, len) {
  numBytesDecoded += len;
  if (numBytesDecoded >= MAX_SAFARI_DECODE_BYTES) {
    cachedTextDecoder = new TextDecoder("utf-8", { ignoreBOM: true, fatal: true });
    cachedTextDecoder.decode();
    numBytesDecoded = len;
  }
  return cachedTextDecoder.decode(getUint8ArrayMemory0().subarray(ptr, ptr + len));
}
var cachedTextEncoder = new TextEncoder();
if (!("encodeInto" in cachedTextEncoder)) {
  cachedTextEncoder.encodeInto = function(arg, view) {
    const buf = cachedTextEncoder.encode(arg);
    view.set(buf);
    return {
      read: arg.length,
      written: buf.length
    };
  };
}
var WASM_VECTOR_LEN = 0;
var wasmModule;
var wasmInstance;
var wasm;
function __wbg_finalize_init(instance, module) {
  wasmInstance = instance;
  wasm = instance.exports;
  wasmModule = module;
  cachedDataViewMemory0 = null;
  cachedUint8ArrayMemory0 = null;
  return wasm;
}
async function __wbg_load(module, imports) {
  if (typeof Response === "function" && module instanceof Response) {
    if (typeof WebAssembly.instantiateStreaming === "function") {
      try {
        return await WebAssembly.instantiateStreaming(module, imports);
      } catch (e) {
        const validResponse = module.ok && expectedResponseType(module.type);
        if (validResponse && module.headers.get("Content-Type") !== "application/wasm") {
          console.warn("`WebAssembly.instantiateStreaming` failed because your server does not serve Wasm with `application/wasm` MIME type. Falling back to `WebAssembly.instantiate` which is slower. Original error:\n", e);
        } else {
          throw e;
        }
      }
    }
    const bytes = await module.arrayBuffer();
    return await WebAssembly.instantiate(bytes, imports);
  } else {
    const instance = await WebAssembly.instantiate(module, imports);
    if (instance instanceof WebAssembly.Instance) {
      return { instance, module };
    } else {
      return instance;
    }
  }
  function expectedResponseType(type) {
    switch (type) {
      case "basic":
      case "cors":
      case "default":
        return true;
    }
    return false;
  }
}
async function __wbg_init(module_or_path) {
  if (wasm !== void 0) return wasm;
  if (module_or_path !== void 0) {
    if (Object.getPrototypeOf(module_or_path) === Object.prototype) {
      ({ module_or_path } = module_or_path);
    } else {
      console.warn("using deprecated parameters for the initialization function; pass a single object instead");
    }
  }
  if (module_or_path === void 0) {
    module_or_path = new URL("ratex.wasm", import.meta.url);
  }
  const imports = __wbg_get_imports();
  if (typeof module_or_path === "string" || typeof Request === "function" && module_or_path instanceof Request || typeof URL === "function" && module_or_path instanceof URL) {
    module_or_path = fetch(module_or_path);
  }
  const { instance, module } = await __wbg_load(await module_or_path, imports);
  return __wbg_finalize_init(instance, module);
}

// node_modules/ratex-wasm/dist/renderer.js
var DEFAULT_OPTIONS = {
  fontSize: 40,
  padding: 10,
  backgroundColor: "white",
  mathFontFamily: 'KaTeX_Main, "Latin Modern Math", "Cambria Math", serif'
};
function fontIdToCss(fontId, sizePx) {
  switch (fontId) {
    case "AMS-Regular":
      return `${sizePx}px KaTeX_AMS`;
    case "Caligraphic-Regular":
      return `${sizePx}px KaTeX_Caligraphic`;
    case "Fraktur-Regular":
      return `${sizePx}px KaTeX_Fraktur`;
    case "Fraktur-Bold":
      return `bold ${sizePx}px KaTeX_Fraktur`;
    case "Main-Bold":
      return `bold ${sizePx}px KaTeX_Main`;
    case "Main-BoldItalic":
      return `italic bold ${sizePx}px KaTeX_Main`;
    case "Main-Italic":
      return `italic ${sizePx}px KaTeX_Main`;
    case "Main-Regular":
      return `${sizePx}px KaTeX_Main`;
    case "Math-BoldItalic":
      return `italic bold ${sizePx}px KaTeX_Math`;
    case "Math-Italic":
      return `italic ${sizePx}px KaTeX_Math`;
    case "SansSerif-Bold":
      return `bold ${sizePx}px KaTeX_SansSerif`;
    case "SansSerif-Italic":
      return `italic ${sizePx}px KaTeX_SansSerif`;
    case "SansSerif-Regular":
      return `${sizePx}px KaTeX_SansSerif`;
    case "Script-Regular":
      return `${sizePx}px KaTeX_Script`;
    case "Size1-Regular":
      return `${sizePx}px KaTeX_Size1`;
    case "Size2-Regular":
      return `${sizePx}px KaTeX_Size2`;
    case "Size3-Regular":
      return `${sizePx}px KaTeX_Size3`;
    case "Size4-Regular":
      return `${sizePx}px KaTeX_Size4`;
    case "Typewriter-Regular":
      return `${sizePx}px KaTeX_Typewriter`;
    // CJK / emoji fallback: KaTeX fonts don't cover these glyphs;
    // use system UI font stack that has broad Unicode coverage on all platforms.
    case "CJK-Regular":
    case "CJK-Fallback":
    case "Emoji-Fallback":
      return `${sizePx}px sans-serif`;
    default:
      return `${sizePx}px KaTeX_Main`;
  }
}
function colorToCss(c) {
  const r = Math.round(c.r * 255);
  const g = Math.round(c.g * 255);
  const b = Math.round(c.b * 255);
  if (c.a >= 1 - 1e-5)
    return `rgb(${r},${g},${b})`;
  return `rgba(${r},${g},${b},${c.a})`;
}
function applyPathCommands(ctx, commands, em, ox, oy) {
  for (const cmd of commands) {
    switch (cmd.type) {
      case "MoveTo":
        ctx.moveTo(ox + cmd.x * em, oy + cmd.y * em);
        break;
      case "LineTo":
        ctx.lineTo(ox + cmd.x * em, oy + cmd.y * em);
        break;
      case "CubicTo":
        ctx.bezierCurveTo(ox + cmd.x1 * em, oy + cmd.y1 * em, ox + cmd.x2 * em, oy + cmd.y2 * em, ox + cmd.x * em, oy + cmd.y * em);
        break;
      case "QuadTo":
        ctx.quadraticCurveTo(ox + cmd.x1 * em, oy + cmd.y1 * em, ox + cmd.x * em, oy + cmd.y * em);
        break;
      case "Close":
        ctx.closePath();
        break;
    }
  }
}
function drawItem(ctx, item, em, mathFontFamily) {
  switch (item.type) {
    case "GlyphPath": {
      const g = item;
      ctx.font = fontIdToCss(g.font, g.scale * em);
      ctx.textBaseline = "alphabetic";
      ctx.textAlign = "left";
      ctx.fillStyle = colorToCss(g.color);
      ctx.fillText(String.fromCodePoint(g.char_code), g.x * em, g.y * em);
      break;
    }
    case "Line": {
      const l = item;
      const x = l.x * em;
      const y = l.y * em;
      const w = l.width * em;
      const t = Math.max(0.5, l.thickness * em);
      const css = colorToCss(l.color);
      if (l.dashed) {
        ctx.save();
        ctx.beginPath();
        ctx.strokeStyle = css;
        ctx.lineWidth = t;
        ctx.lineCap = "butt";
        ctx.setLineDash([t * 3, t * 3]);
        ctx.moveTo(x, y);
        ctx.lineTo(x + w, y);
        ctx.stroke();
        ctx.restore();
      } else {
        ctx.fillStyle = css;
        ctx.fillRect(x, y - t / 2, w, t);
      }
      break;
    }
    case "Rect": {
      const r = item;
      ctx.fillStyle = colorToCss(r.color);
      ctx.fillRect(r.x * em, r.y * em, r.width * em, r.height * em);
      break;
    }
    case "Path": {
      const p = item;
      ctx.beginPath();
      applyPathCommands(ctx, p.commands, em, p.x * em, p.y * em);
      ctx.strokeStyle = colorToCss(p.color);
      ctx.fillStyle = colorToCss(p.color);
      if (p.fill)
        ctx.fill();
      else
        ctx.stroke();
      break;
    }
    default: {
      void mathFontFamily;
      break;
    }
  }
}
function renderToCanvas(displayList, canvas, options = {}) {
  const opts = { ...DEFAULT_OPTIONS, ...options };
  const em = opts.fontSize;
  const pad = opts.padding;
  const totalH = displayList.height + displayList.depth;
  const pixelW = Math.ceil(displayList.width * em + 2 * pad);
  const pixelH = Math.ceil(totalH * em + 2 * pad);
  canvas.width = Math.max(1, pixelW);
  canvas.height = Math.max(1, pixelH);
  const ctx = canvas.getContext("2d");
  if (!ctx)
    throw new Error("Could not get 2d context");
  ctx.fillStyle = opts.backgroundColor;
  ctx.fillRect(0, 0, canvas.width, canvas.height);
  ctx.save();
  ctx.translate(pad, pad);
  const fontFamily = opts.mathFontFamily ?? DEFAULT_OPTIONS.mathFontFamily;
  for (const item of displayList.items) {
    drawItem(ctx, item, em, fontFamily);
  }
  ctx.restore();
}

// bundle_ratex.js
window.RatexCore = { renderLatex, renderToCanvas, init: __wbg_init };
