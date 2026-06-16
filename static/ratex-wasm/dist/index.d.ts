/**
 * RaTeX for the browser: WASM (parse + layout) + web-render (Canvas 2D).
 *
 * Usage:
 *   import { initRatex, renderLatexToCanvas } from './index.js';
 *   await initRatex();  // load WASM once
 *   renderLatexToCanvas('\\frac{-b \\pm \\sqrt{b^2-4ac}}{2a}', canvasElement);
 */
import type { DisplayList } from "./types.js";
import type { WebRenderOptions } from "./renderer.js";
/**
 * Initialize the WASM module. Safe to call concurrently — subsequent calls share
 * the same in-flight promise so WASM is loaded at most once.
 * Pass the URL to the WASM package's init (e.g. from your bundler or script tag).
 */
export declare function initRatex(init?: () => Promise<{
    renderLatex: (s: string) => string;
}>): Promise<void>;
/**
 * Parse LaTeX and return the display list as a JSON string (or throw on parse error).
 * Requires initRatex() to have been called first.
 */
export declare function renderLatex(latex: string, color?: string): string;
/**
 * Parse LaTeX and return the display list as a DisplayList object.
 * Throws if LaTeX is invalid or WASM not initialized.
 */
export declare function renderLatexToDisplayList(latex: string, color?: string): DisplayList;
/**
 * Parse LaTeX and draw the result on the given canvas (web-render).
 * Resizes the canvas to fit. Optional render options (fontSize, padding, backgroundColor).
 */
export declare function renderLatexToCanvas(latex: string, canvas: HTMLCanvasElement, options?: WebRenderOptions, color?: string): DisplayList;
export { renderToCanvas } from "./renderer.js";
export type { DisplayList, DisplayItem, Color, PathCommand } from "./types.js";
export type { WebRenderOptions } from "./renderer.js";
//# sourceMappingURL=index.d.ts.map