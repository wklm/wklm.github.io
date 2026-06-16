/**
 * Web-render: draw RaTeX DisplayList to Canvas 2D.
 * Coordinates are in em units; we scale by font size (em) and add padding.
 */
import type { DisplayList } from "./types.js";
export interface WebRenderOptions {
    /** Font size in pixels (1em). Default 40. */
    fontSize?: number;
    /** Padding in pixels. Default 10. */
    padding?: number;
    /** Fill style for background. Default "white". */
    backgroundColor?: string;
    /** CSS font-family for math glyphs (GlyphPath). Must load a math font in your page. Default uses KaTeX_Main when available. */
    mathFontFamily?: string;
}
/**
 * Render a DisplayList to the given canvas.
 * Resizes the canvas to fit the content (list width/height/depth in em) plus padding.
 */
export declare function renderToCanvas(displayList: DisplayList, canvas: HTMLCanvasElement, options?: WebRenderOptions): void;
//# sourceMappingURL=renderer.d.ts.map