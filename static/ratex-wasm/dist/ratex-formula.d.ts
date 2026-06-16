/**
 * <ratex-formula> Web Component — drop-in, works with any framework or plain HTML.
 *
 * Usage:
 *   1. Load fonts (once): <link rel="stylesheet" href="node_modules/ratex-wasm/fonts.css" />
 *   2. Register component: <script type="module" src="node_modules/ratex-wasm/dist/ratex-formula.js"></script>
 *   3. Use: <ratex-formula latex="\frac{-b \pm \sqrt{b^2-4ac}}{2a}"></ratex-formula>
 *
 * If fonts.css is not imported, the component will attempt auto-injection
 * (resolves fonts.css relative to import.meta.url within the same package).
 */
export declare class RatexFormulaElement extends HTMLElement {
    static get observedAttributes(): string[];
    private _canvas;
    connectedCallback(): void;
    disconnectedCallback(): void;
    attributeChangedCallback(_name: string, _oldValue: string | null, _newValue: string | null): void;
    get latex(): string;
    set latex(value: string);
    private _getOptions;
    /**
     * Canvas size calculation matching drawDisplayList in demo/index.html:
     * totalH = height + depth, w = ceil(width*em + 2*pad), h = ceil(totalH*em + 2*pad)
     */
    private _setCanvasSizeFromDisplayList;
    private _renderWhenReady;
}
//# sourceMappingURL=ratex-formula.d.ts.map