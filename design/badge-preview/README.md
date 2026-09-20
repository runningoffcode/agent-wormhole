# Local logo badge study — revision 2

Three treatments of the existing AgentWormhole Lensed Field mark: Original, Compact, and Micro.
Each comes in a single green or red color, with a transparent canvas and no added surround,
backing disc, text, or status glyph. Compact is the default preview.

Original retains all rings. Compact increases spacing and stroke weight. Micro reduces the
mark to two rings and its center for small placements. Compare at 16, 20, 24, and 32 pixels.
The token-row mockups display only the logo beside the name, without visible verdict labels.

Run from the repository root:

```sh
python3 -m http.server 4173 --bind 127.0.0.1 --directory design/badge-preview
```

Open http://localhost:4173. Download transparent SVGs or 512 × 512 PNGs from the preview.
Regenerate SVGs with `node design/badge-preview/generate.mjs`.

This folder preserves the visual studies. Compact Drift is the selected production treatment in the dashboard token-badge renderer and the site launch-layer demo.
For future integration, preserve distinct unknown/expired states and provide a nonvisual
accessible description for the state; absence of a visible label need not remove semantics.
The previous study's halo/bubble/signal assets remain on disk but are not shown in the preview.

## Motion study — revision 3

The default preview now animates the Compact logo. `static.html` preserves the static comparison.

- **Orbit:** existing inner rings rotate together; outer logo ring stays still. Six-second loop.
- **Drift:** inner rings counter-rotate within the logo. 8.4-second loop.
- Both come in green and red as animated SVGs and transparent 192 × 192 GIFs (120 frames).
- Preview controls switch format, background and motion; reduced-motion preference starts paused.
- Animated SVGs have their own reduced-motion CSS. GIF embeds need a static fallback chosen by the host.
- GIF transparency is binary; animated SVG retains smoother edges at small sizes.

Regenerate with `node design/badge-preview/generate-motion.mjs`.
The exporter uses Sharp (resolved locally or from the sibling site checkout) and Python Pillow.
Temporary render frames are removed after export. The generator only updates this study; production asset copies live in each app’s public/badges directory.
