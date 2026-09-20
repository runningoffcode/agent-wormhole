import { mkdir, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

const destination = new URL('./assets/', import.meta.url);
await mkdir(destination, { recursive: true });

// Original Lensed Field geometry; compact variants remove inner rings for small sizes.
// Color belongs to the logo itself. No added enclosure, backing disc, or status glyph.
const original = `<circle cx="32" cy="32" r="30" stroke-width="2.5"/>
  <circle cx="33.59" cy="33.59" r="23.25" stroke-width="1.9"/>
  <circle cx="35.18" cy="35.18" r="17.5" stroke-width="1.7"/>
  <circle cx="36.95" cy="36.95" r="12.5" stroke-width="1.5"/>
  <circle cx="38.72" cy="38.72" r="8" stroke-width="1.3"/>
  <circle cx="41.02" cy="41.02" r="3.25" fill="currentColor" stroke="none"/>`;
const compact = `<circle cx="32" cy="32" r="30" stroke-width="3.3"/>
  <circle cx="35.18" cy="35.18" r="18.5" stroke-width="3"/>
  <circle cx="38.72" cy="38.72" r="8.5" stroke-width="2.6"/>
  <circle cx="41.02" cy="41.02" r="2.8" fill="currentColor" stroke="none"/>`;
const micro = `<circle cx="32" cy="32" r="29.5" stroke-width="4.5"/>
  <circle cx="36" cy="36" r="16" stroke-width="4"/>
  <circle cx="41" cy="41" r="4.8" fill="currentColor" stroke="none"/>`;

for (const [colorName, color] of Object.entries({ green: '#20B879', red: '#E45464' })) {
  for (const [style, geometry] of Object.entries({ original, compact, micro })) {
    const id = `${style}-${colorName}`;
    const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64" viewBox="-3 -3 70 70" role="img" aria-labelledby="${id}-title">
<title id="${id}-title">AgentWormhole — ${colorName} ${style} mark</title>
<g color="${color}" fill="none" stroke="currentColor">${geometry}</g>
</svg>\n`;
    await writeFile(new URL(`${id}.svg`, destination), svg);
  }
}
console.log(`Generated six transparent logo marks in ${fileURLToPath(destination)}`);
