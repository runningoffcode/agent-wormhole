import { mkdir, writeFile, mkdtemp, rm } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const sharp = require(require.resolve('sharp', { paths: [process.cwd(), fileURLToPath(new URL('../../../agent-wormhole-site/', import.meta.url))] }));
const assets = new URL('./assets/', import.meta.url);
await mkdir(assets, { recursive: true });
const temp = await mkdtemp(join(tmpdir(), 'wormhole-motion-'));
const colors = { green: '#20B879', red: '#E45464' };
const styles = { orbit: { duration: 6, delay: 50 }, drift: { duration: 8.4, delay: 70 } };
const frames = 120;

// Keep the enclosing logo ring stationary. Rotate only the existing inner geometry.
function geometry(style, angle = 0, animated = false) {
  const group = (name, degrees, cx, cy) => animated
    ? `<g class="${name}">`
    : `<g transform="rotate(${degrees} ${cx} ${cy})">`;
  return `<circle cx="32" cy="32" r="30" stroke-width="3.3"/>
    ${group('orbit', angle, 32, 32)}
      <circle cx="35.18" cy="35.18" r="18.5" stroke-width="3"/>
      ${group('drift', style === 'drift' ? -2 * angle : 0, 35.18, 35.18)}
        <circle cx="38.72" cy="38.72" r="8.5" stroke-width="2.6"/>
        <circle cx="41.02" cy="41.02" r="2.8" fill="currentColor" stroke="none"/>
      </g>
    </g>`;
}
function svg(style, colorName, angle = 0, animated = false) {
  const color = colors[colorName];
  const duration = styles[style].duration;
  const css = animated ? `<style>
    .orbit { transform-origin:32px 32px; animation:orbit ${duration}s linear infinite; }
    ${style === 'drift' ? `.drift { transform-origin:35.18px 35.18px; animation:counter ${duration}s linear infinite; }` : ''}
    @keyframes orbit { to { transform:rotate(360deg); } }
    @keyframes counter { to { transform:rotate(-720deg); } }
    @media (prefers-reduced-motion:reduce) { .orbit,.drift { animation:none; } }
  </style>` : '';
  return `<svg xmlns="http://www.w3.org/2000/svg" width="70" height="70" viewBox="0 0 70 70" role="img" aria-label="AgentWormhole ${colorName} compact logo">
  ${css}<g transform="translate(3 3)" color="${color}" stroke="currentColor" fill="none">${geometry(style, angle, animated)}</g></svg>`;
}

try {
  for (const [style, config] of Object.entries(styles)) {
    for (const colorName of Object.keys(colors)) {
      const name = `compact-${style}-${colorName}`;
      await writeFile(new URL(`${name}.svg`, assets), svg(style, colorName, 0, true).replace(/[ \t]+$/gm, ''));
      const dir = join(temp, name);
      await mkdir(dir);
      for (let frame = 0; frame < frames; frame++) {
        await sharp(Buffer.from(svg(style, colorName, frame / frames * 360)))
          .resize(192, 192).png().toFile(join(dir, `${String(frame).padStart(3, '0')}.png`));
      }
      // GIF supports binary transparency; use a fixed palette and explicit disposal
      // so transparent pixels never leave trails from the preceding frame.
      const conversion = spawnSync('python3', ['-c', `
from PIL import Image
from pathlib import Path
import sys
folder, output, color, delay = sys.argv[1:]
rgb = tuple(bytes.fromhex(color[1:]))
palette = [0, 0, 0] + list(rgb) + [0] * (768 - 6)
frames = []
for path in sorted(Path(folder).glob('*.png')):
    rgba = Image.open(path).convert('RGBA')
    image = rgba.getchannel('A').point(lambda a: 1 if a >= 100 else 0, 'P')
    image.putpalette(palette)
    image.info['transparency'] = 0
    frames.append(image)
frames[0].save(output, save_all=True, append_images=frames[1:], duration=int(delay),
    loop=0, transparency=0, disposal=2, optimize=False)
`, dir, fileURLToPath(new URL(`${name}.gif`, assets)), colors[colorName], String(config.delay)], { encoding: 'utf8' });
      if (conversion.status !== 0) throw new Error(conversion.stderr || 'GIF export failed');
      console.log(`${name}: SVG + transparent 192px GIF, ${frames} frames, ${config.duration}s seamless loop`);
    }
  }
} finally {
  await rm(temp, { recursive: true, force: true });
}
