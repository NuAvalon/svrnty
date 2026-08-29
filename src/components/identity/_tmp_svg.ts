import { writeFileSync } from 'fs';
import {
  unicursalPentagramPaths, unicursalClassicPaths,
  flowerOfLifePaths, metatronPaths, composePhiSeal, randomFingerprint,
} from './IdentitySeal';

function panel(x: number, title: string, paths: string[], op = 0.7) {
  const body = paths.map(d => `<path d="${d}" fill="none" stroke="#f9a825" stroke-opacity="${op}" stroke-width="0.9"/>`).join('');
  return `<g transform="translate(${x},20)">
    <text x="50" y="-6" fill="#c4a574" font-size="5" text-anchor="middle">${title}</text>
    ${body}
    <circle cx="50" cy="50" r="1.5" fill="#f9a825"/>
  </g>`;
}

const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 440 120" width="1320" height="360">
  <rect width="440" height="120" fill="#0f0a06"/>
  ${panel(0, 'unicursal pentagram', unicursalPentagramPaths(50,50,36,0))}
  ${panel(110, 'unicursal hexagram', unicursalClassicPaths(50,50,36,0))}
  ${panel(220, 'flower of life', flowerOfLifePaths(50,50,40,0), 0.45)}
  ${panel(330, "Metatron's cube", metatronPaths(50,50,40,0), 0.35)}
</svg>`;
writeFileSync('/opt/cursor/artifacts/seal-catalog-expand.svg', svg);

// sample diversity
const counts = new Map<string, number>();
for (let i = 0; i < 2000; i++) {
  const id = composePhiSeal(randomFingerprint()).figureId;
  counts.set(id, (counts.get(id) ?? 0) + 1);
}
console.log('unique', counts.size);
console.log([...counts.entries()].sort((a,b)=>b[1]-a[1]).slice(0, 12).map(([k,v]) => `${k}:${v}`).join(' '));
