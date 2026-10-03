// JARVIS defense coverage, drawn from /api/coverage.
//
// What the scene means, so nothing in it is decoration:
//   outer shell   every ATT&CK technique, one tile per tactic it belongs to.
//                 Each tactic is a wedge, in attack order; inside a wedge the
//                 proven tiles fill from the top, so the lit share of a wedge
//                 is that tactic's coverage. Tiles have equal area.
//   tile style    solid = validated (a probe made the real detector fire),
//                 hollow = claimed (mapped, unproven), faint dot = blind.
//   inner nodes   the collectors. The arc around a node is the time since its
//                 last run against its interval. Red sparks = open critical or
//                 high findings. A node sits under the techniques it feeds;
//                 collectors that feed none ring the core.
//   pulses        a collector really ran: its stored timestamp advanced.
//   core          this machine, where every collector reports.
//
// Two readings of the same scene, cross-faded and alternating on a timer
// (or pinned with the buttons):
//   coverage      what is proven, as above.
//   uptime        is it watching right now. A tile is a gauge: its fill is the
//                 share of the last 24 h in which at least one collector that
//                 feeds it had fresh evidence. Nodes take the same colour and
//                 their outer ring is their own 24 h uptime. Blind tiles have
//                 no collector, so they stay empty: nothing can be up there.
import * as THREE from '/static/vendor/three.module.min.js';

const LEVELS = ['validated', 'regressed', 'claimed', 'blind'];
const LEVEL_TEXT = {
  validated: ['Validated', 'a probe made the real detector fire for at least one way of doing it'],
  claimed: ['Claimed', 'a collector is mapped, nothing proves it'],
  blind: ['Blind', 'no collector looks for it'],
  regressed: ['Regressed', 'a detector that should fire did not'],
};
const COLOR = { validated: 0x3ddbd0, claimed: 0xf2b84b, blind: 0x7d8fb8, regressed: 0xff5d6c };
const STYLE = { blind: 0, claimed: 1, validated: 2, regressed: 3 };
const STATE = { current: 0, stale: 1, failing: 2, missing: 3 };
const R = 6, ROWS = 8, ZMAX = 0.62, GAP = 0.9, NODE_R = 3.6, INFRA_R = 2.2;
const POLL_MS = 4000;
const calm = matchMedia('(prefers-reduced-motion: reduce)').matches;
const $ = (id) => document.getElementById(id);
const css = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const pretty = (t) => t.replace(/-/g, ' ');

// ── renderer, camera, orbit ────────────────────────────────────────────────
const canvas = $('scene');
const renderer = new THREE.WebGLRenderer({ canvas, antialias: true, alpha: false });
renderer.setPixelRatio(Math.min(devicePixelRatio, 2));
renderer.setClearColor(0x04060b, 1);
const scene = new THREE.Scene();
const camera = new THREE.PerspectiveCamera(42, 1, 0.1, 200);
const HOME = { theta: -0.75, el: 0.2, dist: 18.5 };
for (const [k, v] of new URLSearchParams(location.hash.slice(1))) if (k in HOME && isFinite(+v)) HOME[k] = +v;
const view = { ...HOME }, goal = { ...HOME };
let spin = !calm, lastTouch = 0, drag = null;

function resize() {
  renderer.setSize(innerWidth, innerHeight, false);
  camera.aspect = innerWidth / innerHeight;
  camera.updateProjectionMatrix();
}
addEventListener('resize', resize);
resize();

canvas.addEventListener('pointerdown', (e) => {
  drag = { x: e.clientX, y: e.clientY, moved: 0 };
  canvas.setPointerCapture(e.pointerId);
  canvas.classList.add('dragging');
});
canvas.addEventListener('pointermove', (e) => {
  if (drag) {
    const dx = e.clientX - drag.x, dy = e.clientY - drag.y;
    drag.x = e.clientX; drag.y = e.clientY; drag.moved += Math.abs(dx) + Math.abs(dy);
    goal.theta += dx * 0.006;
    goal.el = Math.max(-1.2, Math.min(1.2, goal.el + dy * 0.005));
    lastTouch = performance.now();
    hideTip();
  } else hover(e.clientX, e.clientY);
});
canvas.addEventListener('pointerup', (e) => {
  canvas.classList.remove('dragging');
  if (drag && drag.moved < 5) select(pick(e.clientX, e.clientY));
  drag = null;
});
canvas.addEventListener('pointerleave', hideTip);
canvas.addEventListener('wheel', (e) => {
  e.preventDefault();
  goal.dist = Math.max(9, Math.min(34, goal.dist * Math.exp(e.deltaY * 0.001)));
  lastTouch = performance.now();
}, { passive: false });

// ── static scenery: stars, core ────────────────────────────────────────────
function glowPoints(positions, size, color, opacity) {
  const g = new THREE.BufferGeometry();
  g.setAttribute('position', new THREE.Float32BufferAttribute(positions, 3));
  const m = new THREE.ShaderMaterial({
    transparent: true, depthWrite: false, blending: THREE.AdditiveBlending,
    uniforms: { uSize: { value: size }, uColor: { value: new THREE.Color(color) }, uOpacity: { value: opacity },
                uScale: { value: 1 } },
    vertexShader: `uniform float uSize; uniform float uScale;
      void main(){ vec4 mv = modelViewMatrix * vec4(position,1.); gl_Position = projectionMatrix * mv;
        gl_PointSize = uSize * uScale / -mv.z; }`,
    fragmentShader: `uniform vec3 uColor; uniform float uOpacity;
      void main(){ float r = length(gl_PointCoord - .5) * 2.; float a = exp(-r*r*5.) * uOpacity * step(r, 1.);
        gl_FragColor = vec4(uColor * a, a); }`,
  });
  return new THREE.Points(g, m);
}
{
  const p = [];
  let seed = 7;
  const rnd = () => (seed = (seed * 16807) % 2147483647) / 2147483647;
  for (let i = 0; i < 1100; i++) {
    const u = rnd() * 2 - 1, a = rnd() * Math.PI * 2, d = 60 + rnd() * 70, s = Math.sqrt(1 - u * u);
    p.push(d * s * Math.cos(a), d * u, d * s * Math.sin(a));
  }
  scene.add(glowPoints(p, 0.34, 0x9db4e0, 0.6));
}
const core = new THREE.Group();
const coreGlow = glowPoints([0, 0, 0], 3.4, 0x9fd0ff, 0.9);
const coreMesh = new THREE.LineSegments(
  new THREE.EdgesGeometry(new THREE.IcosahedronGeometry(0.62, 1)),
  new THREE.LineBasicMaterial({ color: 0xbfe0ff, transparent: true, opacity: 0.55, blending: THREE.AdditiveBlending, depthWrite: false }));
core.add(coreGlow, coreMesh);
scene.add(core);

// ── data-driven objects ────────────────────────────────────────────────────
let data = null, world = null, focus = null, pinned = null, signature = '';
const clock = new THREE.Clock();
const fireTimes = new Float32Array(64).fill(-100);

const tileMaterial = new THREE.ShaderMaterial({
  transparent: true, depthWrite: false, side: THREE.DoubleSide, blending: THREE.AdditiveBlending,
  uniforms: { uTime: { value: 0 }, uMix: { value: 0 } },
  vertexShader: `
    attribute vec3 aColor; attribute float aStyle; attribute vec2 aSize; attribute float aHi; attribute float aPulse; attribute float aUp;
    varying vec2 vP; varying vec2 vHalf; varying vec3 vColor; varying float vStyle; varying float vFace;
    varying float vHi; varying float vPulse; varying float vUp;
    void main(){
      vP = position.xy * aSize; vHalf = aSize * .5; vColor = aColor; vStyle = aStyle; vHi = aHi; vPulse = aPulse; vUp = aUp;
      vec4 mv = modelViewMatrix * instanceMatrix * vec4(position.xy * aSize, 0., 1.);
      vec3 n = normalize(normalMatrix * mat3(instanceMatrix) * vec3(0., 0., 1.));
      vFace = dot(n, normalize(-mv.xyz));
      gl_Position = projectionMatrix * mv;
    }`,
  fragmentShader: `
    uniform float uTime; uniform float uMix;
    varying vec2 vP; varying vec2 vHalf; varying vec3 vColor; varying float vStyle; varying float vFace;
    varying float vHi; varying float vPulse; varying float vUp;
    vec3 upColor(float f){ return f >= .98 ? vec3(.81, .89, 1.) : f >= .8 ? vec3(.95, .72, .29) : vec3(1., .36, .42); }
    float box(vec2 p, vec2 b, float r){ vec2 q = abs(p) - b + r; return length(max(q, 0.)) + min(max(q.x, q.y), 0.) - r; }
    void main(){
      vec2 b = vHalf * .74; float rad = min(b.x, b.y) * .34;
      float d = box(vP, b, rad);
      float w = fwidth(d) + .004;
      float fill = smoothstep(w, -w, d);
      float edge = smoothstep(.035 + w, .0, abs(d));
      float glow = exp(-max(d, 0.) * 9.);
      float a = 0.;
      if (vStyle > 2.5) {                       // regressed: hatched
        float hatch = step(.5, fract((vP.x + vP.y) * 6.));
        a = fill * (.25 + .5 * hatch) + edge * .9 + glow * .25;
      } else if (vStyle > 1.5) {                // validated: solid and lit
        a = fill * .62 + edge * .85 + glow * .34;
      } else if (vStyle > .5) {                 // claimed: hollow
        a = fill * .07 + edge * .95 + glow * .10;
      } else {                                  // blind: a faint outline and a dot
        float dotm = smoothstep(.07 + w, .05, length(vP));
        a = edge * .5 + dotm * .7;
      }
      // uptime reading: a gauge filled from the bottom; unfed tiles stay as blind ones do
      float au;
      if (vUp < 0.) {
        float dotm = smoothstep(.07 + w, .05, length(vP));
        au = edge * .4 + dotm * .6;
      } else {
        float level = (b.y - vP.y) / (2. * b.y);       // matches the way the instanced tiles are oriented on screen
        float lit = smoothstep(vUp - .02, vUp + .02, level);
        au = fill * (1. - lit) * .72 + fill * lit * .06 + edge * .85 + glow * (.12 + .2 * vUp);
      }
      vec3 base = mix(vColor, vUp < 0. ? vColor : upColor(vUp), uMix);
      a = mix(a, au, uMix);
      float pulse = exp(-max(uTime - vPulse, 0.) * 1.6) * step(vPulse, uTime);
      a *= (vFace > 0. ? 1. : .22) * vHi * (1. + pulse * 1.6);
      gl_FragColor = vec4(base * a, a);
    }`,
});

const beamMaterial = new THREE.ShaderMaterial({
  transparent: true, depthWrite: false, blending: THREE.AdditiveBlending,
  uniforms: { uTime: { value: 0 }, uFire: { value: fireTimes } },
  vertexShader: `
    attribute float aT; attribute float aJob; attribute vec3 aColor; attribute float aHi;
    uniform float uTime; uniform float uFire[64];
    varying vec3 vColor; varying float vA;
    void main(){
      float since = uTime - uFire[int(aJob + .5)];
      float p = since * .95 - aT;
      float pulse = exp(-p * p * 26.) * step(0., since) * step(since, 2.6);
      vColor = aColor; vA = (aHi > 1.5 ? .8 : aHi * .34) + pulse;
      gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.);
    }`,
  fragmentShader: `varying vec3 vColor; varying float vA; void main(){ gl_FragColor = vec4(vColor * vA, vA); }`,
});

const nodeMaterial = new THREE.ShaderMaterial({
  transparent: true, depthWrite: false, blending: THREE.AdditiveBlending,
  uniforms: { uTime: { value: 0 }, uScale: { value: 1 }, uMix: { value: 0 } },
  vertexShader: `
    attribute float aState; attribute float aProg; attribute float aFire; attribute float aRun; attribute float aHi; attribute float aUp;
    uniform float uScale; uniform float uTime;
    varying float vState; varying float vProg; varying float vFlash; varying float vRun; varying float vHi; varying float vUp;
    void main(){
      vState = aState; vProg = aProg; vRun = aRun; vHi = aHi; vUp = aUp;
      vFlash = exp(-max(uTime - aFire, 0.) * 1.3) * step(aFire, uTime);
      vec4 mv = modelViewMatrix * vec4(position, 1.);
      gl_Position = projectionMatrix * mv;
      gl_PointSize = (.6 + vFlash * .25) * uScale / -mv.z;
    }`,
  fragmentShader: `
    uniform float uTime; uniform float uMix;
    varying float vState; varying float vProg; varying float vFlash; varying float vRun; varying float vHi; varying float vUp;
    void main(){
      vec2 p = (gl_PointCoord - .5) * 2.; p.y = -p.y;
      float r = length(p);
      vec3 col = vState < .5 ? vec3(.81, .89, 1.) : vState < 1.5 ? vec3(.95, .72, .29) : vec3(1., .36, .42);
      vec3 ucol = vUp < 0. ? col : vUp >= .98 ? vec3(.81, .89, 1.) : vUp >= .8 ? vec3(.95, .72, .29) : vec3(1., .36, .42);
      col = mix(col, ucol, uMix);
      float w = fwidth(r) + .01;
      float disc = smoothstep(.24 + w, .24 - w, r);
      float hollow = smoothstep(.05, .0, abs(r - .21));
      float body = vState > 2.5 ? hollow : disc;               // missing: an empty ring
      float ang = fract(atan(p.x, p.y) / 6.2831853 + (vRun > .5 ? uTime * .9 : 0.));
      float ring = smoothstep(.07, .0, abs(r - .56));
      float arc = ring * (ang < (vRun > .5 ? .3 : vProg) ? 1. : .14) * (1. - .75 * uMix);
      float halo = exp(-r * r * 7.) * (.16 + vFlash * .9);
      float up = 0.;                                           // outer gauge: share of the last 24 h with fresh evidence
      if (vUp >= 0.) {
        float g = smoothstep(.05, .0, abs(r - .84));
        float turn = fract(atan(p.x, p.y) / 6.2831853);
        up = g * (turn < vUp ? .75 + .45 * uMix : .12 + .1 * uMix);
      }
      float a = (body * .8 + arc * .9 + halo + up) * vHi * step(r, 1.);
      gl_FragColor = vec4(col * a, a);
    }`,
});

function basis(angle, z) {
  // Longitude runs clockwise seen from above, so wedges read left to right from outside.
  const lon = -angle, c = Math.sqrt(1 - z * z);
  const n = new THREE.Vector3(c * Math.cos(lon), z, c * Math.sin(lon));
  const east = new THREE.Vector3(-Math.sin(lon), 0, Math.cos(lon));
  const north = new THREE.Vector3().crossVectors(n, east);
  return { n, east, north, c };
}

function build(d) {
  if (world) { scene.remove(world.group); world.group.traverse((o) => o.geometry && o.geometry.dispose()); }
  const group = new THREE.Group();
  const tactics = Object.keys(d.tactics);
  const rank = (t) => LEVELS.indexOf(t.level);
  const wedges = tactics.map((name) => {
    const list = d.techniques.filter((t) => t.tactics.includes(name))
      .sort((a, b) => rank(a) - rank(b) || a.tid.localeCompare(b.tid));
    return { name, list, cols: Math.max(1, Math.ceil(list.length / ROWS)) };
  });
  const unit = (Math.PI * 2) / (wedges.reduce((s, w) => s + w.cols, 0) + wedges.length * GAP);
  const dz = (2 * ZMAX) / ROWS;

  const places = [], byTid = {}, seps = [];
  let lon = 0;
  for (const w of wedges) {
    w.lon0 = lon + unit * GAP / 2;
    w.center = w.lon0 + (w.cols * unit) / 2;
    seps.push(lon);
    w.list.forEach((tech, i) => {
      const row = Math.floor(i / w.cols), col = i % w.cols;      // fill from the top, row by row
      const b = basis(w.lon0 + (col + 0.5) * unit, ZMAX - (row + 0.5) * dz);
      const place = { tech, tactic: w.name, n: b.n, pos: b.n.clone().multiplyScalar(R), index: places.length,
                      size: [unit * R * b.c * 0.96, (dz * R / b.c) * 0.96], b };
      places.push(place);
      (byTid[tech.tid] = byTid[tech.tid] || []).push(place);
    });
    lon = w.lon0 + w.cols * unit + unit * GAP / 2;
  }

  // tiles
  const tiles = new THREE.InstancedMesh(new THREE.PlaneGeometry(1, 1), tileMaterial, places.length);
  const col = new Float32Array(places.length * 3), style = new Float32Array(places.length);
  const size = new Float32Array(places.length * 2), hi = new Float32Array(places.length).fill(1);
  const pulse = new Float32Array(places.length).fill(-100);
  const upt = new Float32Array(places.length).fill(-1);
  const m = new THREE.Matrix4(), c = new THREE.Color();
  for (const p of places) {
    m.makeBasis(p.b.east, p.b.north, p.n).setPosition(p.pos);
    tiles.setMatrixAt(p.index, m);
    c.setHex(COLOR[p.tech.level]); c.toArray(col, p.index * 3);
    style[p.index] = STYLE[p.tech.level];
    size.set(p.size, p.index * 2);
  }
  const ia = (arr, n) => new THREE.InstancedBufferAttribute(arr, n);
  tiles.geometry.setAttribute('aColor', ia(col, 3));
  tiles.geometry.setAttribute('aStyle', ia(style, 1));
  tiles.geometry.setAttribute('aSize', ia(size, 2));
  tiles.geometry.setAttribute('aHi', ia(hi, 1));
  tiles.geometry.setAttribute('aPulse', ia(pulse, 1));
  tiles.geometry.setAttribute('aUp', ia(upt, 1));
  tiles.frustumCulled = false;
  group.add(tiles);

  // wedge separators and the two rims of the shell
  const guide = [];
  const arc = (f, steps) => { for (let i = 0; i < steps; i++) { guide.push(...f(i / steps), ...f((i + 1) / steps)); } };
  for (const s of seps) arc((t) => basis(s, -ZMAX - 0.03 + t * (2 * ZMAX + 0.06)).n.multiplyScalar(R).toArray(), 14);
  for (const z of [ZMAX + 0.03, -ZMAX - 0.03]) arc((t) => basis(t * Math.PI * 2, z).n.multiplyScalar(R).toArray(), 160);
  const gg = new THREE.BufferGeometry();
  gg.setAttribute('position', new THREE.Float32BufferAttribute(guide, 3));
  group.add(new THREE.LineSegments(gg, new THREE.LineBasicMaterial({
    color: 0x7f9bd0, transparent: true, opacity: 0.16, blending: THREE.AdditiveBlending, depthWrite: false })));

  // collectors: under the techniques they feed, or around the core
  const nodes = d.collectors.map((col_, index) => ({ c: col_, index, places: [] }));
  const byJob = Object.fromEntries(nodes.map((n) => [n.c.job, n]));
  for (const p of places) for (const job of p.tech.sources) if (byJob[job]) byJob[job].places.push(p);
  const feeders = nodes.filter((n) => n.places.length), infra = nodes.filter((n) => !n.places.length);
  for (const n of feeders) {
    const v = new THREE.Vector3();
    n.places.forEach((p) => v.add(p.n));
    if (v.lengthSq() < 1e-4) v.set(Math.cos(n.index), 0.2, Math.sin(n.index));
    n.pos = v.normalize().multiplyScalar(NODE_R);
  }
  for (let it = 0; it < 60; it++) {                // keep nodes apart on their sphere
    for (const a of feeders) for (const b of feeders) {
      if (a === b) continue;
      const delta = a.pos.clone().sub(b.pos), dist = delta.length();
      if (dist < 0.95) a.pos.add(delta.multiplyScalar((0.95 - dist) / (dist + 1e-3) * 0.3)).setLength(NODE_R);
    }
  }
  const areaOrder = [...new Set(infra.map((n) => n.c.area))];
  infra.sort((a, b) => areaOrder.indexOf(a.c.area) - areaOrder.indexOf(b.c.area));
  infra.forEach((n, i) => {
    const a = (i / infra.length) * Math.PI * 2;
    n.pos = new THREE.Vector3(Math.cos(a) * INFRA_R, Math.sin(a) * INFRA_R * 0.42, Math.sin(a) * INFRA_R * 0.9);   // a tilted ring
  });

  const ng = new THREE.BufferGeometry();
  ng.setAttribute('position', new THREE.Float32BufferAttribute(nodes.flatMap((n) => n.pos.toArray()), 3));
  for (const name of ['aState', 'aProg', 'aRun']) ng.setAttribute(name, new THREE.Float32BufferAttribute(new Float32Array(nodes.length), 1));
  ng.setAttribute('aFire', new THREE.Float32BufferAttribute(new Float32Array(nodes.length).fill(-100), 1));
  ng.setAttribute('aHi', new THREE.Float32BufferAttribute(new Float32Array(nodes.length).fill(1), 1));
  ng.setAttribute('aUp', new THREE.Float32BufferAttribute(new Float32Array(nodes.length).fill(-1), 1));
  const points = new THREE.Points(ng, nodeMaterial);
  points.frustumCulled = false;
  group.add(points);

  // beams: node -> each tile it feeds, and node -> core (it reports there)
  const SEG = 14, bp = [], bt = [], bj = [], bc = [], beams = [];
  const addBeam = (node, to, color, place) => {
    const first = bp.length / 3;
    c.setHex(color);
    for (let i = 0; i < SEG; i++) for (const t of [i / SEG, (i + 1) / SEG]) {
      bp.push(...node.pos.clone().lerp(to, t).toArray()); bt.push(t); bj.push(node.index); bc.push(c.r, c.g, c.b);
    }
    beams.push({ node, place, first, count: SEG * 2 });
  };
  const origin = new THREE.Vector3();
  for (const n of nodes) {
    addBeam(n, origin, 0x34507f, null);
    for (const p of n.places) addBeam(n, p.pos, COLOR[p.tech.level], p);
  }
  const bg = new THREE.BufferGeometry();
  bg.setAttribute('position', new THREE.Float32BufferAttribute(bp, 3));
  bg.setAttribute('aT', new THREE.Float32BufferAttribute(bt, 1));
  bg.setAttribute('aJob', new THREE.Float32BufferAttribute(bj, 1));
  bg.setAttribute('aColor', new THREE.Float32BufferAttribute(bc, 3));
  bg.setAttribute('aHi', new THREE.Float32BufferAttribute(new Float32Array(bt.length).fill(1), 1));
  const lines = new THREE.LineSegments(bg, beamMaterial);
  lines.frustumCulled = false;
  group.add(lines);

  // sparks: open critical and high findings, a few per node (exact counts are in the tooltip)
  const sparks = [];
  for (const n of nodes) {
    const open = n.c.findings.critical + n.c.findings.high;
    const count = open ? Math.min(5, Math.ceil(Math.log2(open + 1))) : 0;
    const up = n.pos.clone().normalize();
    const u = new THREE.Vector3().crossVectors(up, new THREE.Vector3(0.3, 1, 0.2)).normalize();
    const v = new THREE.Vector3().crossVectors(up, u);
    for (let i = 0; i < count; i++) sparks.push({ n, u, v, phase: (i / count) * Math.PI * 2 + n.index });
  }
  const sp = glowPoints(new Float32Array(Math.max(1, sparks.length) * 3), 0.42, 0xff5d6c, 1);
  sp.frustumCulled = false; sp.visible = sparks.length > 0;
  group.add(sp);

  scene.add(group);
  world = { group, wedges, places, byTid, tiles, nodes, byJob, points, lines, beams, sparks, sp };
  buildTags();
  applyFocus();
}

// ── live state ─────────────────────────────────────────────────────────────
function sync(d, first) {
  const t = clock.getElapsedTime();
  const g = world.points.geometry;
  for (const n of world.nodes) {
    const now = d.collectors.find((x) => x.job === n.c.job) || n.c;
    const ran = !first && now.ts && n.c.ts && now.ts > n.c.ts;
    n.c = now;
    g.attributes.aState.array[n.index] = STATE[now.state] ?? 3;
    g.attributes.aRun.array[n.index] = now.running ? 1 : 0;
    g.attributes.aUp.array[n.index] = now.uptime ? now.uptime.pct24 : -1;
    if (ran) fire(n, t);
  }
  g.attributes.aState.needsUpdate = g.attributes.aRun.needsUpdate = g.attributes.aUp.needsUpdate = true;
  const tu = world.tiles.geometry.attributes.aUp, by = Object.fromEntries(d.techniques.map((x) => [x.tid, x.uptime]));
  for (const p of world.places) tu.array[p.index] = by[p.tech.tid] == null ? -1 : by[p.tech.tid];
  tu.needsUpdate = true;
}

function fire(n, t) {
  fireTimes[n.index] = t;
  world.points.geometry.attributes.aFire.array[n.index] = t;
  world.points.geometry.attributes.aFire.needsUpdate = true;
  const pulse = world.tiles.geometry.attributes.aPulse;
  for (const p of n.places) pulse.array[p.index] = t + 1.0;     // when the beam's pulse arrives
  pulse.needsUpdate = true;
}

function ago(ts) {
  if (!ts) return 'never';
  const s = Math.max(0, Math.round(Date.now() / 1000 - ts));
  return s < 90 ? `${s}s ago` : s < 5400 ? `${Math.round(s / 60)} min ago` : s < 172800 ? `${Math.round(s / 3600)} h ago`
    : `${Math.round(s / 86400)} d ago`;
}
const every = (s) => (s < 90 ? `${s}s` : s < 5400 ? `${Math.round(s / 60)} min` : `${Math.round(s / 3600)} h`);

function hud() {
  const t = data.totals, total = t.total || 0;
  $('pct').textContent = total ? `${Math.round((100 * t.validated) / total)}%` : '–';
  $('sub').textContent = `${t.validated || 0} of ${total} ATT&CK techniques for Windows and Linux`;
  const shown = LEVELS.filter((l) => l !== 'regressed' || t.regressed);
  $('bar').innerHTML = shown.filter((l) => t[l]).map((l) =>
    `<i style="flex:${t[l]};background:${css('--' + l)};opacity:${l === 'blind' ? 0.55 : 1}"></i>`).join('');
  $('legend').innerHTML = shown.map((l) =>
    `<span class="glyph ${l}"></span><span class="l">${LEVEL_TEXT[l][0]}<small>${LEVEL_TEXT[l][1]}</small></span>` +
    `<span class="n num">${t[l] || 0}</span>`).join('');
  $('score').textContent = data.score ? `${data.score.score}%` : '–';
  $('mapage').textContent = data.map_at ? `map measured ${ago(data.map_at)}` : 'map not measured yet';
  $('tlist').innerHTML = Object.entries(data.tactics).map(([name, s]) =>
    `<button class="tactic${focus && focus.tactic === name ? ' on' : ''}" data-tactic="${esc(name)}">` +
    `<span class="name">${esc(pretty(name))}</span><span class="count num">${s.validated} / ${s.total}</span>` +
    `<span class="tbar">${shown.filter((l) => s[l]).map((l) =>
      `<i style="flex:${s[l]};background:${css('--' + l)};opacity:${l === 'blind' ? 0.5 : 1}"></i>`).join('')}</span></button>`).join('');
  uptimePanel();
  feed();
}

const upColor = (f) => (f >= 0.98 ? css('--node') : f >= 0.8 ? css('--claimed') : css('--regressed'));
const pctText = (f) => `${(100 * f).toFixed(f >= 0.9995 ? 0 : 1)}%`;
function strip(buckets) {
  return `<span class="strip">${buckets.map((f, k) => {
    const n = buckets.length - 1 - k, when = `${n}-${n + 1} h ago`;
    return f == null ? `<i class="unk" title="${when}: no history yet"></i>`
      : `<i style="background:${upColor(f)}" title="${when}: ${pctText(f)} fresh"></i>`;
  }).join('')}</span>`;
}

function uptimePanel() {
  const u = data.uptime;
  $('upct').textContent = u ? pctText(u.pct24) : '–';
  $('ustrip').innerHTML = u ? strip(u.buckets) : '';
  const worst = data.collectors.filter((c) => c.uptime).sort((a, b) => a.uptime.pct24 - b.uptime.pct24).slice(0, 3);
  $('uworst').innerHTML = worst.map((c) =>
    `<li><span>${esc(c.label)}</span>${strip(c.uptime.buckets)}<b class="num">${pctText(c.uptime.pct24)}</b></li>`).join('');
  $('unote').textContent = !u ? 'No collector receipts are stored yet.'
    : u.partial_history ? `${u.partial_history} began reporting within the window; time before their first run is not counted. A node's outer ring is its own 24 h uptime.`
      : "A node's outer ring is its own 24 h uptime.";
}

function feed() {
  if (!data) return;
  const cs = data.collectors, count = (s) => cs.filter((c) => c.state === s).length;
  const bad = count('stale') + count('failing') + count('missing');
  $('health').innerHTML = `<span><b class="num">${count('current')}</b> of ${cs.length} current</span>` +
    (bad ? `<span><b class="num">${bad}</b> not reporting</span>` : '') +
    (data.running.length ? `<span>running <b>${esc(data.running.join(', '))}</b></span>` : '');
  const recent = cs.filter((c) => c.ts).sort((a, b) => b.ts - a.ts).slice(0, 7);
  $('runs').innerHTML = recent.map((c) =>
    `<li><i class="dot ${c.state}"></i><span>${esc(c.label)}</span><time class="num">${ago(c.ts)}</time></li>`).join('');
}

// ── focus, picking, tooltip, detail ────────────────────────────────────────
function applyFocus() {
  if (!world) return;
  const f = pinned || focus;
  const tileHi = world.tiles.geometry.attributes.aHi, nodeHi = world.points.geometry.attributes.aHi;
  const beamHi = world.lines.geometry.attributes.aHi;
  const tileOn = (p) => !f || (f.tid ? p.tech.tid === f.tid : f.job ? p.tech.sources.includes(f.job) : p.tactic === f.tactic);
  const nodeOn = (n) => !f || (f.job ? n.c.job === f.job : f.tid ? n.places.some((p) => p.tech.tid === f.tid)
    : n.places.some((p) => p.tactic === f.tactic));
  for (const p of world.places) tileHi.array[p.index] = tileOn(p) ? (f ? 1.5 : 1) : 0.22;
  for (const n of world.nodes) nodeHi.array[n.index] = nodeOn(n) ? 1 : 0.25;
  for (const b of world.beams) {
    const on = !f ? 1 : (nodeOn(b.node) && (!b.place || tileOn(b.place))) ? 2 : 0.25;
    beamHi.array.fill(on, b.first, b.first + b.count);
  }
  tileHi.needsUpdate = nodeHi.needsUpdate = beamHi.needsUpdate = true;
}

const v3 = new THREE.Vector3();
function screen(pos) {
  v3.copy(pos).project(camera);
  return v3.z < 1 ? [(v3.x * 0.5 + 0.5) * innerWidth, (-v3.y * 0.5 + 0.5) * innerHeight] : null;
}
function pick(x, y) {
  if (!world) return null;
  let best = null, bestD = 22 * 22;
  for (const n of world.nodes) {
    const s = screen(n.pos); if (!s) continue;
    const dd = (s[0] - x) ** 2 + (s[1] - y) ** 2;
    if (dd < bestD) { bestD = dd; best = { job: n.c.job }; }
  }
  if (best) return best;
  bestD = 20 * 20;
  for (const p of world.places) {
    if (v3.copy(camera.position).sub(p.pos).dot(p.n) <= 0) continue;    // only the near side
    const s = screen(p.pos); if (!s) continue;
    const dd = (s[0] - x) ** 2 + (s[1] - y) ** 2;
    if (dd < bestD) { bestD = dd; best = { tid: p.tech.tid }; }
  }
  return best;
}
function describe(f) {
  if (f.job) {
    const c = world.byJob[f.job].c, fd = c.findings;
    const open = ['critical', 'high', 'medium', 'low'].filter((s) => fd[s]).map((s) => `${fd[s]} ${s}`).join(', ');
    return { kind: `Collector · ${c.state}${c.running ? ' · running now' : ''}`, title: c.label,
      text: `Last ran ${ago(c.ts)}, scheduled every ${every(c.interval)}. ` +
        `${open ? `Open findings: ${open}.` : 'No open findings.'} ` +
        (c.uptime ? `Up ${pctText(c.uptime.pct24)} of the last 24 h` +
          `${c.uptime.pct7d != null ? `, ${pctText(c.uptime.pct7d)} of 7 days` : ''}; longest silence ` +
          `${every(Math.max(c.uptime.longest_gap_s, 1))}. ` : 'No run receipts stored yet. ') +
        (c.techniques.length ? `Feeds ${c.techniques.length} technique${c.techniques.length > 1 ? 's' : ''}.`
          : 'Supports the monitor itself; mapped to no technique.'),
      strip: c.uptime ? c.uptime : null,
      chips: [c.job, c.area, ...c.techniques] };
  }
  const t = world.byTid[f.tid][0].tech;
  return { kind: `${t.tid} · ${LEVEL_TEXT[t.level][0]}`, title: t.name,
    text: (t.level === 'blind' ? 'No collector looks for this technique.' : t.evidence) +
      (t.uptime != null ? ` At least one of its collectors had fresh evidence ${pctText(t.uptime)} of the last 24 h.` : ''),
    chips: [...t.tactics.map(pretty), ...t.sources] };
}
function hover(x, y) {
  const f = pick(x, y);
  const same = JSON.stringify(f) === JSON.stringify(focus);
  if (!f) { if (focus && !focus.tactic) { focus = null; applyFocus(); } return hideTip(); }
  if (!same) { focus = f; applyFocus(); }
  const d = describe(f), tip = $('tip');
  tip.innerHTML = `<div class="k">${esc(d.kind)}</div><div class="t">${esc(d.title)}</div><div class="d">${esc(d.text)}</div>`;
  tip.style.display = 'block';
  const w = tip.offsetWidth, h = tip.offsetHeight;
  tip.style.left = `${Math.min(innerWidth - w - 12, x + 16)}px`;
  tip.style.top = `${Math.max(12, Math.min(innerHeight - h - 12, y - h - 12))}px`;
}
function hideTip() { $('tip').style.display = 'none'; }
function select(f) {
  pinned = f;
  if (!f) { $('detail').style.display = 'none'; return applyFocus(); }
  const d = describe(f);
  $('dbody').innerHTML = `<div class="k">${esc(d.kind)}</div><h3>${esc(d.title)}</h3><p>${esc(d.text)}</p>` +
    `<div class="chips">${d.chips.map((c) => `<span class="chip">${esc(c)}</span>`).join('')}</div>` +
    (d.strip ? `${strip(d.strip.buckets)}<div class="axis"><span>24 h ago</span><span>now</span></div>` : '');
  $('detail').style.display = 'block';
  applyFocus();
}
$('close').onclick = () => select(null);
$('tlist').addEventListener('click', (e) => {
  const b = e.target.closest('.tactic'); if (!b) return;
  const w = world.wedges.find((x) => x.name === b.dataset.tactic);
  const off = focus && focus.tactic === w.name;
  focus = off ? null : { tactic: w.name };
  pinned = null; $('detail').style.display = 'none';
  if (!off) {
    const turns = Math.round((view.theta + w.center) / (Math.PI * 2));
    goal.theta = -w.center + turns * Math.PI * 2; goal.el = 0.12; lastTouch = performance.now() + 6000;
  }
  applyFocus(); hud();
});
$('spin').onclick = (e) => { spin = !spin; e.target.setAttribute('aria-pressed', spin); };
$('spin').setAttribute('aria-pressed', spin);
$('reset').onclick = () => { Object.assign(goal, HOME, { theta: view.theta }); focus = pinned = null;
  $('detail').style.display = 'none'; applyFocus(); hud(); };
$('showtable').onclick = () => {
  const rows = [...data.techniques].sort((a, b) => LEVELS.indexOf(a.level) - LEVELS.indexOf(b.level) || a.tid.localeCompare(b.tid));
  $('tbody').innerHTML = '<table><thead><tr><th>Technique</th><th>Name</th><th>Level</th><th>Tactics</th><th>Collectors</th></tr></thead><tbody>' +
    rows.map((t) => `<tr><td class="num">${esc(t.tid)}</td><td>${esc(t.name)}</td><td>${LEVEL_TEXT[t.level][0]}</td>` +
      `<td>${esc(t.tactics.map(pretty).join(', '))}</td><td>${esc(t.sources.join(', ') || '—')}</td></tr>`).join('') + '</tbody></table>' +
    '<table><thead><tr><th>Collector</th><th>State</th><th>Last run</th><th>Up, 24 h</th><th>Up, 7 d</th><th>Longest silence, 24 h</th></tr></thead><tbody>' +
    [...data.collectors].sort((a, b) => (a.uptime ? a.uptime.pct24 : -1) - (b.uptime ? b.uptime.pct24 : -1)).map((c) =>
      `<tr><td>${esc(c.label)}</td><td>${esc(c.state)}</td><td>${ago(c.ts)}</td>` +
      `<td class="num">${c.uptime ? pctText(c.uptime.pct24) : '—'}</td>` +
      `<td class="num">${c.uptime && c.uptime.pct7d != null ? pctText(c.uptime.pct7d) : '—'}</td>` +
      `<td class="num">${c.uptime ? every(Math.max(c.uptime.longest_gap_s, 1)) : '—'}</td></tr>`).join('') + '</tbody></table>';
  $('table').style.display = 'block';
};
$('tclose').onclick = () => { $('table').style.display = 'none'; };
addEventListener('keydown', (e) => { if (e.key === 'Escape') { $('table').style.display = 'none'; select(null); } });

function buildTags() {
  $('tags').innerHTML = world.wedges.map((w, i) => {
    const s = data.tactics[w.name];
    return `<div class="tag" data-i="${i}">${esc(pretty(w.name))}<b class="num">${s.validated}/${s.total}</b></div>`;
  }).join('');
  world.tags = [...$('tags').children];
  world.wedges.forEach((w, i) => { w.tagPos = basis(w.center, ZMAX + (i % 2 ? 0.2 : 0.11)).n.multiplyScalar(R * 1.02); });
}

// ── polling ────────────────────────────────────────────────────────────────
async function poll() {
  try {
    const res = await fetch('/api/coverage', { cache: 'no-store' });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const d = await res.json();
    const sig = JSON.stringify(d.techniques.map((t) => [t.tid, t.level, t.sources])) + d.collectors.map((c) => `${c.job}:${Math.min(5, Math.ceil(Math.log2(c.findings.critical + c.findings.high + 1)))}`).join();
    const first = !world || sig !== signature;
    data = d;
    if (first) { signature = sig; build(d); }
    sync(d, first);
    hud();
    $('banner').style.display = 'none';
    if (!d.techniques.length) { $('banner').textContent = 'The coverage map has not been measured yet.'; $('banner').style.display = 'block'; }
  } catch (err) {
    // Never quiet: a view that cannot reach JARVIS says so and stops implying liveness.
    $('banner').textContent = `JARVIS is not answering (${err.message}). This view is not live.`;
    $('banner').style.display = 'block';
  }
}
poll();
setInterval(poll, POLL_MS);
setInterval(feed, 1000);

// ── frame ──────────────────────────────────────────────────────────────────
// ── the two readings: coverage and uptime ──────────────────────────────────
const MODE_MS = 14000, FADE_S = 1.6;
const MODE_TEXT = {
  coverage: ['What is proven', 'Tiles show how far each technique is proven. Nodes show when each collector last ran.'],
  uptime: ['Is it watching right now', 'Each tile fills with the share of the last 24 h that a collector feeding it had fresh evidence. Empty tiles have no collector.'],
};
let modeSetting = calm ? 'coverage' : 'auto', shown = 'coverage', mix = 0, flipAt = performance.now() + MODE_MS, lastT = 0;
function setMode(setting) {
  modeSetting = setting;
  if (setting !== 'auto') shown = setting;
  flipAt = performance.now() + MODE_MS;
  for (const b of document.querySelectorAll('#tools [data-mode]')) b.setAttribute('aria-pressed', b.dataset.mode === setting);
  paintMode();
}
function paintMode() {
  document.body.dataset.mode = shown;
  $('modename').textContent = MODE_TEXT[shown][0];
  $('modehint').textContent = MODE_TEXT[shown][1];
}
function stepMode(t) {
  const dt = Math.min(0.1, Math.max(0, t - lastT)); lastT = t;
  const held = pinned || focus || document.hidden || $('table').style.display === 'block';
  if (modeSetting === 'auto' && !held && performance.now() > flipAt) {
    shown = shown === 'coverage' ? 'uptime' : 'coverage';
    flipAt = performance.now() + MODE_MS;
    paintMode();
  }
  const target = shown === 'uptime' ? 1 : 0;
  mix = calm ? target : mix + (target - mix) * Math.min(1, dt / FADE_S * 3);
  if (Math.abs(target - mix) < 0.002) mix = target;
  tileMaterial.uniforms.uMix.value = nodeMaterial.uniforms.uMix.value = mix;
}
for (const b of document.querySelectorAll('#tools [data-mode]')) b.onclick = () => setMode(b.dataset.mode);
{ const m = new URLSearchParams(location.hash.slice(1)).get('mode'); setMode(m in MODE_TEXT || m === 'auto' ? m : modeSetting); mix = shown === 'uptime' ? 1 : 0; }

function frame() {
  const t = clock.getElapsedTime();
  if (spin && !drag && performance.now() - lastTouch > 2500) goal.theta += 0.0011;
  view.theta += (goal.theta - view.theta) * 0.08;
  view.el += (goal.el - view.el) * 0.08;
  view.dist += (goal.dist - view.dist) * 0.08;
  const ce = Math.cos(view.el);
  camera.position.set(view.dist * ce * Math.cos(view.theta), view.dist * Math.sin(view.el), view.dist * ce * Math.sin(view.theta));
  camera.lookAt(0, 0, 0);

  stepMode(t);
  const scale = renderer.domElement.height / (2 * Math.tan((camera.fov * Math.PI) / 360));
  tileMaterial.uniforms.uTime.value = beamMaterial.uniforms.uTime.value = nodeMaterial.uniforms.uTime.value = t;
  nodeMaterial.uniforms.uScale.value = scale;
  scene.traverse((o) => { if (o.isPoints && o.material.uniforms.uScale && o.material !== nodeMaterial) o.material.uniforms.uScale.value = scale; });
  coreMesh.rotation.y = t * 0.15; coreMesh.rotation.x = t * 0.07;
  coreGlow.material.uniforms.uOpacity.value = 0.75 + (calm ? 0 : Math.sin(t * 1.4) * 0.12);

  if (world) {
    const prog = world.points.geometry.attributes.aProg, nowS = Date.now() / 1000;
    for (const n of world.nodes) prog.array[n.index] = n.c.ts ? Math.min(1, (nowS - n.c.ts) / n.c.interval) : 0;
    prog.needsUpdate = true;
    if (world.sparks.length) {
      const pos = world.sp.geometry.attributes.position;
      world.sparks.forEach((s, i) => {
        const a = s.phase + (calm ? 0 : t * 0.9);
        v3.copy(s.n.pos).addScaledVector(s.u, Math.cos(a) * 0.3).addScaledVector(s.v, Math.sin(a) * 0.3);
        pos.setXYZ(i, v3.x, v3.y, v3.z);
      });
      pos.needsUpdate = true;
    }
    world.wedges.forEach((w, i) => {
      const tag = world.tags[i], s = screen(w.tagPos);
      const facing = v3.copy(camera.position).normalize().dot(w.tagPos.clone().normalize());
      const dim = (pinned || focus) && (pinned || focus).tactic && (pinned || focus).tactic !== w.name;
      tag.style.opacity = s ? Math.max(0, Math.min(1, (facing - 0.42) * 4)) * (dim ? 0.3 : 1) : 0;
      if (s) { tag.style.left = `${s[0]}px`; tag.style.top = `${s[1]}px`; }
    });
  }
  renderer.render(scene, camera);
  requestAnimationFrame(frame);
}
frame();
