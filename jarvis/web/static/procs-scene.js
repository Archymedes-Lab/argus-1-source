// The /procs 3D scene: what carries meaning, and nothing else moves.
//
//   disc        one per domain: Windows (the host) and Linux (the WSL guest).
//               The guest disc is tethered to vmmemWSL, the Windows process
//               that is the guest's virtual machine.
//   floor tree  parent to child, radially from each domain's centre. A
//               process whose parent has exited (or whose pid was reused by a
//               younger process) sits on the first ring as an orphan.
//   stem        height is CPU, linear: STEM_H is 100% of the machine.
//   sphere      size is resident memory (log scale); colour is the domain,
//               warm from 5% CPU, hot from 25%; red for alarm and amber for
//               notice (procs-model.js) override load.
//   ring        a process started; red rings pulse around alarm processes.
//   fade        a process exited.
//   ghost       a start Sysmon recorded that no 500 ms look caught.
//   grey scene  the feed is stale or down; nothing on screen is current, and
//               motion stops rather than pretend.
import * as THREE from '/static/vendor/three.module.min.js';

const STEM_H = 24;            // world units for 100% of the machine's CPU
const RING_GAP = 4.2;         // radius step per tree depth
const MAX_DEPTH = 9;
const BIRTH_MS = 1400, EXIT_MS = 900, GHOST_MS = 2200;
const HALO_MS = 2400, HALO_MAX = 12;   // alarm pulses: a bounded few per beat
const LABELS_MAX = 18;
const RINGS = 64;
const PALETTE_KEYS = ['bg', 'ink-3', 'win', 'lin', 'hot', 'warm', 'ghost', 'accent', 'new', 'recent'];

export class ProcScene {
  constructor(canvas, labelBox, state) {
    this.canvas = canvas;
    this.labelBox = labelBox;
    this.state = state;
    this.palette = {};
    this.query = '';
    this.onlyChanges = false;
    this.hovered = null;
    this.focused = null;
    this.order = [];
    this.fitted = false;
    this.dirty = true;
    this.animating = 0;
    this.haloAt = 0;
    this.orbit = { theta: -0.6, phi: 0.95, dist: 90, tx: 12, ty: 0, tz: 0, goal: null };
    this.tmp = { m4: new THREE.Matrix4(), q: new THREE.Quaternion(), v3: new THREE.Vector3(),
      s3: new THREE.Vector3(), col: new THREE.Color() };
    this.build();
    this.readPalette();
  }

  // ---- construction -----------------------------------------------------------

  build() {
    this.renderer = new THREE.WebGLRenderer({ canvas: this.canvas, antialias: true, alpha: false,
      powerPreference: 'low-power' });
    this.renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
    this.scene = new THREE.Scene();
    this.camera = new THREE.PerspectiveCamera(45, 1, 0.5, 2000);
    this.scene.add(new THREE.HemisphereLight(0xffffff, 0x666666, 2.2));
    const sun = new THREE.DirectionalLight(0xffffff, 1.2);
    sun.position.set(30, 80, 40);
    this.scene.add(sun);

    this.capacity = 0;
    this.spheres = null;
    this.sphereGeo = new THREE.SphereGeometry(1, 14, 10);
    this.sphereMat = new THREE.MeshLambertMaterial();
    this.stemGeo = new THREE.BufferGeometry();
    this.edgeGeo = new THREE.BufferGeometry();
    this.scene.add(
      new THREE.LineSegments(this.stemGeo, new THREE.LineBasicMaterial({ vertexColors: true, transparent: true, opacity: 0.75 })),
      new THREE.LineSegments(this.edgeGeo, new THREE.LineBasicMaterial({ vertexColors: true, transparent: true, opacity: 0.35 })));
    this.ensureCapacity(1);

    this.discs = {};
    for (const h of ['win', 'lin']) {
      const geo = new THREE.BufferGeometry();
      const pts = [];
      for (let i = 0; i <= 128; i++) { const a = i / 128 * Math.PI * 2; pts.push(Math.cos(a), 0, Math.sin(a)); }
      geo.setAttribute('position', new THREE.Float32BufferAttribute(pts, 3));
      const line = new THREE.Line(geo, new THREE.LineBasicMaterial({ transparent: true, opacity: 0.5 }));
      line.visible = false;
      this.scene.add(line);
      this.discs[h] = { line, cx: 0, cz: 0, r: 1, parents: new Map() };
    }

    // Rings come from a fixed pool, so a burst of starts cannot allocate.
    const ringGeo = new THREE.RingGeometry(0.9, 1, 48);
    ringGeo.rotateX(-Math.PI / 2);
    this.rings = [];
    this.ringNext = 0;
    for (let i = 0; i < RINGS; i++) {
      const mesh = new THREE.Mesh(ringGeo, new THREE.MeshBasicMaterial({ transparent: true, depthWrite: false,
        side: THREE.DoubleSide }));
      mesh.visible = false;
      this.scene.add(mesh);
      this.rings.push({ mesh, start: 0, dur: 0, max: 1 });
    }
    this.ray = new THREE.Raycaster();
    this.ndc = new THREE.Vector2();
  }

  ensureCapacity(n) {
    if (n <= this.capacity) return;
    this.capacity = Math.max(1024, 2 ** Math.ceil(Math.log2(n)));
    if (this.spheres) { this.scene.remove(this.spheres); this.spheres.dispose(); }
    this.spheres = new THREE.InstancedMesh(this.sphereGeo, this.sphereMat, this.capacity);
    this.spheres.instanceMatrix.setUsage(THREE.DynamicDrawUsage);
    this.spheres.setColorAt(0, new THREE.Color());
    this.scene.add(this.spheres);
    // Stems: 2 vertices per process. Edges: 2 per process plus the tether.
    for (const [geo, verts] of [[this.stemGeo, this.capacity * 2], [this.edgeGeo, this.capacity * 2 + 2]]) {
      for (const attr of ['position', 'color']) {
        geo.setAttribute(attr, new THREE.BufferAttribute(new Float32Array(verts * 3), 3).setUsage(THREE.DynamicDrawUsage));
      }
    }
  }

  readPalette() {
    const s = getComputedStyle(document.documentElement);
    for (const k of PALETTE_KEYS) this.palette[k] = new THREE.Color(s.getPropertyValue('--' + k).trim() || '#888');
    this.scene.background = this.palette.bg;
    for (const h of ['win', 'lin']) this.discs[h].line.material.color.copy(this.palette[h]);
    this.wake();
  }

  wake() { this.dirty = true; }

  resize(w, h) {
    this.renderer.setSize(w, h, false);
    this.camera.aspect = w / h;
    this.camera.updateProjectionMatrix();
    this.wake();
  }

  // ---- layout -------------------------------------------------------------------

  layout() {
    const state = this.state;
    state.structural = false;
    const byHost = { win: [], lin: [] };
    for (const p of state.procs.values()) if (!p.dying && byHost[p.h]) byHost[p.h].push(p);
    const radius = {};
    const trees = {};
    for (const h of Object.keys(byHost)) {
      trees[h] = tree(byHost[h]);
      radius[h] = trees[h].depth * RING_GAP + 2;
    }
    // Windows at the origin; the guest to its right, tethered to vmmemWSL.
    const d = this.discs;
    d.win.cx = 0; d.win.cz = 0; d.win.r = radius.win;
    d.lin.cx = radius.win + radius.lin + 8; d.lin.cz = 0; d.lin.r = radius.lin;
    for (const h of Object.keys(trees)) this.place(d[h], trees[h]);
    for (const p of state.procs.values()) {
      if (p.born && !p.pulsed && !p.dying) {
        p.pulsed = true;
        this.pulse(p.tx, p.tz, this.palette.accent, BIRTH_MS, 2.0);
      }
    }
    for (const h of ['win', 'lin']) {
      const src = state.sources[h];
      d[h].line.visible = !!(src && src.state && src.state !== 'absent');
      d[h].line.position.set(d[h].cx, 0, d[h].cz);
      d[h].line.scale.setScalar(d[h].r);
    }
    // Frame the scene once, when every present domain has reported; after that
    // the camera moves only when the viewer asks (drag, wheel, F, double-click).
    const reported = ['win', 'lin'].every((h) => state.sources[h]
      && (state.sources[h].state === 'absent' || byHost[h].length));
    if (!this.fitted && reported) this.fitted = this.fit();
  }

  place(disc, { roots, kids, leaves, total }) {
    let a0 = 0;
    const visit = (p, depth, from, span) => {
      const a = from + span / 2;
      const r = Math.min(depth, MAX_DEPTH) * RING_GAP;
      p.tx = disc.cx + Math.cos(a) * r; p.tz = disc.cz + Math.sin(a) * r;
      if (!Number.isFinite(p.x)) { p.x = p.tx; p.z = p.tz; }
      let f = from;
      for (const c of kids.get(p.id) || []) {
        const s = span * leaves.get(c.id) / leaves.get(p.id);
        visit(c, depth + 1, f, s); f += s;
      }
    };
    for (const r of roots) {
      const s = (Math.PI * 2) * leaves.get(r.id) / Math.max(1, total);
      visit(r, 1, a0, s); a0 += s;
    }
    disc.parents = new Map();
    for (const [pid, list] of kids) for (const c of list) disc.parents.set(c.id, this.state.procs.get(pid));
  }

  parentOf(p) {
    const parent = this.discs[p.h] && this.discs[p.h].parents.get(p.id);
    return parent && this.state.procs.has(parent.id) ? parent : null;
  }

  fit() {
    const shown = ['win', 'lin'].filter((h) => this.discs[h].line.visible);
    if (!shown.length) return false;
    const d = this.discs;
    const minX = Math.min(...shown.map((h) => d[h].cx - d[h].r));
    const maxX = Math.max(...shown.map((h) => d[h].cx + d[h].r));
    const maxR = Math.max(...shown.map((h) => d[h].r));
    this.orbit.goal = { x: (minX + maxX) / 2, y: 0, z: 0 };
    this.orbit.theta = Math.PI / 2;            // look along -z: the domains side by side
    this.orbit.phi = 0.9;
    const half = Math.max((maxX - minX) / 2 / Math.max(this.camera.aspect, 0.5), maxR);
    this.orbit.dist = Math.min(600, half / Math.tan(THREE.MathUtils.degToRad(this.camera.fov / 2)) * 1.25);
    this.wake();
    return true;
  }

  focus(p) { this.focused = p; this.orbit.goal = { x: p.x, y: 0, z: p.z }; this.wake(); }

  // ---- drawing ---------------------------------------------------------------------

  colorOf(p) {
    const { palette, tmp: { col } } = this;
    col.copy(palette[p.h]);
    if (p.cpu >= 25) col.copy(palette.hot);
    else if (p.cpu >= 5) col.lerp(palette.warm, 0.7);
    // The lens wins over load: an alarm is red whatever the process does.
    if (p.level === 'alarm') col.copy(palette.new);
    else if (p.level === 'notice') col.lerp(palette.recent, 0.85);
    else if (this.onlyChanges) col.lerp(palette.bg, 0.86);
    if (this.query && !this.state.matches(p, this.query)) col.lerp(palette.bg, 0.82);
    if (p === this.hovered || p === this.focused) col.lerp(palette.accent, 0.5);
    return col;
  }

  draw(now, dt) {
    const { state, palette, tmp: { m4, q, v3, s3 } } = this;
    this.animating = 0;
    const k = Math.min(1, dt * 7);
    this.order = [];
    for (const p of [...state.procs.values()]) {
      if (p.dying && now - p.dyingAt > EXIT_MS) state.remove(p.id);
      else this.order.push(p);
    }
    this.ensureCapacity(this.order.length + 1);
    const sp = this.stemGeo.attributes.position.array, sc = this.stemGeo.attributes.color.array;
    const ep = this.edgeGeo.attributes.position.array, ec = this.edgeGeo.attributes.color.array;
    let si = 0, ei = 0;
    this.order.forEach((p, i) => {
      if (Math.abs(p.tx - p.x) + Math.abs(p.tz - p.z) > 0.01) { p.x += (p.tx - p.x) * k; p.z += (p.tz - p.z) * k; this.animating++; }
      else { p.x = p.tx; p.z = p.tz; }
      const ty = STEM_H * Math.min(100, p.cpu) / 100;
      if (Math.abs(ty - p.y) > 0.005) { p.y += (ty - p.y) * k; this.animating++; } else p.y = ty;
      let size = 0.16 + 0.07 * Math.log2(1 + p.rss / 1024);
      if (p.level === 'alarm') size = Math.max(size * 1.5, 0.5);   // a change must be findable
      if (p.dying) { size *= Math.max(0, 1 - (now - p.dyingAt) / EXIT_MS); this.animating++; }
      if (p.born && now - p.bornAt < 300) { size *= (now - p.bornAt) / 300; this.animating++; }
      m4.compose(v3.set(p.x, p.y + size, p.z), q, s3.setScalar(size));
      this.spheres.setMatrixAt(i, m4);
      const c = this.colorOf(p);
      this.spheres.setColorAt(i, c);
      sp.set([p.x, 0, p.z, p.x, p.y, p.z], si * 3);
      sc.set([c.r, c.g, c.b, c.r, c.g, c.b], si * 3); si += 2;
      const parent = this.parentOf(p);
      const from = parent || { x: this.discs[p.h].cx, z: this.discs[p.h].cz };
      ep.set([from.x, 0, from.z, p.x, 0, p.z], ei * 3);
      const e = this.tmp.col.copy(palette[p.h]);
      if (this.onlyChanges && p.level !== 'alarm' && p.level !== 'notice') e.lerp(palette.bg, 0.86);
      ec.set([e.r, e.g, e.b, e.r, e.g, e.b], ei * 3); ei += 2;
    });
    // The tether: vmmemWSL is the guest's virtual machine.
    const vm = this.order.find((p) => p.h === 'win' && /^vmmem(WSL)?$/i.test(p.name) && !p.dying);
    if (vm && this.discs.lin.line.visible) {
      const t = palette['ink-3'];
      ep.set([vm.x, 0, vm.z, this.discs.lin.cx, 0, this.discs.lin.cz], ei * 3);
      ec.set([t.r, t.g, t.b, t.r, t.g, t.b], ei * 3); ei += 2;
    }
    this.spheres.count = this.order.length;
    this.spheres.instanceMatrix.needsUpdate = true;
    if (this.spheres.instanceColor) this.spheres.instanceColor.needsUpdate = true;
    for (const [geo, n] of [[this.stemGeo, si], [this.edgeGeo, ei]]) {
      geo.setDrawRange(0, n);
      geo.attributes.position.needsUpdate = true;
      geo.attributes.color.needsUpdate = true;
      geo.computeBoundingSphere();
    }
    this.spheres.computeBoundingSphere();
    for (const r of this.rings) {
      if (!r.mesh.visible) continue;
      const t = (now - r.start) / r.dur;
      if (t >= 1) { r.mesh.visible = false; continue; }
      r.mesh.scale.setScalar(0.3 + t * r.max);
      r.mesh.material.opacity = 0.9 * (1 - t);
      this.animating++;
    }
  }

  pulse(x, z, color, dur, max) {
    const r = this.rings[this.ringNext++ % this.rings.length];
    r.mesh.position.set(x, 0.02, z);
    r.mesh.material.color.copy(color);
    r.start = performance.now(); r.dur = dur; r.max = max;
    r.mesh.visible = true;
    this.wake();
  }

  // New ghosts from the state, and the alarm halo beat.
  pulses(now, live) {
    for (const g of this.state.ghosts.splice(0)) {
      const at = g.parent && Number.isFinite(g.parent.x) ? g.parent : { x: this.discs[g.h].cx, z: this.discs[g.h].cz };
      const color = g.level === 'alarm' ? this.palette.new : g.level === 'notice' ? this.palette.recent : this.palette.ghost;
      this.pulse(at.x, at.z, color, GHOST_MS, 2.4);
    }
    if (!live || now - this.haloAt < HALO_MS) return;
    this.haloAt = now;
    let n = 0;
    for (const p of this.state.procs.values()) {
      if (p.level !== 'alarm' || p.dying || !Number.isFinite(p.x)) continue;
      this.pulse(p.x, p.z, this.palette.new, HALO_MS * 0.9, 2.2);
      if (++n >= HALO_MAX) break;
    }
  }

  // One rendered frame when something moved. `live` false freezes motion.
  frame(now, dt, live) {
    if (this.state.structural) this.layout();
    const o = this.orbit;
    if (o.goal) {
      const kk = Math.min(1, dt * 5);
      o.tx += (o.goal.x - o.tx) * kk; o.tz += (o.goal.z - o.tz) * kk;
      if (Math.abs(o.goal.x - o.tx) + Math.abs(o.goal.z - o.tz) < 0.02) o.goal = null;
      this.dirty = true;
    }
    if (!this.dirty && !this.animating) return;
    this.draw(now, live ? dt : 0);
    if (!live) this.animating = 0;
    this.placeCamera();
    this.renderer.render(this.scene, this.camera);
    this.renderLabels();
    this.dirty = false;
  }

  placeCamera() {
    const { theta, phi, dist, tx, ty, tz } = this.orbit;
    this.camera.position.set(tx + dist * Math.sin(phi) * Math.cos(theta), ty + dist * Math.cos(phi),
      tz + dist * Math.sin(phi) * Math.sin(theta));
    this.camera.lookAt(tx, ty, tz);
  }

  renderLabels() {
    const alive = this.order.filter((p) => !p.dying);
    // Changes first; the busiest processes only when not focusing on changes.
    const chosen = new Set(alive.filter((p) => p.level === 'alarm').slice(0, LABELS_MAX));
    if (this.onlyChanges) for (const p of alive) { if (chosen.size >= LABELS_MAX) break; if (p.level === 'notice') chosen.add(p); }
    else for (const p of alive.filter((q) => q.cpu >= 0.5).sort((a, b) => b.cpu - a.cpu).slice(0, 6)) chosen.add(p);
    if (this.hovered) chosen.add(this.hovered);
    if (this.focused && this.state.procs.has(this.focused.id)) chosen.add(this.focused);
    if (this.query) for (const p of alive) { if (chosen.size >= LABELS_MAX) break; if (this.state.matches(p, this.query)) chosen.add(p); }
    const v3 = this.tmp.v3;
    const html = [];
    for (const p of chosen) {
      v3.set(p.x, p.y + 0.6, p.z).project(this.camera);
      if (v3.z > 1) continue;
      const x = (v3.x + 1) / 2 * innerWidth, y = (1 - v3.y) / 2 * innerHeight;
      html.push(`<div style="left:${x.toFixed(0)}px;top:${y.toFixed(0)}px">${esc(p.name)}${p.cpu >= 0.5 ? ' · ' + p.cpu.toFixed(1) + '%' : ''}</div>`);
    }
    this.labelBox.innerHTML = html.join('');
  }

  // ---- camera input ------------------------------------------------------------------

  bindInput(onPick, onHover) {
    const c = this.canvas, o = this.orbit;
    let drag = null;
    c.addEventListener('pointerdown', (e) => {
      drag = { x: e.clientX, y: e.clientY, moved: false };
      c.setPointerCapture(e.pointerId); c.classList.add('dragging');
    });
    c.addEventListener('pointerup', (e) => {
      c.classList.remove('dragging');
      if (drag && !drag.moved) onPick(this.pick(e.clientX, e.clientY));
      drag = null; this.wake();
    });
    c.addEventListener('pointermove', (e) => {
      if (drag) {
        const dx = e.clientX - drag.x, dy = e.clientY - drag.y;
        if (Math.abs(dx) + Math.abs(dy) > 3) drag.moved = true;
        o.theta += dx * 0.005;
        o.phi = Math.min(1.45, Math.max(0.15, o.phi - dy * 0.005));
        drag.x = e.clientX; drag.y = e.clientY; o.goal = null; this.wake();
        return;
      }
      const p = this.pick(e.clientX, e.clientY);
      if (p !== this.hovered) { this.hovered = p; this.wake(); }
      onHover(p, e.clientX, e.clientY);
    });
    c.addEventListener('pointerleave', () => { this.hovered = null; onHover(null); this.wake(); });
    c.addEventListener('wheel', (e) => {
      e.preventDefault();
      o.dist = Math.min(600, Math.max(12, o.dist * Math.exp(e.deltaY * 0.001)));
      this.wake();
    }, { passive: false });
    c.addEventListener('dblclick', () => this.fit());
  }

  pick(x, y) {
    if (!this.spheres || !this.order.length) return null;
    this.ndc.set((x / innerWidth) * 2 - 1, -(y / innerHeight) * 2 + 1);
    this.ray.setFromCamera(this.ndc, this.camera);
    const hit = this.ray.intersectObject(this.spheres, false)[0];
    return hit && hit.instanceId != null ? this.order[hit.instanceId] || null : null;
  }
}

// The parent-to-child tree of one domain, sized for a radial layout.
function tree(list) {
  const byPid = new Map(list.map((p) => [p.pid, p]));
  const kids = new Map();
  const roots = [];
  for (const p of list) {
    const parent = byPid.get(p.ppid);
    // A parent must predate its child; otherwise the pid was reused.
    if (parent && parent !== p && parent.created <= p.created + 1000) {
      if (!kids.has(parent.id)) kids.set(parent.id, []);
      kids.get(parent.id).push(p);
    } else roots.push(p);
  }
  const order = (a, b) => (a.created - b.created) || (a.pid - b.pid);
  roots.sort(order);
  for (const v of kids.values()) v.sort(order);
  const leaves = new Map();
  const count = (p) => {
    let n = 0;
    for (const c of kids.get(p.id) || []) n += count(c);
    leaves.set(p.id, Math.max(1, n));
    return Math.max(1, n);
  };
  let total = 0, depth = 1;
  for (const r of roots) total += count(r);
  const deepen = (p, d) => { depth = Math.max(depth, d); for (const c of kids.get(p.id) || []) deepen(c, Math.min(d + 1, MAX_DEPTH)); };
  for (const r of roots) deepen(r, 1);
  return { roots, kids, leaves, total, depth };
}

export const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
