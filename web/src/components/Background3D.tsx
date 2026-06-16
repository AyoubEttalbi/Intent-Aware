import { useMemo, useRef } from "react";
import { Canvas, useFrame, useThree } from "@react-three/fiber";
import * as THREE from "three";
import type { Grade } from "../lib/types";
import { GRADE_META } from "../lib/ui";

export type SceneMode = "idle" | "scanning" | "done";

const prefersReducedMotion =
  typeof window !== "undefined" && window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;

/* Monochrome core. The chrome carries no colour — the only colour the core ever
   takes is the GRADE hue on a verdict (meaningful, not decorative). Idle/scanning
   are pure neutral: near-white on dark, near-black zinc on light. */
function coreColor(mode: SceneMode, grade: Grade | undefined, isDark: boolean): THREE.Color {
  if (mode === "done" && grade) return new THREE.Color(GRADE_META[grade].hex);
  if (mode === "scanning") return new THREE.Color(isDark ? "#fafafa" : "#3f3f46");
  return new THREE.Color(isDark ? "#d4d4d8" : "#71717a");
}

/* ── Classic Ashima simplex noise (snoise) — inlined so the core can displace
      its vertices on the GPU without a texture. ─────────────────────────── */
const SNOISE = /* glsl */ `
vec4 permute(vec4 x){return mod(((x*34.0)+1.0)*x,289.0);}
vec4 taylorInvSqrt(vec4 r){return 1.79284291400159 - 0.85373472095314 * r;}
float snoise(vec3 v){
  const vec2 C = vec2(1.0/6.0, 1.0/3.0);
  const vec4 D = vec4(0.0, 0.5, 1.0, 2.0);
  vec3 i  = floor(v + dot(v, C.yyy));
  vec3 x0 = v - i + dot(i, C.xxx);
  vec3 g = step(x0.yzx, x0.xyz);
  vec3 l = 1.0 - g;
  vec3 i1 = min(g.xyz, l.zxy);
  vec3 i2 = max(g.xyz, l.zxy);
  vec3 x1 = x0 - i1 + 1.0 * C.xxx;
  vec3 x2 = x0 - i2 + 2.0 * C.xxx;
  vec3 x3 = x0 - 1.0 + 3.0 * C.xxx;
  i = mod(i, 289.0);
  vec4 p = permute(permute(permute(
       i.z + vec4(0.0, i1.z, i2.z, 1.0))
     + i.y + vec4(0.0, i1.y, i2.y, 1.0))
     + i.x + vec4(0.0, i1.x, i2.x, 1.0));
  float n_ = 1.0/7.0;
  vec3 ns = n_ * D.wyz - D.xzx;
  vec4 j = p - 49.0 * floor(p * ns.z *ns.z);
  vec4 x_ = floor(j * ns.z);
  vec4 y_ = floor(j - 7.0 * x_);
  vec4 x = x_ *ns.x + ns.yyyy;
  vec4 y = y_ *ns.x + ns.yyyy;
  vec4 h = 1.0 - abs(x) - abs(y);
  vec4 b0 = vec4(x.xy, y.xy);
  vec4 b1 = vec4(x.zw, y.zw);
  vec4 s0 = floor(b0)*2.0 + 1.0;
  vec4 s1 = floor(b1)*2.0 + 1.0;
  vec4 sh = -step(h, vec4(0.0));
  vec4 a0 = b0.xzyw + s0.xzyw*sh.xxyy;
  vec4 a1 = b1.xzyw + s1.xzyw*sh.zzww;
  vec3 p0 = vec3(a0.xy, h.x);
  vec3 p1 = vec3(a0.zw, h.y);
  vec3 p2 = vec3(a1.xy, h.z);
  vec3 p3 = vec3(a1.zw, h.w);
  vec4 norm = taylorInvSqrt(vec4(dot(p0,p0), dot(p1,p1), dot(p2,p2), dot(p3,p3)));
  p0 *= norm.x; p1 *= norm.y; p2 *= norm.z; p3 *= norm.w;
  vec4 m = max(0.6 - vec4(dot(x0,x0), dot(x1,x1), dot(x2,x2), dot(x3,x3)), 0.0);
  m = m * m;
  return 42.0 * dot(m*m, vec4(dot(p0,x0), dot(p1,x1), dot(p2,x2), dot(p3,x3)));
}`;

const VERT = /* glsl */ `
uniform float uTime;
uniform float uAmp;
uniform float uFreq;
varying float vNoise;
varying vec3 vNormalW;
varying vec3 vViewDir;
${SNOISE}
void main(){
  float n = snoise(normal * uFreq + uTime * 0.18);
  vNoise = n;
  vec3 displaced = position + normal * n * uAmp;
  vec4 worldPos = modelMatrix * vec4(displaced, 1.0);
  vNormalW = normalize(mat3(modelMatrix) * normal);
  vViewDir = normalize(cameraPosition - worldPos.xyz);
  gl_Position = projectionMatrix * viewMatrix * worldPos;
}`;

const FRAG = /* glsl */ `
precision highp float;
uniform vec3  uColor;
uniform vec3  uRim;
uniform float uOpacity;
uniform float uRimPower;
varying float vNoise;
varying vec3 vNormalW;
varying vec3 vViewDir;
void main(){
  float fres = pow(1.0 - clamp(dot(vNormalW, vViewDir), 0.0, 1.0), uRimPower);
  vec3 col = mix(uColor, uRim, fres);
  col += vNoise * 0.06;
  float alpha = uOpacity * (0.32 + fres * 0.85);
  gl_FragColor = vec4(col, alpha);
}`;

function makeCoreMaterial(wireframe: boolean) {
  return new THREE.ShaderMaterial({
    vertexShader: VERT,
    fragmentShader: FRAG,
    transparent: true,
    depthWrite: false,
    blending: THREE.NormalBlending,
    wireframe,
    uniforms: {
      uTime: { value: 0 },
      uAmp: { value: 0.16 },
      uFreq: { value: 1.5 },
      uColor: { value: new THREE.Color("#d4d4d8") },
      uRim: { value: new THREE.Color("#ffffff") },
      uOpacity: { value: 1 },
      uRimPower: { value: 2.2 },
    },
  });
}

function Core({ mode, grade, isDark }: { mode: SceneMode; grade?: Grade; isDark: boolean }) {
  const group = useRef<THREE.Group>(null);
  const geo = useMemo(() => new THREE.IcosahedronGeometry(1.65, 24), []);
  const solidMat = useMemo(() => makeCoreMaterial(false), []);
  const wireMat = useMemo(() => {
    const m = makeCoreMaterial(true);
    m.uniforms.uOpacity.value = isDark ? 0.6 : 0.3;
    m.uniforms.uRimPower.value = 1.6;
    return m;
  }, [isDark]);

  const target = useMemo(() => coreColor(mode, grade, isDark), [mode, grade, isDark]);
  const rim = useMemo(() => new THREE.Color(isDark ? "#ffffff" : "#a1a1aa"), [isDark]);

  useFrame((state, delta) => {
    const t = state.clock.elapsedTime;
    const working = mode === "scanning";
    const ampTarget = working ? 0.28 : mode === "done" ? 0.18 : 0.12;
    for (const m of [solidMat, wireMat]) {
      m.uniforms.uTime.value = prefersReducedMotion ? 0 : t;
      m.uniforms.uAmp.value += (ampTarget - m.uniforms.uAmp.value) * Math.min(1, delta * 2);
      (m.uniforms.uColor.value as THREE.Color).lerp(target, Math.min(1, delta * 3));
      (m.uniforms.uRim.value as THREE.Color).lerp(rim, Math.min(1, delta * 3));
    }
    // translucent core — the wireframe carries the structure, the shell only tints
    solidMat.uniforms.uOpacity.value = isDark ? 0.4 : 0.1;
    if (group.current && !prefersReducedMotion) {
      group.current.rotation.y += delta * (working ? 0.32 : 0.08);
      group.current.rotation.x = Math.sin(t * 0.15) * 0.18;
    }
  });

  return (
    <group ref={group}>
      <mesh geometry={geo} material={solidMat} />
      <mesh geometry={geo} material={wireMat} scale={1.012} />
    </group>
  );
}

function ParticleShell({ mode, isDark }: { mode: SceneMode; isDark: boolean }) {
  const ref = useRef<THREE.Points>(null);
  const count = 1100;
  const positions = useMemo(() => {
    const arr = new Float32Array(count * 3);
    for (let i = 0; i < count; i++) {
      const r = 2.6 + Math.random() * 3.4;
      const theta = Math.random() * Math.PI * 2;
      const phi = Math.acos(2 * Math.random() - 1);
      arr[i * 3] = r * Math.sin(phi) * Math.cos(theta);
      arr[i * 3 + 1] = r * Math.sin(phi) * Math.sin(theta);
      arr[i * 3 + 2] = r * Math.cos(phi);
    }
    return arr;
  }, []);
  const color = useMemo(() => new THREE.Color(isDark ? "#a1a1aa" : "#71717a"), [isDark]);

  useFrame((_, delta) => {
    if (!ref.current || prefersReducedMotion) return;
    const speed = mode === "scanning" ? 0.12 : 0.035;
    ref.current.rotation.y -= delta * speed;
    ref.current.rotation.x += delta * speed * 0.25;
  });

  return (
    <points ref={ref}>
      <bufferGeometry>
        <bufferAttribute attach="attributes-position" args={[positions, 3]} />
      </bufferGeometry>
      <pointsMaterial
        size={0.018}
        color={color}
        transparent
        opacity={mode === "idle" ? (isDark ? 0.55 : 0.45) : 0.85}
        sizeAttenuation
        depthWrite={false}
      />
    </points>
  );
}

function ScanSweep({ mode, grade, isDark }: { mode: SceneMode; grade?: Grade; isDark: boolean }) {
  const ref = useRef<THREE.Mesh>(null);
  const color = useMemo(() => coreColor(mode, grade, isDark), [mode, grade, isDark]);
  useFrame((state) => {
    if (!ref.current) return;
    const mat = ref.current.material as THREE.MeshBasicMaterial;
    if (prefersReducedMotion || mode === "idle") {
      mat.opacity = 0;
      return;
    }
    const t = state.clock.elapsedTime;
    ref.current.position.y = Math.sin(t * (mode === "scanning" ? 1.15 : 0.5)) * 2.4;
    ref.current.rotation.x = Math.PI / 2;
    mat.opacity = 0.5;
  });
  return (
    <mesh ref={ref}>
      <torusGeometry args={[2.9, 0.008, 8, 140]} />
      <meshBasicMaterial color={color} transparent opacity={0} />
    </mesh>
  );
}

/** Mouse-parallax rig — the whole scene leans gently toward the pointer. */
function Rig({ children }: { children: React.ReactNode }) {
  const ref = useRef<THREE.Group>(null);
  const { pointer } = useThree();
  useFrame(() => {
    if (!ref.current || prefersReducedMotion) return;
    ref.current.rotation.y += (pointer.x * 0.35 - ref.current.rotation.y) * 0.04;
    ref.current.rotation.x += (-pointer.y * 0.25 - ref.current.rotation.x) * 0.04;
  });
  // lifted so the core's mass sits behind the headline, not the form below it
  return (
    <group ref={ref} position={[0, 0.6, 0]}>
      {children}
    </group>
  );
}

export default function Background3D({
  mode = "idle",
  grade,
  isDark = true,
}: {
  mode?: SceneMode;
  grade?: Grade;
  isDark?: boolean;
}) {
  return (
    <div className="pointer-events-none absolute inset-0 -z-10" aria-hidden>
      <Canvas
        dpr={[1, 1.75]}
        camera={{ position: [0, 0, 8.4], fov: 50 }}
        gl={{ antialias: true, alpha: true, powerPreference: "high-performance" }}
        frameloop={prefersReducedMotion ? "demand" : "always"}
      >
        <Rig>
          <Core mode={mode} grade={grade} isDark={isDark} />
          <ParticleShell mode={mode} isDark={isDark} />
          <ScanSweep mode={mode} grade={grade} isDark={isDark} />
        </Rig>
      </Canvas>
      {/* dissolve the core into the page before it reaches the form/content */}
      <div className="absolute inset-0 bg-gradient-to-b from-bg/10 via-bg/55 to-bg" />
    </div>
  );
}
