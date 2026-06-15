import { useMemo, useRef, useState } from "react";
import { Canvas, useFrame } from "@react-three/fiber";
import { Html } from "@react-three/drei";
import * as THREE from "three";
import type { Finding, Severity } from "../lib/types";
import { SEVERITY_META, SEVERITY_ORDER, vulnLabel } from "../lib/ui";

const prefersReducedMotion =
  typeof window !== "undefined" && window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;

interface Node {
  key: string;
  worst: Severity;
  count: number;
  pos: [number, number, number];
}

function worstSeverity(list: Finding[]): Severity {
  for (const s of SEVERITY_ORDER) if (list.some((f) => f.severity === s)) return s;
  return "info";
}

/** Fibonacci sphere — even distribution of endpoint nodes. */
function spherePositions(n: number, radius = 3): [number, number, number][] {
  const pts: [number, number, number][] = [];
  const phi = Math.PI * (3 - Math.sqrt(5));
  for (let i = 0; i < n; i++) {
    const y = 1 - (i / Math.max(1, n - 1)) * 2;
    const r = Math.sqrt(1 - y * y);
    const t = phi * i;
    pts.push([Math.cos(t) * r * radius, y * radius, Math.sin(t) * r * radius]);
  }
  return pts;
}

function NodeMesh({
  node,
  onSelect,
}: {
  node: Node;
  onSelect?: (k: string) => void;
}) {
  const [hover, setHover] = useState(false);
  const ref = useRef<THREE.Mesh>(null);
  const meta = SEVERITY_META[node.worst];
  const size = 0.1 + (5 - SEVERITY_ORDER.indexOf(node.worst)) * 0.03;
  const linePos = useMemo(
    () => new Float32Array([0, 0, 0, -node.pos[0], -node.pos[1], -node.pos[2]]),
    [node.pos]
  );

  useFrame((state) => {
    if (!ref.current) return;
    const pulse = 1 + Math.sin(state.clock.elapsedTime * 2 + node.pos[0]) * (hover ? 0.18 : 0.06);
    ref.current.scale.setScalar(pulse);
  });

  return (
    <group position={node.pos}>
      {/* connector to the core */}
      <line>
        <bufferGeometry>
          <bufferAttribute attach="attributes-position" args={[linePos, 3]} />
        </bufferGeometry>
        <lineBasicMaterial color={meta.hex} transparent opacity={hover ? 0.5 : 0.16} />
      </line>
      <mesh
        ref={ref}
        onPointerOver={(e) => {
          e.stopPropagation();
          setHover(true);
          document.body.style.cursor = "pointer";
        }}
        onPointerOut={() => {
          setHover(false);
          document.body.style.cursor = "auto";
        }}
        onClick={(e) => {
          e.stopPropagation();
          onSelect?.(node.key);
        }}
      >
        <sphereGeometry args={[size, 20, 20]} />
        <meshStandardMaterial
          color={meta.hex}
          emissive={meta.hex}
          emissiveIntensity={hover ? 1.1 : 0.55}
          roughness={0.35}
        />
      </mesh>
      {hover && (
        <Html center distanceFactor={9} zIndexRange={[20, 0]}>
          <div className="pointer-events-none -translate-y-8 whitespace-nowrap rounded-lg border border-line bg-ink-900/90 px-2.5 py-1.5 text-xs shadow-card backdrop-blur">
            <span className="font-mono text-fg">{node.key}</span>
            <span className="ml-2" style={{ color: meta.hex }}>
              {node.count} {node.count === 1 ? "issue" : "issues"}
            </span>
          </div>
        </Html>
      )}
    </group>
  );
}

function Graph({ nodes, onSelect }: { nodes: Node[]; onSelect?: (k: string) => void }) {
  const group = useRef<THREE.Group>(null);
  useFrame((_, delta) => {
    if (group.current && !prefersReducedMotion) group.current.rotation.y += delta * 0.12;
  });
  return (
    <group ref={group}>
      {/* core */}
      <mesh>
        <icosahedronGeometry args={[0.5, 0]} />
        <meshStandardMaterial color="#6E79E5" emissive="#6E79E5" emissiveIntensity={0.6} wireframe />
      </mesh>
      {nodes.map((n) => (
        <NodeMesh key={n.key} node={n} onSelect={onSelect} />
      ))}
    </group>
  );
}

export default function AttackSurface3D({
  findings,
  onSelect,
}: {
  findings: Finding[];
  onSelect?: (endpointKey: string) => void;
}) {
  const nodes = useMemo<Node[]>(() => {
    const byKey = new Map<string, Finding[]>();
    for (const f of findings) {
      const k = f.endpoint_key;
      byKey.set(k, [...(byKey.get(k) || []), f]);
    }
    const keys = [...byKey.keys()];
    const pos = spherePositions(keys.length, 3);
    return keys.map((k, i) => ({
      key: k,
      worst: worstSeverity(byKey.get(k)!),
      count: byKey.get(k)!.length,
      pos: pos[i],
    }));
  }, [findings]);

  return (
    <div className="relative h-[340px] w-full overflow-hidden rounded-2xl">
      <div className="absolute inset-0" aria-hidden="true">
        <Canvas dpr={[1, 1.75]} camera={{ position: [0, 0, 8], fov: 50 }} gl={{ alpha: true, antialias: true }}>
          <ambientLight intensity={0.6} />
          <pointLight position={[6, 6, 8]} intensity={1.2} />
          <Graph nodes={nodes} onSelect={onSelect} />
        </Canvas>
      </div>
      <div className="pointer-events-none absolute bottom-3 left-4 text-xs text-fg-subtle">
        {nodes.length} affected endpoint{nodes.length === 1 ? "" : "s"} · hover to inspect · click to jump
      </div>
      {/* Accessible, keyboard-operable equivalent of the 3D graph */}
      <ul className="sr-only" aria-label="Affected endpoints">
        {nodes.map((n) => (
          <li key={n.key}>
            <button type="button" onClick={() => onSelect?.(n.key)}>
              {n.key} — {SEVERITY_META[n.worst].label}, {n.count} {n.count === 1 ? "issue" : "issues"}
            </button>
          </li>
        ))}
      </ul>
    </div>
  );
}
