import { expect, it } from "vitest";
import { cq001ExcessiveToolPermission } from "@cerqon/risk-engine";
const base = { id: "x", name: "x", sourcePath: "x", adapterName: "test", servers: [] };
it("flags structured broad permissions", () => { expect(cq001ExcessiveToolPermission.evaluate({ config: { ...base, tools: [{ name: "tool", permissions: ["admin"] }] } })).toHaveLength(1); });
it("ignores descriptive words and ordinary explicit permissions", () => { expect(cq001ExcessiveToolPermission.evaluate({ config: { ...base, tools: [{ name: "read", description: "admin documentation", permissions: ["read"] }] } })).toEqual([]); });
