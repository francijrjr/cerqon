import { build } from "esbuild";
import { copyFile, readFile } from "node:fs/promises";

const pkg = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"));
await build({ entryPoints: ["src/index.ts"], outfile: "dist/index.js", bundle: true,
  platform: "node", format: "esm", target: "node20.19", external: Object.keys(pkg.dependencies),
});
await copyFile(new URL("../../../LICENSE", import.meta.url), new URL("../LICENSE", import.meta.url));
