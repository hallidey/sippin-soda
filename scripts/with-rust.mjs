import { existsSync } from "node:fs";
import { spawn } from "node:child_process";
import { delimiter, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const env = { ...process.env };
const cargoHome = join(root, ".tools", "cargo");
const cargoBinary = join(
  cargoHome,
  "bin",
  process.platform === "win32" ? "cargo.exe" : "cargo",
);
const local = existsSync(cargoBinary);
if (local) {
  const pathKey =
    Object.keys(env).find((key) => key.toUpperCase() === "PATH") ?? "PATH";
  env[pathKey] = `${join(cargoHome, "bin")}${delimiter}${env[pathKey] ?? ""}`;
  env.CARGO_HOME = cargoHome;
  env.RUSTUP_HOME = join(root, ".tools", "rustup");
}
const [tool, ...args] = process.argv.slice(2);
if (tool !== "tauri" && tool !== "cargo")
  throw new Error("Expected tauri or cargo.");
const command =
  tool === "tauri" ? process.execPath : local ? cargoBinary : "cargo";
const commandArgs =
  tool === "tauri"
    ? [join(root, "node_modules", "@tauri-apps", "cli", "tauri.js"), ...args]
    : args;
const child = spawn(command, commandArgs, {
  cwd: root,
  env,
  stdio: "inherit",
  windowsHide: true,
});
child.on("error", (error) => {
  console.error(
    `Unable to start ${tool}: ${error.message}. Check the prerequisites in README.md.`,
  );
  process.exitCode = 1;
});
child.on("exit", (code) => {
  process.exitCode = code ?? 1;
});
