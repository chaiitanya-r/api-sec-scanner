import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT_DIR = path.resolve(__dirname, "../..");

async function clean() {
  console.log("Cleaning generated artifacts and temporary files...");

  // Files to remove directly
  const filesToRemove = [
    path.join(ROOT_DIR, "report.json"),
    path.join(ROOT_DIR, "report.html")
  ];

  for (const file of filesToRemove) {
    try {
      await fs.unlink(file);
      console.log(`✓ Removed ${path.relative(ROOT_DIR, file)}`);
    } catch {
      // not found, ignore
    }
  }

  // Clean reports directory (keep .gitkeep)
  const reportsDir = path.join(ROOT_DIR, "reports");
  try {
    const reportFiles = await fs.readdir(reportsDir);
    for (const f of reportFiles) {
      if (f !== ".gitkeep") {
        await fs.unlink(path.join(reportsDir, f));
        console.log(`✓ Removed reports/${f}`);
      }
    }
  } catch {
    // ignore
  }

  console.log("Clean complete.");
}

clean().catch((err) => {
  console.error("Clean failed:", err.message);
  process.exit(1);
});
