import { readFileSync } from "node:fs";
import { resolve } from "node:path";

interface LabelSpec {
  name: string;
  color: string;
  description: string;
}

const token = process.env.GITHUB_TOKEN;
const repo = process.env.GITHUB_REPO ?? "VAIPROG/JustNewMCP";
const userAgent =
  process.env.HTTP_USER_AGENT ??
  "Mozilla/5.0 (compatible; Google-Agent; +https://developers.google.com/crawling/docs/crawlers-fetchers/google-agent)";

if (!token) {
  console.error("Missing GITHUB_TOKEN environment variable.");
  process.exit(1);
}

const labelsPath = resolve(import.meta.dir, "../.github/labels.json");
const labels = JSON.parse(readFileSync(labelsPath, "utf8")) as LabelSpec[];

const headers = {
  Authorization: `Bearer ${token}`,
  Accept: "application/vnd.github+json",
  "Content-Type": "application/json",
  "User-Agent": userAgent,
};

let created = 0;
let updated = 0;

for (const label of labels) {
  const encodedName = encodeURIComponent(label.name);
  const patchUrl = `https://api.github.com/repos/${repo}/labels/${encodedName}`;
  const patchRes = await fetch(patchUrl, {
    method: "PATCH",
    headers,
    body: JSON.stringify({
      new_name: label.name,
      color: label.color,
      description: label.description,
    }),
  });

  if (patchRes.ok) {
    updated += 1;
    continue;
  }

  if (patchRes.status !== 404) {
    const body = await patchRes.text();
    throw new Error(`Failed to update label "${label.name}": ${patchRes.status} ${body}`);
  }

  const postRes = await fetch(`https://api.github.com/repos/${repo}/labels`, {
    method: "POST",
    headers,
    body: JSON.stringify(label),
  });

  if (!postRes.ok) {
    const body = await postRes.text();
    throw new Error(`Failed to create label "${label.name}": ${postRes.status} ${body}`);
  }

  created += 1;
}

console.log(`Synced ${labels.length} labels to ${repo} (${created} created, ${updated} updated).`);
