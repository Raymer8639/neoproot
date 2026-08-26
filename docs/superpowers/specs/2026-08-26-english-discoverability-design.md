# English Discoverability Design

## Goal

Make neoproot easier to discover and evaluate for ARM64 Android/Termux users while keeping the English README as the primary entry point and providing a Chinese counterpart.

## Scope

- Reorder and tighten `README.md` around the target user workflow: what neoproot is, supported environments, release installation, source installation, and measurable limitations.
- Keep `README.zh-CN.md` structurally aligned with the English README, with Chinese wording for the same commands and claims.
- Add an English release announcement draft with a Chinese translation for maintainers to post in GitHub Discussions or community channels.
- Add a performance-report issue form that requests reproducible device, Android, Termux, workload, and comparison details.
- Update the GitHub repository description and topics to match actual supported use cases.

## Non-goals

- No runtime or build-system changes.
- No unsupported architecture claims or synthetic benchmark data.
- No AI-generated social-preview image in this change; an actual terminal screenshot can be added later from a real device.
- Do not publish `v5.9.1` until the documentation PR is merged; the release will use the merged `master` commit.

## Content principles

- English is authoritative; Chinese mirrors the same information and links.
- State ARM64/Android/Termux scope in the first viewport.
- Put a copy-paste install path before lineage/history details.
- Describe performance as device/workload-specific and link to reproducible commands where possible.
- Prefer focused language that names pnpm, Node.js, TypeScript, nvim, containers, and bwrap users.
- Keep contribution and security guidance visible without making the landing page read like marketing copy.
