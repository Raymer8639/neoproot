# English Discoverability Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Improve neoproot's discoverability for ARM64 Android/Termux users with English-first documentation, Chinese parity, actionable release material, and structured performance reports.

**Architecture:** Documentation remains the public source of truth. The English README is the primary landing page, the Chinese README mirrors its workflow, and GitHub issue metadata/templates provide searchable and reproducible entry points. Repository description/topics are updated through GitHub metadata after the documentation branch is ready.

**Tech Stack:** Markdown, GitHub Issue Forms YAML, GitHub CLI, git.

---

### Task 1: Rewrite the English landing page

**Files:**
- Modify: `README.md`

- [x] **Step 1: Replace the opening with an ARM64/Termux user-focused summary**

  Put the supported target, current release link, and a short install command before the lineage section. Name Node.js, pnpm, TypeScript, nvim, containers, and bwrap as representative workloads without promising universal compatibility.

- [x] **Step 2: Reorganize evidence and limitations**

  Keep the existing real benchmark table, label it as device/workload-specific, retain the x86_64 limitation, and move historical lineage below installation and usage guidance.

- [x] **Step 3: Verify links and Markdown**

  Run `git diff --check` and inspect all relative links with `rg -n '\]\(' README.md`.

### Task 2: Mirror the workflow in Chinese

**Files:**
- Modify: `README.zh-CN.md`

- [x] **Step 1: Mirror the English section order and commands**

  Translate the new summary, installation paths, workload examples, evidence caveat, and contribution links while preserving shell commands and URLs.

- [x] **Step 2: Verify parity**

  Compare headings and code blocks with `README.md`; run `git diff --check`.

### Task 3: Add launch and feedback material

**Files:**
- Create: `docs/ANNOUNCEMENT.md`
- Create: `.github/ISSUE_TEMPLATE/performance_report.yml`

- [x] **Step 1: Write the English announcement and Chinese translation**

  Include the target audience, the v5.9.1 release placeholder, verified feature highlights from the README, installation links, benchmark caveat, and a request for real-device reports. Keep Chinese immediately after each English section or in a clearly labeled translation section.

- [x] **Step 2: Add a reproducible performance issue form**

  Require neoproot version, device/SoC, Android version, Termux version, rootfs, workload command, baseline command/version, repeated results, and sanitized output. Include bilingual labels/descriptions and a sensitive-data checklist.

- [x] **Step 3: Validate YAML and Markdown**

  Run `ruby -e 'require "yaml"; YAML.load_file(".github/ISSUE_TEMPLATE/performance_report.yml")'` and `git diff --check`.

### Task 4: Update GitHub metadata

**Files:**
- GitHub repository metadata for `Raymer8639/neoproot`

- [x] **Step 1: Set an English repository description**

  Use `ARM64 Android/Termux PRoot fork for faster, more stable containers and modern Node.js/pnpm workflows.`

- [x] **Step 2: Add focused topics**

  Add `android`, `termux`, `proot`, `arm64`, `aarch64`, `linux`, `container`, `nodejs`, and `pnpm`.

- [x] **Step 3: Verify metadata**

  Run `gh repo view Raymer8639/neoproot --json description,repositoryTopics,url` and confirm the values.

### Task 5: Review and publish the documentation branch

**Files:**
- All files from Tasks 1-3.

- [x] **Step 1: Run repository checks**

  Run `git diff --check`, YAML parsing, and the existing documentation-only smoke checks available in the repository.

- [x] **Step 2: Inspect the final diff**

  Confirm no source files, Chinese study files, or unrelated generated files are staged.

- [x] **Step 3: Commit and push**

  Commit as `docs: improve English-first project discoverability` and push `codex/english-discoverability`.

- [x] **Step 4: Open a draft PR**

  Create a draft PR targeting `master` with a body describing the English-first README, Chinese parity, announcement, issue form, metadata, and validation commands.
