# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

See [VERSIONING.md](VERSIONING.md) for why the version starts at 1.8.1.

## [1.17.0] - 2026-09-20

### Added

- **Insomnia request credentials in the credential inventory**: a new `insomnia` source, under a new `api_clients` category, reports one finding per Insomnia database file under the platform data root (`~/Library/Application Support/Insomnia`, `%APPDATA%\Insomnia`, `$XDG_CONFIG_HOME/Insomnia` with a `~/.config` fallback) or under `INSOMNIA_DATA_PATH`. Fourteen databases are read: request, folder, WebSocket, Socket.IO and MCP authentication material by auth type; `Authorization`, `Proxy-Authorization`, `X-API-Key` and `API-Key` headers and gRPC metadata; credential-named environment variables; secret-typed variables, where a valid encrypted envelope is `protected`, a raw value `plaintext` and a malformed envelope `unrecognized_format`; OAuth2 access, refresh and identity tokens; client-certificate passphrases; and the GitCredentials, legacy GitRepository, CloudCredential and UserSession stores. Every retained record within bounds is counted, including deleted and superseded ones, because bytes stay in the file until compaction. Each database read is bounded to 8 MiB and its count to 10,000, and compressed request history to 8 MiB of expansion per file; reaching a limit reports `capped`, `truncated` and an incomplete scan rather than a clean one. Template-only values are references, not material. As with every other source, only locations, counts and protection state are reported — never a value, digest or fingerprint. On macOS only the fixed Insomnia catalog files and their ancestors are exempt from the `~/Library` guard. The credential catalog version is now 2.
- **Kiro IDE, five more AI CLIs, and wider skills coverage**: Grok Build (xAI), Kimi Code (Moonshot), Muse Code (Meta), Hermes Agent (Nous Research) and Oh My Pi (Stencil) join the AI CLI inventory, and Kiro IDE is reported separately from Kiro CLI at its fixed roots (`/Applications/Kiro.app`, `%LOCALAPPDATA%\Programs\Kiro`, `/usr/share/kiro`) once the root itself proves it is Kiro from bundle or manifest metadata. The five new CLIs and Kiro CLI (still reported as `amazon-q-cli`, vendor Amazon) are identified from installation metadata rather than by accepting a same-name binary, and none is ever launched to read a version — package manifests, versioned paths, Python `dist-info` names, the Muse sidecar, macOS bundle metadata, Windows HKCU installer metadata (query-only) or Linux dpkg ownership supply it, and `unknown` is reported otherwise. Earlier releases ran every `kiro-cli`/`kiro`/`q` on `$PATH` with `--version`. The skills inventory adds user and project roots for the five new agents plus Kiro, Windsurf (including its managed system roots), Antigravity, OpenClaw's default workspace and Codex project skills; the singular `.agent/skills` root keeps its `factory_agent_*` labels but is attributed to the shared agent, since Factory and Antigravity both read it. Windows directory junctions are handled alongside Unix symlinks — a linked skill folds into the physical skill's record while a copy stays a separate instance — and linked-skill traversal goes through a guarded reader that checks the destination against the allowed roots and macOS TCC policy before following it.
- **WSL inventory and in-distro scanning on Windows** (#57): `device.wsl` reports registered WSL distributions and whether any is running. The inventory comes from an HKU registry walk, so a SYSTEM-context scan still sees a signed-in user's distros, plus the `WslService`/`LxssManager` service check; `System32\wsl.exe` alone is never a presence signal. Each distro carries its WSL1/WSL2 version (from the `Flags` bit — the `Version` DWORD reads 2 on WSL1), its stable `distro_id` GUID, and its `default_uid`. The running-distro probe, `wsl --list --running`, is gated on the service already being up, because the command itself starts a stopped `WslService`. When the tenant enables it through the `wsl_directive` block of the existing run-config check-in, a new `wsl_scan` phase launches the agent's Linux build inside each *running* distro over its `/mnt/c` mount, pointed at the host's config, and returns as soon as it has started: the distro's own agent owns its upload, gates itself under a derived guest device id (a UUIDv5 of host serial and distro id) so the tenant's cadence applies to distros too, and carries a `wsl_guest` block that lets the backend pair it to its host. A stopped distro is never started, and a distro whose default user is root is skipped. The switch fails closed — an absent block, a backend predating the field, an explicit `enabled:false`, a failed check-in or a bypassed cadence gate all leave distro scanning off; `STEPSEC_FORCE_WSL_SCAN=1` is the only local escape. The MSI now ships the Linux agent as a third component (`dmg-linux`, amd64 and arm64 so Windows on ARM works), about 11–12 MB, which Windows never executes itself. Rendered in pretty and HTML output; feature gate `wsl-detection`.
- **Tenant switch for credential scanning**: the run-config check-in may now carry `{"scanners":{"credentials":{"enabled":false}}}`, and the agent reads it on every invocation. Disabled means no detector is constructed, no credential file is read, no `credentials_scan` phase is recorded and no `credential_scan` key is uploaded; every other phase runs as before. Nothing is persisted — each run starts enabled and is disabled only by an explicit `false` in its own check-in, so a missing, null, malformed or non-200 answer scans. `--force-scan`, `STEPSEC_FORCE_SCAN` and `STEPSEC_DISABLE_RUN_GATE` still bypass cadence only; they still perform the check-in, so a fresh `false` applies to a forced run too. `scan_directive` and `scanners` are decoded independently, so a malformed cadence block cannot discard a valid credential answer, and a response without `scan_directive` is no longer an error. The check-in response cap rises from 64 KiB to 4 MiB to match the device-policy client.
- **PyPI package-configuration device policy**: a `package_config/pypi` policy reconciles pip, uv and `.netrc` for the resolved user so both clients resolve through the tenant's registry. pip's config gets `index-url` in `[global]`, `uv.toml` gets a default `[[index]]` with `index-strategy = "first-index"` and `authenticate = "always"`, and the credential is stored only in `.netrc` (`_netrc` on Windows), never in a client config. Each client gets an independent outcome and the report is an aggregate, secret-free observation. Managed files get the same protection as the npm lane: confined path traversal, symlink checks, atomic replacement, bounded backups, ownership validation, rollback, POSIX modes and Windows ACLs verified through reparse-point-safe handles. DMG enforcement and component-scoped MDM verify-only observation are both supported, and Python is never executed.
- **Go package-configuration device policy**: a `package_config/go` policy manages `GOPROXY` in the default Go environment file (`~/.config/go/env`, `~/Library/Application Support/go/env`, or `%APPDATA%\go\env`; a `GOENV` pointing elsewhere is honoured) and the registry credential it shares with PyPI in `.netrc`, through the same secure-file, ownership, rollback and reporting seams. Supports DMG enforcement, MDM verification, reversible clear, drift repair and cross-target credential retention — clearing Go leaves a PyPI-owned credential in place and vice versa — without executing Go. CRLF markers on Windows are recognised on both the write and the verify path.
- **Managed npm settings**: the `package_config#npm` policy may now carry additional npm settings beside, or instead of, the StepSecurity registry pair. Settings are strictly validated and rendered deterministically (byte-sorted) into the managed `~/.npmrc` block; a settings-only policy treats `registry` as an ordinary last-wins setting and restores a previously prefixed user registry line on the transition. Reconciliation flows through the existing DMG and MDM ownership paths with reversible clear and secret-free aggregate observation, and fails closed on unsafe mixed ownership, ambiguous npm syntax, normalised-key collisions and invalid value shapes. Enforcement failures now log at the default level. The pip, uv, Go env and netrc markers introduced in this release use the provider-neutral Package Configuration contract.
- **macOS network-volume scan toggle and PPPC pre-approval path** (#177): container runtimes expose the guest filesystem through mounts macOS classifies as *network volumes* (OrbStack's `~/OrbStack`, Docker Desktop and Colima shares), so the first scan that walks one fires a `SystemPolicyNetworkVolumes` prompt naming a process the developer doesn't recognize. That walk stays **on by default** — it is what inventories npm and Python packages inside dev containers, supply-chain surface nothing else covers — but MDM fleets now have both ways out. `include_network_volumes: false` (config) or `--no-include-network-volumes` (CLI) skips every non-local mount, enumerated from the kernel mount table via `getfsstat` rather than a hard-coded path list, so a newly installed runtime is covered without an agent change; the run then logs exactly which mounts it gave up. A mount named explicitly as a walk root (`--search-dirs ~/OrbStack`) is still walked in full. Alternatively `packaging/macos/stepsecurity-dev-machine-guard-tcc.mobileconfig` pre-answers the prompt for the whole fleet (allow *or* deny) alongside the existing Full Disk Access grant, with its code requirement bound to the Dev Machine Guard binary identifier rather than the signing team alone — that route needs a fixed system-wide install path, since PPPC identifiers can't express `$HOME`, and `docs/macos-tcc-permissions.md` now carries the migration steps for a fleet already deployed per-user. Default runs behave exactly as before the toggle.
- **`execguard` now answers on Linux, not just macOS.** It was a macOS-only gate, so every Linux exec fallback ran unguarded. On Linux it now refuses a binary that is a packaged Electron app's entry point, decided from stats alone: an Electron bundle ships `resources/app.asar` and the Chromium runtime beside its executable, and nothing else does. Only the binary's own directory is examined, which is what separates the app from its CLI — `/usr/share/code/code` sits beside `libffmpeg.so` and is refused, while the shim at `/usr/share/code/bin/code` does not and is allowed. Checking the parent too, as the macOS quarantine probe must because cask installs mark whole trees, would have rejected exactly the shims we need. Electron-only is deliberate: a GTK or Qt app on `$PATH` would need its own signal. macOS and Windows behavior are unchanged. The IDE detector now consults the guard too — it was the one version-probe path that never did.
- **Three static version sources for Linux**, so fewer tools reach an exec at all. **dpkg**: the version of the package that owns the binary, proved from the package's own file manifest rather than assumed from a matching name, so a stale `foo` package cannot lend its version to a hand-installed `/usr/local/bin/foo`; purged packages are rejected. **snap**: the `version` field of `/snap/<name>/current/meta/snap.yaml`, which no path rule could reach since `/snap/bin/<name>` symlinks to the snap wrapper. **AppImage**: the version in the filename, the only static source a single-file install has; the tool-name prefix must match. All three are plain file reads, mirroring the existing static pacman-database reads.
- **Per-run CPU and memory profiling**: both dispatch paths now log what a run cost (`resource usage: wall=… cpu=… cpu_pct=… peak_rss=…`) at info level and append one JSON record per run to `run-metrics.jsonl` in the install dir, capped at the newest 200. Enterprise runs also log a per-phase CPU breakdown, and emit both lines before the execution-log snapshot so they ship inside the `ExecutionLogs` payload rather than only appearing on a local terminal. Subprocess CPU is included on Linux and macOS via `getrusage(RUSAGE_CHILDREN)`; Windows has no equivalent, so its records set `children_attributed: false` rather than silently reporting a smaller number.

### Changed

- **The scan-state delta upload protocol is now on by default.** `use_legacy_package_scan` defaults to `false`, so a run uploads full npm and Python package bodies only for projects whose inventory hash changed, ships refs for the unchanged and removed ones, and re-asserts the whole picture on a full sync — weekly, or after an agent-version change. Requires a backend that understands `payload_schema_version` 1. Measured on Ubuntu 24.04 at 2000 npm plus 600 Python packages: the npm and Python inventory drops out of a settled payload entirely, taking the whole payload down 27.5% (22.7% gzipped). Scan time is unchanged — the scan still walks everything, so the saving is upload bytes, not runtime, and `system_package_scans` caps it. Set `use_legacy_package_scan=true` in config.json to hold a fleet on full-snapshot uploads; `STEPSEC_DISABLE_SCAN_STATE=1` forces legacy for one run.
- **The malicious-file scanner pre-filters the walk by filename.** Every relative glob regex used to run against every regular file walked — 47 full-path checks per file on the current rule bundle — although most files can never match because their name matches no rule. Globs whose final segment is fixed now feed a filename index consulted before `filepath.Rel` or any regex; a glob with `*` or `?` in its final segment disables the index and falls back to the original flat matcher loop, preserving matcher order and `matched_glob` selection. Reference measurement on 200,000 non-matching files across 2,001 directories: 33.98s → 0.21s, with byte-identical `RuleScan` output.
- Reduce malicious-file scan CPU and allocations by checking mandatory conditions before optional evidence and constructing paths only for directories and candidate files. Retain filename indexes with wildcard rules, prune disjoint literal prefixes, reuse bounded file reads and metadata, and retire truncated rules. Detection coverage, rule ordering, and reported evidence are preserved. On Fedora with the production four-rule bundle: 35% lower scan-phase CPU, 36% less phase time, 37% fewer allocated bytes, identical findings.
- **Community download instructions** in the README and community-mode guide now resolve the latest release tag and use the current `stepsecurity-dev-machine-guard-<version>-<os>` asset names; the `_windows_amd64.exe` / `_linux_amd64` names they pointed at no longer exist.

### Fixed

- **Plugin catalog templates are no longer counted as MCP servers** (#201): the MCP walk matches on basename anywhere under `$HOME`, and an agent plugin marketplace is a clone of a catalog repo where every entry ships a template `.mcp.json` — on one machine that turned 7 real configs into 53, 16 from `~/.claude/plugins/marketplaces` and 30 from `~/.codex/.tmp/plugins`, none installed and none loaded by any agent, and in enterprise mode 36 of them carried an `mcpServers` block that inflated the fleet inventory and `mcp_servers_count`. Every plugin package is marked by a `.claude-plugin` / `.codex-plugin` manifest at its root, so a hit inside one is now classified: the package's own `.mcp.json` in an installed package (`plugins/cache`) is kept as `claude_plugin` / `codex_plugin`; a catalog entry, or an MCP-shaped file vendored elsewhere in a payload, is dropped; a file with no manifest above it stays `discovered_mcp`. Manifest detection was preferred over a list of catalog paths so this holds for agents whose plugin directories we haven't seen yet. An installed-but-disabled plugin is still reported.
- **Global npm packages report the root they were found in.** Since v1.13.0 the disk scan merged every global root for a package manager into one result and never set `ProjectPath`, so global packages reached the dashboard with a blank "Project Paths" column; per-project scans were unaffected. One result is now emitted per global root, tagged with the `node_modules` directory it was read from, so two prefixes (nvm per-version trees) list both. Scan state still keys globals by package manager, and the root is deliberately part of the hash so an upgraded agent on a delta-enabled device cannot see an unchanged hash, skip the upload, and keep the blank paths.
- **macOS user-scoped Node global roots resolve from the developer's home.** An elevated service scanned the service process's home for npm, pnpm and Yarn global roots instead of the detected developer home. Linux `HOME` (including unset), Windows `USERPROFILE`, explicit npm/pnpm prefix overrides and Python are unchanged.
- **Two delta-protocol bugs.** An empty venv never converged: `ProjectInfo` has no exit code, so the delta layer read a nil package list as "scan failed" and kept the project out of scan state, but the disk scanner also returned nil for a venv scanned cleanly with nothing installed, so those venvs shipped a full body on every run. `ScanRoots` and the `--without-pip` branch now return an empty non-nil slice on success, leaving nil to mean failure, so a transient pip error still cannot persist an empty hash. And unchanged projects lost their upload provenance: `LastUploadedExecutionID` advanced on every run even for projects that shipped only a ref, until it pointed at a run whose payload carried no inventory for them; it now advances only when the run actually sent the packages.
- Suppress Windows scheduler-registration probe console flashes during heartbeat, telemetry initialization, and scheduler diagnostics; bound each probe to three seconds.
- **The scan no longer opens LM Studio's window on Linux.** `lm-studio` names the desktop application's launcher, not a CLI (LM Studio's CLI is a separate binary, `lms`), and a packaged Electron app does not implement `--version`, so the flag was ignored and the app booted. An Ubuntu 22.04 customer running the agent from a systemd timer had LM Studio appear on their desktop mid-scan, with the probe of `/usr/bin/lm-studio` sitting on the full 10s exec deadline before being killed. Framework specs now carry a per-tool `GUIApp` flag that suppresses the `--version` fallback, so a GUI entry point is reported as installed with whatever on-disk metadata yields and `unknown` otherwise. The flag is opt-in per entry: ollama, LocalAI and Text Generation WebUI are real CLIs and are still exec'd exactly as before.
- **IDE version probes on Linux are static-first and shim-only.** `<installDir>/<LinuxBinary>` was an exec candidate ahead of `product-info.json` and `.eclipseproduct` — and for every VS Code fork that path is the Electron GUI binary, not the CLI (`/opt/Cursor/cursor` launches Cursor; the CLI is `bin/cursor`), so an install whose `package.json` had moved would launch the app. It is no longer a candidate. Separately, an IDE found only as a name on `$PATH` went straight to `<binary> --version`; it now resolves the symlink and walks up to the install root's `package.json`/`product-info.json` first, which also yields a better version than the shim prints.

## [1.16.0] - 2026-08-20

### Added

- **Credential-location inventory**: a new `credentials_scan` phase reports which developer tools on this machine hold credentials, where, and how well guarded each location is — locations and protection only, never the credential itself. Thirteen sources across cloud (AWS, GCP), source control (SSH keys, git credential store, `.netrc`, GitHub CLI hosts), package registries (`.npmrc`, `.pypirc`), containers (Docker, kubeconfig) and infrastructure (Terraform, Vault). Every location is an exact path rather than a root to walk, every read is byte-capped, and a capped or uninterpretable read is recorded as incomplete rather than clean — so a credential sitting past the cap can never render as "read, empty, complete". Paths come from the OS user record rather than the agent's own environment, which belongs to root or SYSTEM, and every read goes through a new resolver that refuses a symlink leaving the user's roots, checks TCC consent before each syscall, and cannot be hung by a FIFO planted in a credential path. A nil section means the phase did not run; zero findings is the positive assertion that no known location holds one.
- **OpenCode MCP server configs**: OpenCode keeps servers under a top-level `mcp` key rather than `mcpServers`, accepts the config as both `opencode.json` and `opencode.jsonc`, and documents examples carrying comments and trailing commas — so its servers were invisible to the MCP inventory. Global configs are now read from `~/.config/opencode/opencode.{json,jsonc}`, resolved against the developer's home rather than the service account's, and project configs are found by the existing bounded walk. The secret allowlist is unchanged and still deny-by-default, so OpenCode's `environment` and `headers` blocks are never collected.
- **Pi, Factory Droid and Amp in the AI agent inventory**: all three already appeared under `agent_skills` but were missing from `ai_agents_and_tools`, so a machine running them looked like a machine that wasn't. They cannot be added by binary name — `pi`, `amp` and `droid` each collide with a popular same-name tool, and because resolution takes the first candidate that exists, a collider winning the `$PATH` race would hide a genuine install elsewhere on the machine. Each agent is now proven from an on-disk artifact instead: an npm or Bun manifest naming the package, the installer's anchor directory, a Homebrew cask root as opposed to the collider's formula root, winget's publisher-qualified package directory, or a pacman file manifest claiming the path — searched across the prefixes a global install actually lands in, including the per-version trees of nvm, fnm, mise, volta and asdf. Amp and Pi skip the `--version` exec, which was measured to make Gatekeeper prompt; their versions come from disk or read `unknown`.
- **Two new agent-skills roots**: `~/.config/amp/skills` (`amp_user`) and `~/.agent/skills` (`factory_agent_user`) — singular `.agent`, distinct from the `~/.agents` convention.
- **Copilot CLI installs that never land on PATH**: `gh copilot` downloads the same `@github/copilot` CLI into gh's own data directory, which never reaches `$PATH`, so users who let gh install Copilot for them read as having no Copilot CLI at all. Seven home-relative anchors are now tried after a `LookPath` miss, covering the `gh copilot` download on both platform spellings, the non-root install-script path, the WinGet and npm global shims, and the `gh-copilot` extension. Bare names stay first, so machines that already resolve `copilot` through `$PATH` are unaffected. Two limits are documented in `SCAN_COVERAGE.md` rather than worked around: a non-default `$XDG_DATA_HOME` is not followed, because the scan runs as a root daemon and does not have the user's value, and WinGet's hashed payload directory needs globbing that binary-name resolution does not do, so only its `Links` shim is covered.

### Changed

- **The macOS TCC skipper is wired into AI CLI detection.** The new resolution ladders stat candidates directly instead of descending a walk, so the walk-level skip could not protect them; consent is now checked before every stat and again on every resolved symlink. The pnpm and fnm trees under `~/Library` are exempted, since the coarse `~/Library` skip that is correct for a walk would otherwise drop both macOS channels silently.
- **CI: release publishing is gated on verification.** A new `publish-release.yml` runs the verification suite as a reusable workflow and publishes the draft release, marking it latest, only if every check passes — signed checksums, Windows Authenticode, macOS notarization — replacing the manual `gh release edit --draft=false --latest` step. Verification now also requires a valid out-of-band Ed25519 `.sha256.sig` for the `x64` and `arm64` `.intunewin` packages, so every distributable artifact is covered. Because those checksums are created outside the repository, a compromised repository alone cannot ship a release that customers' loaders will accept.

## [1.15.0] - 2026-08-03

### Added

- **Server-driven scan cadence (run gating)**: on every invocation the agent asks the backend's new `run-directive` endpoint whether a full scan is due and exits quietly when it isn't, with no run-status row, no phases, and a single log line. The scan frequency lives in the StepSecurity dashboard (per tenant, minutes granularity, with a temporary override that auto-reverts at a set time and a per-device "re-scan now" request), so fleets deployed via an external MDM (for example JAMF's hourly cadence) get their real cadence from the backend with no MDM scheduling changes. Run gating is controlled entirely from the backend: the agent always makes the check-in call, and the backend decides. It is gated by a per-environment backend flag so it can be enabled for one environment at a time; while the flag is off the backend answers "scan" every time and the agent behaves exactly as before. Once enabled, gating applies to every device (a 4-hour default when a tenant has not set its own cadence). Any check-in failure fails open to a scan (with a cached-interval fallback so offline machines don't scan every wakeup), and an invocation that lands while another scan is running backs off quietly instead of reporting a failed run. Bypass for debugging: `--force-scan` / `STEPSEC_FORCE_SCAN=1`; per-device kill switch: `STEPSEC_DISABLE_RUN_GATE=1`.
- **npm secure-registry device policy**: a new `package_config#npm` enforcement lane converges a StepSecurity-owned block in the console user's `~/.npmrc` so npm — and the pnpm, yarn v1, and bun tools that read the same file — resolve packages through the tenant's secure registry. Because the agent may touch a user-controlled home as root (macOS LaunchDaemon), every file operation goes through `os.Root` with explicit symlink-chain resolution, post-open identity re-checks, and metadata changes on open handles rather than by path. The INI classifier mirrors npm's own key/value parsing and fails closed on the forms it cannot safely reason about (sections, bare CRs, `key[]=` array-append on a managed key, coercible quoted keys). Writes are transactional with snapshot rollback and bounded, identity-checked backups; the lane runs unconditionally but stays dormant until the backend returns a `package_config` policy — an absent policy is a no-op, never a wipe.
- **VS Code private marketplace URL enforcement**: an optional `extensions.gallery.serviceUrl` is written into user-scope `settings.json` beside `extensions.allowed` in a single atomic multi-key write. The agent owns both keys: a set is authoritative, removal is ownership-gated so a user-configured value is never deleted, and drift, convergence, selective clear, and post-write rollback all cover both. An allowlist-only policy writes byte-identically to before.
- **MDM verify-only enforcement channel**: device policy now selects an enforcement channel per cycle for both the IDE-extension and npm lanes. `dmg` (or empty) is the existing write-and-verify path; `mdm` is verify-only — the agent reads the OS-managed VS Code policy (Windows registry, macOS managed-preferences plist, `/etc/vscode/policy.json`) or the effective `~/.npmrc` and reports what it observed, never writing, patching, or clearing, because an external MDM owns the policy. Compliance reports carry the observed values plus the canonical channel the cycle actually ran, so the backend can diff like-for-like. Unknown channels fail safe to the write path. The npm reader never returns or logs a token, hash, or fingerprint, and reports an observed plaintext `http://` registry as drift evidence rather than discarding the most security-relevant signal the channel exists to catch.

### Changed

- **Device policy ownership is tracked in one locked state file**: every category now records what the agent has written in `device-policy-state.json` keyed by (category, target), replacing the npm lane's separate per-uid store. Lost updates are prevented by a cross-process advisory lock (`flock` on POSIX, `LockFileEx` on Windows) held only for the read-modify-write, instead of by splitting the file. Acquisition fails closed — a lock that cannot be taken fails the operation and the next cycle retries — with a single waiver for filesystems that do not implement locking at all, where no peer can hold a lock either. An unreadable state file is no longer treated as absent: a present-but-unreadable file returns an error rather than letting one category's clear silently drop another's ownership record.
- **Run-config device policy is keyed by setting id**: the policy payload is now a settings map (setting id → compiled value) instead of a bare `extensions.allowed` object plus a sibling `gallery_service_url` field, and the hash covers the whole map. Enforce and clear are driven entirely by the map and the recorded ownership with no per-key special-casing, so a new managed setting needs no agent change. This is a breaking run-config wire change (pre-GA) and requires the backend to emit the settings-map shape.
- **Managed `settings.json` writes preserve a leading UTF-8 BOM**, which PowerShell 5.1's `Set-Content -Encoding UTF8` and editors set to `utf8bom` emit. Previously a seeded file carrying one parsed as invalid and stayed permanently unenforceable.

### Fixed

- **Homebrew installed outside PATH is now detected**: the brew executable is resolved from the standard install locations (`/opt/homebrew`, `/usr/local`, `/home/linuxbrew`) when it is not on PATH, and the version is read from the Homebrew git repo metadata instead of by shelling out to `brew --version`. Detection and formula/cask listing now work for scans run without the user's interactive PATH.
- **Credential masking in malformed multi-`@` index URLs**: `redactCredsInValue` split userinfo at the first `@`, so a value with several `user:pass@host` runs concatenated before the real host (a mangled pip index-url, in one real case carrying a live PAT) shipped the trailing credential verbatim into effective-config telemetry. Userinfo is now taken up to the *last* `@` within the URL authority, and a userinfo run that itself contains an extra `@` is masked whole.
- **Device policy clears report a removal only when something was removed.** An unassigned device announced "cleared managed block" on every cycle forever, which read in fleet logs as a device being remediated repeatedly when it had been clean for weeks.

## [1.14.0] - 2026-07-17

### Added

- **AI agent skills inventory**: a new scanner discovers AI agent "skills" across the machine — walking home directories and both registered and unregistered project trees, recognizing a broader set of executable script types (`has_code`), collapsing symlink shadows, honoring macOS TCC-protected directories, and hardened against partial or hostile inputs. Claude Code plugin trees are intentionally excluded from skills discovery.
- **Gatekeeper pre-exec guard (macOS)**: before any version-probe exec fallback, the agent checks the resolved binary (and its containing directory) for the `com.apple.quarantine` attribute; quarantined binaries are then assessed silently with `spctl --assess --type execute`, and Gatekeeper-rejected ones are skipped (version reported as `unknown`) instead of executed. This removes the main scan-triggered path to the macOS "could not verify … free of malware" dialog for tools whose install layout carries no readable version metadata. It is not a blanket guarantee: the assessment covers the launched binary itself, so a Gatekeeper-accepted binary that loads a separately quarantined, un-notarized plugin at runtime could still prompt — metadata-first resolution (which avoids the exec entirely) remains the primary defense. Unquarantined binaries (e.g. Homebrew formulae) are unaffected.

### Changed

- **Metadata-first version detection**: tool version probes (AI CLIs, AI agents, AI frameworks, Node and Python package managers) now resolve versions from on-disk metadata — npm `package.json` manifests, `<tool>/versions/<v>` install layouts, Homebrew Cellar/Caskroom paths, and macOS app bundles — before falling back to executing `<tool> --version`. Executing third-party binaries could trigger macOS Gatekeeper "could not verify" popups when a tool ships un-notarized native code (e.g. cursor-agent's `merkle-tree-napi.darwin-arm64.node`); the exec fallback is unchanged, so tools without metadata are still detected exactly as before. Each remaining exec fallback is logged to stderr (`exec fallback: running <binary> ...`) so rollouts can track which tools still get executed.
- **MCP configuration discovery broadened**: MCP server configs are now recognized by filename in addition to known locations, with VS Code support, a vendor heuristic for unrecognized clients, and de-duplication on Windows.
- **Python package discovery via filesystem walk**: installed Python packages are now discovered by walking the filesystem and recognizing on-disk install layouts (complementing 1.13.0's `dist-info` reading); root-run scans resolve the console user's home directory instead of root's.
- **Claude Desktop reclassification**: Claude Desktop is no longer reported as an IDE; it is captured as a cowork agent only.

### Fixed

- **Downloaded execution logs**: upload-intent log lines are now included in the execution logs available for download.

## [1.13.0] - 2026-07-08

### Added

- **Device policy enforcement**: the agent now applies device policy profiles fetched from run-config, including OS-native enforcement of a VS Code extension allowlist. Policy identity is target-aware (category + target) and on-device state is keyed by category; state files written by a newer schema version are rejected. Generally available and enabled by default for all enterprise customers.
- **Classic Visual Studio detection**: scans now discover classic Visual Studio installs and their extensions.
- **Disk-based package scanning**: npm packages are discovered by parsing lockfiles and Python packages by reading `dist-info` metadata on disk, so package inventory no longer depends solely on invoking the package manager.
- **Run-on-login scheduling and scheduler diagnostics**: scans can be scheduled to run on login, Windows Task Scheduler history is enabled, and a new scheduler-info subsystem reports cross-platform scheduling state for troubleshooting.
- **Last-run heartbeat**: a `last-run.json` heartbeat is written at the start of telemetry send, and this run's loader-script logs are included in telemetry.
- **Scan-state delta upload protocol**: infrastructure to upload only package add/remove deltas between runs (opt-in; disabled by default).

### Changed

- **Legacy package scan remains the default**: the scan-state delta protocol is gated off by default; `use_legacy_package_scan` controls the legacy full-inventory path.
- **schtasks frequencies of 24h+ now use a DAILY schedule** instead of a minute-interval trigger.
- **Go toolchain bumped to 1.26.**
- **Lock-acquisition contention** is now logged and reported at info level.

### Fixed

- **Node package-manager version resolution**: PM versions are resolved via default install paths, and `NodeScanner.pmAvailability` access is guarded by a mutex.
- **Scan cap and delta gating**: disk-discovered packages now count toward the scan cap, and delta upload is gated on a resolved PM version.
- **Lock failures** are no longer assumed to indicate contention.
- **IDE policy under SYSTEM**: the installer no longer enforces IDE policy inline when running as SYSTEM.
- **Device policy source**: policy is fetched from run-config; the removed effective-policy endpoint is no longer called.
- **scan-state persistence**: scan-state is written to the `--telemetry-out` path when specified.

## [1.12.0] - 2026-06-09

### Added

- **Malicious-file detection**: new rules-engine scanner that flags suspicious files as IOCs and wires the results into scan telemetry. The detector streams one file at a time to keep scan memory bounded regardless of repository size.
- **pnpm configuration inventory**: scans now surface the contents of pnpm configuration.
- **bun configuration inventory**: scans now surface `bunfig.toml` configuration.
- **yarn configuration inventory**: scans now surface both yarn classic and yarn berry configuration.

### Changed

- **pnpm/bun/yarn audits enabled by default**: the agent now runs all three audits on every scan and emits `pnpm_audit`, `bun_audit`, and `yarn_audit` on the wire payload (gated via rc-config feature gates).
- **npm and pip rc-config scanning enabled by default**.
- **macOS service management**: the agent now uses `launchctl bootstrap`/`bootout` instead of the deprecated `load`/`unload`.

### Fixed

- **pnpm path resolution**: corrected pnpm path handling on both Linux and Windows.
- **Package-manager resolution under launchd**: package managers are now resolved correctly under the LaunchAgent's stripped `PATH`.
- **Shell quoting in `RunAsUser`**: command and argument quoting is now handled correctly when executing as the target user.
- **Windows empty payloads**: empty payloads are handled gracefully when npm is not present.
- **launchd failures surfaced**: `bootstrap`/`bootout` failures are now reported instead of silently swallowed.
- **brew raw scan output**: raw scan output is now synthesized from the rich brew data.

## [1.11.7] - 2026-05-31

### Added

- **Antigravity IDE detection**: scans now recognize the Antigravity editor.
- **Bounded scan execution**: scans are now capped by a global deadline (60m default; override via `STEPSEC_MAX_SCAN_DURATION`, or `0` to disable) plus per-phase deadlines, so a single stuck phase no longer hangs the whole run. Subprocesses are killed by process group on cancel, preventing forked grandchildren (Electron `--version`, npm/yarn/pnpm `ls`) from blocking on inherited file descriptors.
- **Log tail in heartbeat**: heartbeats now carry a gzipped+base64 tail of recent stderr (throttled), and log capture uses a bounded ring buffer to cap memory on long runs, surfacing where a scan is stuck.

### Fixed

- **`api_endpoint` trailing slash**: configured `api_endpoint` values are now normalized to strip trailing slashes at the config boundary, avoiding malformed `//v1/...` URLs that some gateways reject with 403/500.
- **pip detection triggering CLT install dialog**: pip detection no longer invokes a command that could pop the macOS Command Line Tools install dialog.
- **macOS IDE pop-ups and stuck processes**: macOS scans are further hardened against IDE permission pop-ups and processes that never exit.
- **Execution-watchdog limit via config**: the execution-watchdog limit is now delivered through `config.json`.

## [1.11.6] - 2026-05-27

### Fixed

- **macOS Tahoe Media Library prompt**: the project walker now skips `~/Library` wholesale instead of curating individual TCC-protected subpaths. This prevents new TCC prompts (e.g. `kTCCServiceMediaLibrary` from `~/Library/Application Support/com.apple.avfoundation/`) from firing after each macOS release adds Apple-managed subtrees behind new TCC services. Targeted detectors that read specific files under `~/Library` (JetBrains plugins, Claude desktop MCP config, pip global config) keep working unchanged.

## [1.11.5] - 2026-05-27

### Added

- **macOS TCC-protected directory skipping**: scanners now skip TCC-protected paths (Photos, Media Library, App Management, etc.) by default when running under launchd, avoiding spurious permission prompts and noisy denials. Hits are logged so operators can see which paths were skipped.
- **PPPC configuration guide**: new docs explain how to grant the agent the necessary TCC permissions via a PPPC profile for environments that want full coverage.
- **`verify-msi.ps1` script**: client-side PowerShell script for verifying the integrity and Authenticode signature of distributed MSI artifacts.

### Fixed

- **Empty `--install-dir` rejected**: install/uninstall commands now reject an empty `--install-dir` value instead of silently falling back to a default, preventing accidental installs to the wrong location.
- **`install_dir` config field is authoritative**: the configured `install_dir` is now treated as the source of truth across install/uninstall paths, resolving inconsistencies when the field disagreed with runtime defaults.

## [1.11.4] - 2026-05-26

### Added

- **Authenticode-signed Windows binaries and MSIs**: release artifacts are now signed via Azure Trusted Signing, so installs no longer trip SmartScreen/EDR unsigned-binary heuristics on Windows.
- **Feature gate for selective scanning**: new feature-gate mechanism allows disabling or enabling individual scanners at runtime, giving operators a way to scope what a deployment reports without rebuilding.
- **Invocation method + in-flight status reporting**: telemetry now records how the agent was invoked (launchd / systemd / scheduled task / interactive) and emits structured per-phase status info while a scan is running.
- **`$HOME` expansion in configured paths**: path-style config values now expand `$HOME` (and `~`) consistently across platforms.

### Fixed

- **Windows console window flashes during scheduled scans**: the scheduled task no longer pops a visible console window on each run.
- **Telemetry post-phase is non-blocking**: post-phase telemetry submission can no longer stall scan completion if the backend is slow or unreachable; sandbox invocation tests added to cover the path.
- **Canonicalised `$HOME`/`~` expansion**: path expansion now goes through `filepath.Join` so the resulting paths are normalised across `/`-vs-`\` and trailing-separator edge cases.

### Changed

- **Per-phase telemetry sub-progress incl. upload phase**: progress reporting now tracks sub-progress within each phase and adds an explicit upload phase, giving the dashboard finer-grained visibility into long-running scans.
- **CI: on-demand test-binary + MSI workflow** added so non-release builds can be produced from a PR without cutting a tag.
- **CI: msi-smoke workflow hardened** following StepSecurity best-practice review.

## [1.11.3] - 2026-05-21

### Added

- **AI agent hook state polling**: agents periodically check the StepSecurity backend for desired hook enable/disable state and reconcile local installation to match. Silent no-op in community mode; failures are logged but never crash the scanner.
- **Static machine resource info in device payload**: each scan now reports CPU model and count, total RAM, and disk capacity for the scanned host, giving the dashboard a clearer picture of the endpoint context.
- **Configurable install directory + persistent stderr logs**: new `--install-dir` flag (and matching env var/config field) relocates all non-bootstrap agent state, and stderr is now captured to a rotated `agent.error.log` under the install dir so MDM/service deployments have durable diagnostics (#88).

### Fixed

- **Auto-update signing**: fixed a signing regression in the previous 1.11.2 release that prevented auto-update from working. v1.11.2 has been removed; install or upgrade to 1.11.3 directly.
- **Windows scheduled task user context**: the scheduled task now runs under the logged-in user via `/ru INTERACTIVE` instead of `SYSTEM`, so the scanner can read `HKCU`, `%USERPROFILE%`, and the user's `PATH` — fixing a class of missed detections for tools installed in user scope.
- **Windows agent log directory permissions**: `C:\ProgramData\StepSecurity` now grants `BUILTIN\Users` Modify rights so the scheduled task (running as the logged-in user) can append to `agent.log` instead of failing with Access Denied.
- **AI agent hook command path on Windows**: hook entries written into agent config files now use forward-slash paths, avoiding Windows shell quoting issues that could prevent the hook from firing.
- **pnpm v11 global scan regression**: globally installed pnpm packages were missing from the npm scan output on pnpm v11; detection logic updated for the new layout.
- **Linux/macOS lock contention race**: an edge case where the singleton-lock check could misidentify the console user on systems with no active interactive session is fixed.

### Changed

- **CI: gosec SAST scan** added to the workflow set, with a corresponding badge in the README.
- **CI: cross-platform build + vet/fmt/tidy** checks added to the Tests workflow, surfacing platform-specific compile errors at PR time instead of at release time.

## [1.11.1] - 2026-05-05

### Added

- **Install path in scan output**: Installed packages and IDE extensions now report their on-disk install location alongside name and version. Covers Homebrew formulae and casks, JetBrains/Eclipse/Xcode/VS Code-family extensions, and Linux snap and flatpak system packages.

### Fixed

- **IDE and AI CLI detection through symlinks**: Tools installed or invoked via symlinks (for example, Homebrew shims or user-managed aliases) are now resolved to their real install path so they are detected and reported correctly instead of being missed or duplicated.
- **Windows AI CLI detection on relative PATH entries**: AI CLI detection on Windows no longer fails when `PATH` contains relative directory entries — these are resolved before the binary probe runs.

## [1.11.0] - 2026-04-29

### Added

- **Linux support**: Cross-platform scanning on Linux with feature parity for the core workflow — IDE/extension/AI tool/MCP/Node.js/Python detection plus the device, telemetry, and locking subsystems.
  - **systemd scheduling**: LaunchDaemon/LaunchAgent equivalent on Linux, using systemd timers/services to run scheduled scans.
  - **Native Linux package detection**: rpm, deb, snap, and flatpak packages enumerated and reported.
  - **JetBrains IDE detection on Linux**.
  - **BIOS serial number** used for device identification on Linux when system serial is unavailable.
- **Linux distro-native release artifacts**: Release workflow now produces `.deb` and `.rpm` packages alongside the raw Linux binaries, packaged via goreleaser.
- **System package metadata + security context**: Brew formulae/casks (macOS) and system packages (Linux: rpm/deb/snap/flatpak) now report rich metadata — name, version, vendor, install date, and per-package security context (signature/signing-key information where available) — in the telemetry payload.
- **Telemetry run status reporting**: Agent reports run start/success/failure status to telemetry separately from scan results, so backend can track agent health independently of scan content.
- **Gzip compression for telemetry uploads**: Telemetry payload upload to S3 is now gzip-compressed, reducing transfer size on slow networks.
- **Log level configuration**: New `--log-level` flag and config option replace hard-coded logging; progress and component logs honor the configured level throughout the application.
- **Cursor Agent CLI detection**: `cursor-agent` (Cursor's agent CLI, installed via `curl https://cursor.com/install`) is now detected as a distinct AI CLI tool, separate from the existing Cursor IDE record. Machines with both installed will now report two artifacts.

### Changed

- **Legacy shell script removed**: The original `stepsecurity-dev-machine-guard.sh` (and its accompanying shellcheck CI workflow and shell smoke tests) has been removed. The Go binary, introduced in 1.9.0, is now the only entry point.
- **UUID generation**: Replaced custom UUID generator with the `google/uuid` library for telemetry IDs.

### Fixed

- **Python project detection**: Virtual-environment path discovery now handles venvs created without pip, and project detection inside such venvs no longer skips them.
- **GitHub Copilot CLI detection**: Detector rejects non-zero exit codes from the version probe (previously yielded false positives) and correctly parses the Copilot CLI's version output format.

## [1.10.2] - 2026-04-22

### Added

- **Windows Eclipse plugin detection**: Multi-stage detection pipeline using detected IDE install paths (registry-aware), well-known path probes (Oomph installer, vendor variants like STS/MyEclipse, D:-Z: drive scanning), and install validation to eliminate false positives.
- **Eclipse p2 director integration**: Uses `eclipsec.exe -listInstalledRoots` for authoritative marketplace plugin identification. Falls back to `bundles.info` parsing if unavailable.
- **`--include-bundled-plugins` flag**: Bundled/platform plugins (e.g., Eclipse's 500+ OSGi bundles) are now filtered out by default to reduce noise and payload size (~124KB → ~21KB). Use the flag to include them.
- **Sigstore signing retry logic**: Release workflow retries artifact signing with Sigstore on transient failures.

### Changed

- **Quiet mode now defaults to `false`**: Progress output is shown by default in community mode, matching the behavior already documented in the README. `configure` prompt and `configure show` now display `false` when the value is unset.
- **S3 telemetry upload timeout increased from 60 seconds to 10 minutes**: Large scan payloads on slower networks were exhausting the previous 60 s budget and forcing the retry loop to redo the entire upload.

## [1.10.1] - 2026-04-21

### Added

- **Glob-based Windows path matching**: `detectWindows` supports wildcard patterns in `WinPaths` for JetBrains IDEs that embed version numbers in folder names. Picks the newest installation when multiple versions are present.
- **`product-info.json` version extraction**: Reads JetBrains `product-info.json` for accurate marketing version numbers on Windows (avoids registry build numbers).
- **`.eclipseproduct` version extraction**: Reads Eclipse's `.eclipseproduct` properties file for version detection on Windows.
- **JetBrains plugin detection enhancements**: Reads `productVendor` from `product-info.json` for correct config paths (handles Android Studio's `Google` vendor). Checks `idea.plugins.path` override in `idea.properties`.

### Fixed

- **Windows project package scanning**: Added `RunInDir` to Executor interface to bypass `cmd.exe` quote escaping issues. Fixes project-level NPM packages not being collected on Windows.
- `RunAsUser` now sources `~/.zshrc` (or `~/.bashrc`) for full PATH resolution when running as root. Tools installed via nvm, n, fnm, bun, or npm-global were invisible in LaunchDaemon/IRU contexts because the login shell skipped `.zshrc`.
- `RunAsUser` now propagates non-zero exit codes as errors instead of silently returning nil.
- `LookPath` validates that `which` output is an absolute path, preventing zsh's "not found" stdout messages from being treated as valid binary paths.
- `UserAwareExecutor.Run` now extracts actual exit codes from `RunAsUser` errors, fixing `isProcessRunning` false positives for AI frameworks.

## [1.10.0] - 2026-04-20

### Added

- Windows support: cross-platform detection for IDEs, extensions, AI tools, frameworks, MCP configs, and Node.js scanning on Windows.
- Homebrew scanning: detects formulae and casks with raw output capture for enterprise telemetry.
- Python scanning: detects package managers, global packages, and projects with virtual environments.
- User-aware executor: commands like `brew`, `pip3`, and `npm` now run in the logged-in user's context when the agent runs as root.
- IDE plugin detection: JetBrains IDEs, Xcode Source Editor extensions, and Eclipse plugins with bundled/user-installed source tagging.
- Project-level MCP configuration discovery and filtering.
- S3 upload retry mechanism with exponential backoff and extended timeout for large payloads.
- Enhanced user shell resolution for macOS `RunAsUser`.

### Fixed

- Populated missing performance metrics fields (brew formulae/cask counts, Python global packages/project counts).
- S3 retry logging now includes the actual error value for easier debugging.
- Retry backoff respects context cancellation during shutdown.

## [1.9.2] - 2026-04-15

### Fixed

- LaunchDaemon now sets `HOME` in the plist environment so `configDir()` resolves correctly at runtime (fixes "Enterprise configuration not found" error in periodic scans).
- Progress and error log lines now include timestamps for easier debugging.

## [1.9.1] - 2026-04-07

### Fixed

- Config `quiet: false` now correctly shows progress (was ignored previously).
- Enterprise auto-detect mode respects the configured quiet setting instead of overriding it.
- Release now produces a single universal macOS binary (amd64 + arm64).

## [1.9.0] - 2026-04-03

Migrated from shell script to a compiled Go binary. All existing scanning features, detection logic, CLI flags, output formats, and enterprise telemetry are preserved — this release changes the implementation, not the functionality.

### Added

- **Go binary**: Single compiled binary (`stepsecurity-dev-machine-guard`) replaces the shell script. Zero external dependencies, no runtime required.
- **`configure` / `configure show` commands**: Interactive setup and display of enterprise credentials, search directories, and preferences. Saved to `~/.stepsecurity/config.json`.

## [1.8.2] - 2026-03-17

### Added

- `--search-dirs DIR [DIR...]` flag to scan specific directories instead of `$HOME` (replaces default; repeatable)
  - Accepts multiple directories in a single flag: `--search-dirs /tmp /opt /var`
  - Supports repeated use: `--search-dirs /tmp --search-dirs /opt`
  - Quoted paths with spaces work: `--search-dirs "/path/with spaces"`

## [1.8.1] - 2026-03-10

First open-source release. The scanning engine was previously an internal enterprise tool (v1.0.0-v1.8.1) running in production. This release adds community mode for local-only scanning while keeping the enterprise codebase intact.

### Added

- **Community mode** with three output formats: pretty terminal, JSON, and HTML report
- **AI agent and CLI tool detection**: Claude Code, Codex, Gemini CLI, Kiro, Aider, OpenCode, and more
- **General-purpose AI agent detection**: OpenClaw, ClawdBot, GPT-Engineer, Claude Cowork
- **AI framework detection**: Ollama, LM Studio, LocalAI, Text Generation WebUI
- **MCP server config auditing** across Claude Desktop, Claude Code, Cursor, Windsurf, Antigravity, Zed, Open Interpreter, and Codex
- **IDE extension scanning** for VS Code and Cursor (with publisher, version, and install date)
- **Node.js package scanning** for npm, yarn, pnpm, and bun (opt-in in community mode)
- CLI flags: `--pretty`, `--json`, `--html FILE`, `--verbose`, `--enable-npm-scan`, `--color=WHEN`
- Documentation: community mode guide, enterprise mode guide, MCP audit guide, adding detections guide, reading scan results guide
- GitHub issue templates for bugs, feature requests, and new detections
- ShellCheck CI workflow with Harden-Runner

### Changed

- Enterprise config variables are now clearly labeled and placed below the community-facing header
- Progress messages suppressed by default in community mode (enable with `--verbose`)
- Node.js scanning off by default in community mode (enable with `--enable-npm-scan`)

### Enterprise (unchanged from v1.8.1)

- `install`, `uninstall`, and `send-telemetry` commands
- Launchd scheduling (LaunchDaemon for root, LaunchAgent for user)
- S3 presigned URL upload with backend notification
- Execution log capture and base64 encoding
- Instance locking to prevent concurrent runs

[1.17.0]: https://github.com/step-security/dev-machine-guard/compare/v1.16.0...v1.17.0
[1.16.0]: https://github.com/step-security/dev-machine-guard/compare/v1.15.0...v1.16.0
[1.15.0]: https://github.com/step-security/dev-machine-guard/compare/v1.14.0...v1.15.0
[1.14.0]: https://github.com/step-security/dev-machine-guard/compare/v1.13.0...v1.14.0
[1.13.0]: https://github.com/step-security/dev-machine-guard/compare/v1.12.0...v1.13.0
[1.12.0]: https://github.com/step-security/dev-machine-guard/compare/v1.11.7...v1.12.0
[1.11.7]: https://github.com/step-security/dev-machine-guard/compare/v1.11.6...v1.11.7
[1.11.6]: https://github.com/step-security/dev-machine-guard/compare/v1.11.5...v1.11.6
[1.11.5]: https://github.com/step-security/dev-machine-guard/compare/v1.11.4...v1.11.5
[1.11.4]: https://github.com/step-security/dev-machine-guard/compare/v1.11.3...v1.11.4
[1.11.3]: https://github.com/step-security/dev-machine-guard/compare/v1.11.1...v1.11.3
[1.11.1]: https://github.com/step-security/dev-machine-guard/compare/v1.11.0...v1.11.1
[1.11.0]: https://github.com/step-security/dev-machine-guard/compare/v1.10.2...v1.11.0
[1.10.2]: https://github.com/step-security/dev-machine-guard/compare/v1.10.1...v1.10.2
[1.10.1]: https://github.com/step-security/dev-machine-guard/compare/v1.10.0...v1.10.1
[1.10.0]: https://github.com/step-security/dev-machine-guard/compare/v1.9.2...v1.10.0
[1.9.2]: https://github.com/step-security/dev-machine-guard/compare/v1.9.1...v1.9.2
[1.9.1]: https://github.com/step-security/dev-machine-guard/compare/v1.9.0...v1.9.1
[1.9.0]: https://github.com/step-security/dev-machine-guard/compare/v1.8.2...v1.9.0
[1.8.2]: https://github.com/step-security/dev-machine-guard/compare/v1.8.1...v1.8.2
[1.8.1]: https://github.com/step-security/dev-machine-guard/releases/tag/v1.8.1
