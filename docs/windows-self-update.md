# Windows self-update (MSI installs)

MSI installs (Intune, SCCM) keep themselves on the release your tenant
selects, without IT pushing a new MSI for every version. A small, stable
bootstrap launches whichever version is current. A separate SYSTEM task
downloads, verifies and switches versions, and rolls back a version that
crashes.

Packaging details (custom actions, the `AUTOUPDATE` property, upgrades and
the Intune detection rule) are in
[`packaging/windows/README.md`](../packaging/windows/README.md).

## Layout

```
C:\Program Files\StepSecurity\
  stepsecurity-dev-machine-guard-bootstrap.exe   MSI-owned, stable
  seed\<msi-version>\                            MSI-owned fallback payload
  versions\<v>\                                  updater-owned, immutable once in place
    stepsecurity-dev-machine-guard.exe
    stepsecurity-dev-machine-guard-task.exe
    dmg-linux
    manifest.json                                sha256 of every file
  state\state.json, update.lock, update.log      updater-owned
C:\ProgramData\StepSecurity\runs\<v>.json        one record per scan launch
HKLM\Software\StepSecurity\AgentVersion          MSI version (Intune detection)
HKLM\Software\StepSecurity\RunningVersion        version currently selected
```

- `versions\` and `state\` are owned by SYSTEM with a protected ACL:
  SYSTEM and Administrators full control, Users read and execute. The
  updater re-applies it on every run and reports any drift.
- The MSI never touches `versions\` or `state\`, and the updater never
  touches the bootstrap, the seed or `AgentVersion`. A repair or upgrade
  can't undo a self-update. An MSI only moves `current` forward to its
  own seed, never back.

## Tasks

| Task | Runs as | Action |
|---|---|---|
| Scan (hourly/daily) and logon | Logged-in user | `bootstrap.exe run send-telemetry …` |
| `StepSecurity Dev Machine Guard (Update)` | SYSTEM, hourly + 15 min after boot | `bootstrap.exe update` |

`bootstrap.exe run` reads `state.json` once and launches `current`. If
that directory is missing or incomplete it falls back to `previous`, then
to the seed. Each launch is recorded in `runs\<v>.json`. A scan that ran
a fallback reports `update_pointer_invalid`.

`bootstrap.exe update` runs `agent.exe self-update --system` from the
confirmed version. While a new version is on probation it uses the
previous one, and after three consecutive updater failures it uses the
seed, so a broken updater can't freeze a device.

## One updater run

Every step can be interrupted at any point; the next run picks up from
the state on disk.

1. Take `state\update.lock`. Another updater already running → exit.
2. Clean up leftover staging, remove version directories nothing points
   at, re-apply ACLs, and refresh the device id from the hardware.
3. Check the version on probation (see below). This may roll back.
4. Ask the backend for the target: at most every 6 hours, or right after
   a probation closes. Stop if updates are off, the target is the current
   version, quarantined, below the minimum self-update version, or a
   probation is still open.
5. Stage the target in `versions\.staging-*`. Verification happens before
   anything is renamed into place:
   - every checksum's SSH signature is checked against the pinned release
     key, before any download;
   - sha256 is checked on each download (GitHub first, then the optional
     mirror);
   - both executables must have a valid, timestamped Authenticode
     signature from the same publisher as the running updater.
6. Run `agent.exe self-check` from the staged directory as SYSTEM (in a
   job, 60 s limit). A failure quarantines the version.
7. Wait (up to 10 minutes) until no scan is running, then switch `current`
   to the new version and start its probation.
8. Report the result.

## Health, rollback and quarantine

A new version is on probation until its scans prove it:

- **Healthy run:** the scan reached the backend (`started`). One healthy
  run confirms the version.
- **Bad run:** a crash, a watchdog kill, or an exit before `started` with
  an unexpected code. Two bad runs in a row roll back to the previous
  version.
- **Neutral run:** offline, or skipped because another scan was running.
  These neither confirm nor count against the version.

If no scan runs within 72 hours, the version is confirmed on its
self-check alone. After six or more runs with no healthy one, it rolls
back with a 7-day quarantine. Any other rollback quarantines the version
permanently on that device, so it is never staged again. A fix ships as a
new version.

## Turning it off

Install with `AUTOUPDATE=0` to keep the device on the MSI's version. The
update task still runs and reports `update_disabled`, so the backend
shows how far behind the device is. See the packaging README for
re-enabling.

## Events

Every outcome is posted to `run-status` with `status: "update"`, the
device id, the sending agent's version, `install_channel: "msi"`, and
`update_event`, plus `update_from` / `update_to` / `error_message` where
they apply:

`update_ok`, `update_confirmed`, `update_rolled_back`,
`update_download_failed`, `update_verify_failed`, `update_stage_failed`,
`update_health_failed`, `update_switch_failed`, `update_switch_deferred`,
`update_check_failed`, `update_refused_floor`, `update_disabled`,
`update_pointer_invalid`, `update_acl_drift`, `update_state_corrupt`,
`update_updater_failed`.

Events are saved in `state.json` in the same write as the change they
report and are retried until the backend accepts them. Repeated failures
are reported at most once per day per target.

## Existing fleets

Devices on an MSI older than the first self-updating release can't
update themselves. They need one final MSI push of a release that ships
the bootstrap; from then on they follow the tenant's target.
