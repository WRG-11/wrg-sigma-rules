<!--
Companion detection note covering TWO unrelated CVE-sourced Sigma rules, both a path/argument-
injection primitive leading to unauthorized file read on a media/ML-adjacent tool:
- resources/examples/collection/observed_diffusers_weight_map_path_traversal_t1005.yml
- resources/examples/initial_access/observed_jellyfin_ffmpeg_arg_injection_lfi_t1190.yml
Advisory sources: HuggingFace Diffusers fix commit cee298c + PR #14182 (CVE-2026-65920, VulnCheck
advisory) / Jellyfin GHSA-jh22-fw8w-2v9x (CVE-2026-35033, SentinelOne vulnerability database).
Detection/defense only, no exploit/PoC reproduced beyond what the vendor sources already published.
-->

# Two File-Read Primitives Through Unvalidated Paths: Diffusers Checkpoint Traversal and Jellyfin FFmpeg Argument Injection

Two unrelated CVEs, each demonstrating a distinct way an unvalidated string reaches a file-read operation — one through a supply-chain-delivered model artifact, one through an unauthenticated HTTP streaming endpoint.

## What each flaw actually does

**1. A checkpoint file's own index tells the loader what to open — with no validation (CVE-2026-65920, HuggingFace Diffusers ≤0.39.0).** Diffusers loads sharded model checkpoints via a `weight_map` index (`diffusion_pytorch_model.safetensors.index.json`) whose values are shard filenames — taken verbatim (`sorted(set(index["weight_map"].values()))`) and joined to the model directory without validation. A malicious model repository ships an index whose `weight_map` values carry `../` segments or an absolute path (e.g. `{"w": "../secret/SECRET.safetensors"}`); on load, Diffusers opens that path directly, reading a file outside the model directory. This is a supply-chain-delivered read primitive — the attacker-controlled input is the model artifact itself, not a network request, which is why the CVE's CVSS vector carries `UI:P` (user interaction required — someone has to load the malicious model). The fix (commit `cee298c`) rejects any shard entry where `os.path.basename(shard_filename) != shard_filename`.

**2. Query parameters concatenated straight into an FFmpeg command line, unauthenticated (CVE-2026-35033, Jellyfin <10.11.7).** Jellyfin's `/Videos/{itemId}/stream` endpoint takes codec/level parameters (`VideoCodec`, `AudioCodec`, `Profile`, `SubtitleCodec`, `Level`) from user input and concatenates them directly into the FFmpeg command line with no validation. An attacker injects a value like `h264 -vf drawtext=textfile=/etc/passwd:...` — the embedded space breaks argument parsing, adding an FFmpeg `-vf drawtext` video filter whose `textfile=` source points at a sensitive server file. FFmpeg renders the file's contents as TEXT into the output video stream, leaking it to the requester. The endpoint carries no `[Authorize]` attribute — unauthenticated, though a valid (pseudo-random) item GUID is required to reach it. The fix (v10.11.7) gates each parameter behind a strict validation regex (`^[a-zA-Z0-9\-\._,|]{0,40}$` for codec names) that can never contain a space, `=`, or `/`.

## The shared lesson

Both flaws are the same underlying mistake in a different guise: a value with a very narrow legitimate shape (a bare filename; a codec name) was trusted to STAY that narrow shape without being checked, and an attacker supplied a value from the same field that carried extra structure (a path separator; a space plus a flag) the code never anticipated. Neither vulnerability is a classic "missing auth check" — #1 requires a user to load a malicious artifact, #2 requires only an unauthenticated HTTP request but is gated by needing a valid item GUID. Both detection rules therefore key on the SHAPE of the value reaching a sensitive sink (a `.safetensors` read containing `../`; an `ffmpeg`-family process whose command line carries both `drawtext` and `textfile=`) rather than on any network-layer signature, since the exploitation surface in both cases is inherently value-shaped, not request-shaped.

## The detection signals

- **#1 (file_access logsource, requires object-access auditing — see limitation below):** a `.safetensors`-suffixed `TargetFilename` whose path also contains a `../` or `..\` traversal marker.
- **#2 (process_creation logsource):** an `ffmpeg`/`ffmpeg.exe`-suffixed image whose command line contains BOTH `drawtext` AND `textfile=` — Jellyfin's own transcoding pipeline never legitimately emits this filter combination (confirmed absent from `EncodingHelper.cs`; Jellyfin uses `subtitles`/overlay filters for subtitle burn-in and Skia, not FFmpeg drawtext, for image text), so the co-occurrence is high-fidelity for this specific injection.

## Known limitations (per rule)

**#1 carries an explicit, unusually detailed telemetry-requirement warning in the rule's own description, worth repeating verbatim in spirit**: the manifestation is a file READ, but the dominant Windows file-telemetry source (Sysmon EventID 11, FileCreate) records WRITES. This rule uses `category: file_access`, which maps to Windows EventID 4663 (object-access auditing — OFF by default, requires a SACL on the target path) or Linux auditd file watches. On a host without that telemetry configured, the rule cannot fire at all — it will look clean because nothing is being collected, which is explicitly NOT the same as clean. A second, independent limitation: many sensors and filesystem APIs normalize a path before it reaches the log, collapsing `model/../secret/x` to `secret/x` and erasing the traversal marker entirely — where normalization is in effect, the rule as written will miss the traversal; the rule's own description recommends keying on the absolute-path variant instead (a `.safetensors` read from outside the HuggingFace cache root), which needs a deployment-specific allow-path and is deliberately NOT modeled here. Also: training/conversion scripts referencing checkpoints by relative path from a working directory (e.g. a notebook opening `../checkpoints/model.safetensors`) are the main benign producer of this pattern — scope by process image or exclude known project roots before deploying.

**#2** cannot distinguish this from a legitimate video-production/broadcast/watermarking pipeline that intentionally invokes FFmpeg's `drawtext` filter with a `textfile=` source — uncommon on a dedicated Jellyfin media-server host (which doesn't use drawtext for its own transcoding) but plausible on a shared host running other FFmpeg-based tooling; scope by host role or parent-process filter if needed. Administrator-run diagnostic FFmpeg commands using the same filter combination against non-sensitive files are also a plausible source of noise — correlate the actual `textfile=` path against sensitive targets (`/etc/`, `/proc/`, `/root/`, or a `..` traversal) to prioritize.

## What to do right now

1. **Upgrade**: #1 to Diffusers 0.39.1+ (per fix commit `cee298c`); #2 to Jellyfin 10.11.7+.
2. **#1's general lesson**: if your own code trusts a "just a filename" value out of any externally-supplied index/manifest file (not just a Diffusers-specific pattern — any sharded/chunked-artifact loader with an attacker-influenceable index), verify you check `os.path.basename(value) == value` (or equivalent) before joining it to a directory, exactly as the fix does.
3. **#2's general lesson**: any endpoint that concatenates user-supplied parameters into a command line for a subprocess (FFmpeg or otherwise) needs an allowlist-shaped validation regex on EVERY parameter reaching that command line, not just the obviously-dangerous-looking ones — codec/format/profile-style parameters look innocuous until argument injection is considered.
4. Deploy both detection rules against the log sources each requires — #1 specifically needs object-access auditing enabled (SACL/auditd), which most environments do not have on by default; verify this BEFORE relying on the rule's silence as a clean signal.

---

*Detection content from WinstonRedGuard (WRG-11). Defensive detection of two vendor-disclosed, now-patched vulnerabilities. References: [huggingface/diffusers fix commit cee298c](https://github.com/huggingface/diffusers/commit/cee298c1f37c439a9a408396b8283a921238a1c6), [diffusers PR #14182](https://github.com/huggingface/diffusers/pull/14182), [VulnCheck: Diffusers path traversal advisory](https://www.vulncheck.com/advisories/diffusers-path-traversal-via-weight-map-arbitrary-file-read), [Jellyfin GHSA-jh22-fw8w-2v9x](https://github.com/jellyfin/jellyfin/security/advisories/GHSA-jh22-fw8w-2v9x), [SentinelOne: CVE-2026-35033](https://www.sentinelone.com/vulnerability-database/cve-2026-35033/).*
