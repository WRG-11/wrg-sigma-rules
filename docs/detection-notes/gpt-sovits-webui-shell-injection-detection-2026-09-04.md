<!--
Companion detection note for the GPT-SoVITS webui shell-injection Sigma rule.
Accuracy source: resources/examples/execution/observed_gpt_sovits_webui_shell_injection_t1059.yml
Advisory sources: https://github.com/RVC-Boss/GPT-SoVITS/issues/2793 (fetched directly via
`gh api repos/RVC-Boss/GPT-SoVITS/issues/2793`) + VulnCheck corroborating write-up.
Detection/defense only, no exploit/PoC reproduced beyond what the GitHub issue already published.
-->

# Detecting the GPT-SoVITS WebUI Shell-Injection RCE (CVE-2026-63766, CVSS 9.3)

GPT-SoVITS's training/preprocessing WebUI runs by default on `0.0.0.0` with no authentication, and four of its handlers build shell commands by string-interpolating path values a visitor types into a Gradio textbox.

## What the flaw actually does

The ASR handler in `webui.py` (around lines 376-395) builds a command string like `'"%s" -s tools/asr/funasr/funasr_asr.py -i "%s" -o "%s" ...' % (python_exec, asr_inp_dir, asr_opt_dir)` and runs it with `Popen(cmd, shell=True)`. The slice, denoise, and uvr5 handlers repeat the identical pattern with their own textbox-sourced paths. The one sanitizer in the path, `clean_path()` in `tools/my_utils.py`, strips leading/trailing whitespace and quote characters and normalizes slashes — it does not touch `"`, `;`, `` ` ``, or `$()`. A path value containing a `"` followed by a shell metacharacter breaks out of the intended quoted argument and runs an arbitrary trailing command as the WebUI's own process user. The reporter confirmed this against the real sanitizer and command builder: an injected `;touch ...` ran.

Because the WebUI binds to every interface by default and requires no login, this is unauthenticated remote code execution on any network-reachable instance — a visitor just needs to type a crafted string into a path field and click the corresponding start button.

## The detection signal

The corpus rule (`execution/observed_gpt_sovits_webui_shell_injection_t1059.yml`) looks for a process spawned as a child of `webui.py` whose command line matches a quoted argument immediately followed by a semicolon and more content — the exact `"<path>" ... "; <injected>"` shape `clean_path()`'s incomplete filtering allows. The process-lineage condition (parent is the webui process) is what keeps this from matching ordinary shell usage elsewhere on the host.

## Known limitation

No patched version was confirmed at the time this rule and note were written — the GitHub issue's own remediation section describes what SHOULD change (argument-list `Popen` calls, a metacharacter-aware `clean_path()`, authentication or loopback-only binding) without stating that any of it has shipped. This rule has no reliable "already fixed, ignore" case to lean on; every match deserves a look until you have confirmed your specific deployment's version behavior directly. Separately, a legitimate path containing a semicolon for unrelated reasons is unusual but not provably impossible on every filesystem — the process-lineage check narrows this but does not fully resolve it.

## What to do right now

1. **Do not expose this WebUI beyond a trusted network.** It binds to `0.0.0.0` by default with no authentication built in — put it behind a reverse proxy that requires auth, or restrict it to loopback/VPN-only access, until an upstream fix lands.
2. If you maintain a fork or a patched build, apply the reporter's own remediation: replace `shell=True` string interpolation with an argument-list `Popen` call across all four handlers (ASR, slice, denoise, uvr5), and harden `clean_path()` to reject shell metacharacters rather than only stripping quotes and whitespace.
3. Deploy the detection rule above against process-creation telemetry on any host running GPT-SoVITS's WebUI.

---

*Detection content from WinstonRedGuard (WRG-11). Defensive detection of a publicly reported, unpatched-at-authoring vulnerability. References: [RVC-Boss/GPT-SoVITS issue #2793](https://github.com/RVC-Boss/GPT-SoVITS/issues/2793), [VulnCheck corroborating write-up](https://www.vulncheck.com/advisories/gpt-sovits-20250606v2pro-os-command-injection-via-webui-py).*
