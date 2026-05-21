# Pattern 5 -- Cross-platform supply chain compromise

**MITRE coverage**: T1195 (Supply Chain Compromise), T1195.001
(Compromise Software Dependencies), T1195.002 (Compromise Software
Supply Chain), T1583 (Acquire Infrastructure), T1583.006 (Web Services).

**Detection type**: `process_creation` + `file_event` (cross-platform
Windows / Linux / macOS).

## What it detects

Adversary compromise of trusted software distribution channels:
NPM postinstall script execution, GitHub Action workflow injection,
Python package install-time code execution, container image layer
tampering, IDE/editor extension malicious updates, and SaaS-vendor
breaches that pivot to customer infrastructure.

## Canonical detection shape

```yaml
logsource:
  category: process_creation
  product: windows  # works for linux + macos with path normalisation
detection:
  selection_unsigned_install:
    Image|contains:
    - '\AppData\Local\Temp\'
    - '\Downloads\'
    - '\Installers\'
    - '/tmp/'
    - '/var/tmp/'
    Image|endswith:
    - '.exe'
    - '.msi'
    - '.dll'
    - '.dylib'
    - '.so'
  selection_pkg_install_script:
    ParentImage|endswith:
    - '\npm.exe'
    - '\node.exe'
    - '\pip.exe'
    - '\python.exe'
    - '\gem'
    - '\cargo.exe'
    CommandLine|contains:
    - 'postinstall'
    - 'preinstall'
    - 'install.js'
    - 'setup.py'
  filter_signed:
    Signed: 'true'
  filter_known_pkg_registry:
    cs-host|endswith:
    - '.npmjs.org'
    - '.pypi.org'
    - '.rubygems.org'
    - '.crates.io'
  condition: |
    (selection_unsigned_install or selection_pkg_install_script)
    and not filter_signed
```

## Why it works

- **Unsigned install selection** catches the canonical post-download
  installer execution from temp + downloads + installers paths.
  The `Signed` filter excludes legitimate signed installers.
- **Package install script selection** catches NPM / pip / gem /
  cargo install-time scripts -- the most common supply chain attack
  vector circa 2022-2026. The `ParentImage` filter ensures the rule
  fires only on script execution under package manager parents, not
  on developer-written scripts that happen to share names.
- **Package registry filter** allows install-time script execution
  from known good package registry hosts (npmjs.org, pypi.org, etc.)
  while still detecting install-time execution from foreign registries
  or direct-from-git installs.

## False positives

- **Legitimate package installs**: every `npm install` triggers
  install scripts for some dependencies. The `not filter_signed`
  branch will dominate -- consider scoping the rule to specific
  user contexts (build server vs developer workstation).
- **CI/CD pipelines**: build agents run package installs continuously.
  Whitelist by parent process being a known CI runner (`gha-runner`,
  `gitlab-runner`, etc.).
- **Container image bootstraps**: Dockerfile RUN instructions may
  match install-script patterns. Filter by hostname pattern being a
  build-isolated host.

## Reference rules from corpus

- `initial_access/template_t1195_supply_chain_compromise_untrusted_installer_execution.yml`
- `resource_development/template_t1583_acquire_infrastructure_newly_registered_domain_query.yml`
- `resource_development/template_t1583_001_acquire_infrastructure_domains_lookalike_domain.yml`
- `resource_development/template_t1585_001_establish_accounts_social_media_signup_hosts.yml`

## Specialisations

- **NPM postinstall-only (T1195.001 sub-variant)**: pivot to
  `selection_pkg_install_script` with `npm.exe` parent + `postinstall`
  / `prepublish` script hooks. Combine with newly-published-package
  filter (package age `<7 days`).
- **GitHub Actions workflow injection (T1195.002 sub-variant)**:
  pivot to `gha-runner` process + reference to third-party Action
  with a moved tag (`@v1` rewritten to point at a malicious commit
  SHA).
- **Pip + dependency confusion**: pivot to `pip install` with private
  package name resolving against public PyPI (organisation
  namespace-takeover variant).
- **VSCode extension supply chain (Pattern 18 sister)**: pivot to
  VSCode extension install path + post-install scripted command
  execution.
- **IoT/printer firmware supply chain**: pivot to printer-vendor
  firmware download + post-install configuration mutation (R88-53f
  IoT sister).

## Severity guidance

Supply chain compromise is typically **high** to **critical** --
the blast radius extends to every downstream consumer of the
compromised dependency. Lower to **medium** for single-package
install-script signals without secondary corroboration (network or
file-event signal).

## Why this pattern matters

The 2020-2026 window has seen supply chain compromise climb from
fringe-tactic to top-3-attack-vector. WRG's Pattern 18 (trust-but-
verify endpoint-supply-chain) v1.1 5-vaka super-cluster documents
TeamPCP NPM + Cengaver browser + TeamPCP VSCode + IoT printer +
Anthropic resmi marketplace plugin drift -- "even resmi vendor not
exempt" critical observation. Pattern 5 here is the detection-side
sister to Pattern 18's operational discipline.
