# Project Config — certinspect

> All project-specific **values** live in this file; skills read `section.key`
> (and `{section.key}` in commands) and must use the configured value, never a literal.

## SCHEMA — how to read this file
> - **`project.role`** picks the archetype; **`stack.profile`** picks the tech profile. Together they decide
>   which sections apply.
> - Everything under the trunk (`identity`, `git`) is a **capability**: present in an instance ONLY if that
>   repo has it. The **`capabilities:`** line lists the active set. **A skill whose capability is absent must
>   say "not configured for this repo" and stop — never guess a command.**
> - Capabilities model an **interface** (intent) + this repo's binding, so the same skill works on any stack.
> - **A capability carries a MECHANISM the skill must branch on — never assume one.** `test.framework`,
>   `i18n.mechanism`, `build.mechanism`, `release.key` differ per profile (`vue-i18n`≠`transloco`≠`gettext`;
>   `manage.py test`≠`pytest`≠`karma`). Read the mechanism before acting; if unknown, ask, don't guess.
> - `# default: X` = the BU standard a new repo starts from. `# BU` = a binding org standard.
> - **Lists** are comma-separated; the first item is primary.
> - Enums (validated across 11 BU repos: django×2, fastapi×2, vue+angular SPAs, electron×2, py/node native libs, android lib, ios apps×2):
>   - role: `web-backend | frontend-spa | desktop-app | mobile-app | native-lib | service | deploy-orchestrator`
>   - stack.profile: `django | fastapi | vue-spa | angular | electron | ios-swift | android | py-lib | node-native | jvm`  (the profile block is keyed by this)
>   - stack.package-manager: `poetry | uv | pip | npm | pnpm | cocoapods | gradle | maven`
>   - capabilities: `lifecycle · tracker · run · test · build · release · containers · i18n · docs · domain · benchmark · signing · variants · native-build · submodules`
>   - git.lifecycle: `gitflow` (dev→staging→prod) | `trunk` (single main)
>   - git.commit-format: conventional `type(KEY): ...` (this repo) | bracketed `[KEY] ...` (e.g. digitalid) — per-repo value
>   - test.framework: `django | pytest | vitest | karma | jest | junit | node-test | xctest`
>   - i18n.mechanism: `django-gettext | vue-i18n | transloco | i18next | apple-strings | android-resources | none`
>   - build.mechanism: `docker-image | static-bundle | installer (nsis/pkg/dmg) | wheel | npm-pkg | aar | native-exe (hpython/pyinstaller)`
>   - release.key: `tenant` (web) | `os` (desktop) | `platform` (mobile→testflight/appstore/play) | `publish` (lib→pypi/npm/maven/artifactory) | `static` (spa→cdn/s3) | `none`
>     - release.tag GRAMMAR is a per-repo value, not universal: `b4#deploy@stage=…@tenant=…` (web, BU std) vs `CUSTOMER;VERSION` (firma4 desktop, Jenkins). Read it; don't assume.
>   - signing [capability]: a BUILD concern for distributables — PER-PLATFORM: `{macos: certs+notarize+entitlements, windows: authenticode-pfx, linux: none}` · `apple-certs+provisioning` (ios) · `android-keystore`. Absent for web/lib.
>   - variants [capability]: white-label/flavors — `xcconfig` (ios) · `gradle-flavors` (android) · `compile_env` (angular) · `customers/` + electron-builder `extraMetadata`/`<CUSTOMER>` substitution · docker `--build-arg customer=`. PERVASIVE (~8 repos); build & release multiply per flavor.
>   - native-build [capability]: compiled C/C++ inside the build — `cmake-js` (node) · `scikit-build` (py) · `ndk+cmake` (android, multi-ABI).
>   - NOTE: domain richness (crypto/signing-engine/identity-stores/cryptoki/HSM) is a `domain` OVERLAY (like this repo's IAM block), NOT new capabilities. deploy-orchestrator has two flavors: web-deploy (compose+ssh, e.g. nss-deploy) and desktop-build (cross-platform installers, e.g. bit4id-firma4). Both use `submodules`.

---

## identity            [always]
```
project.name:            certinspect
project.org:             mangrisano
project.repo:            mangrisano/certinspect
project.role:            native-lib
project.app-dir:         src/certinspect/
project.context-file:    none
stack.profile:           py-lib
stack.languages:         Python
stack.package-manager:   pip
content.languages:       en
capabilities:            run, test, build, release, benchmark
#                          (absent here: lifecycle, tracker, containers, i18n, docs, domain, signing, variants, native-build, submodules)
```

## git                 [always]
```
git.forge:               GitHub
git.host:                github.com
git.cli:                 gh
git.remote:              origin
git.pr-term:             PR
git.lifecycle:           trunk
git.production-branch:   main
git.protected-branches:  main
git.hotfix-origin:       production-branch
git.commit-format:       type(scope): imperative description (<=72 chars)
git.commit-types:        feat, fix, refactor, test, docs, chore
git.commit-footers:      none
git.branch-prefixes:     feature/, bugfix/, refactor/, chore/, hotfix/
git.branch-format:       <prefix>/<kebab-description>
git.never:               force-push, hard reset, --no-verify, amend pushed commits, delete remote branches
```

## run                 [capability: run]
```
run.mechanism:           native-cmd
run.dev:                 .venv/bin/certinspect <target>
```

## test                [capability: test]
```
test.framework:          pytest
test.full-suite:         .venv/bin/pytest -q
test.single-target:      .venv/bin/pytest -q {path}
test.serial-flag:        -n 0
test.output-capture:     redirect to /tmp/test-output.txt in ONE call, grep AFTER (never chain a pipe)
test.path-derivation:    tests/test_<module>.py
test.rules:              run via .venv/bin/pytest; also check .venv/bin/ruff check src tests and .venv/bin/mypy src
test.skip:               none
test.flags:              -k <name>, -q, -v
```

## build               [capability: build]
```
build.mechanism:         wheel
build.command:           .venv/bin/python -m build
build.output:            dist/
```

## benchmark           [capability: benchmark]
```
benchmark.run-cmd:       .venv/bin/pytest benchmarks --benchmark-json=output.json -o 'python_files=bench_*.py'
benchmark.baseline:      gh-pages:dev/bench
benchmark.threshold:     2x
benchmark.results-json:  output.json
benchmark.filter-flag:   -k <name>
benchmark.run-rules:     run serially against benchmarks/bench_perf.py
```

## release             [capability: release]
```
release.mechanism:       publish
release.key:             publish
release.tag:             v<semver>
release.version:         SemVer (vX.Y.Z)
release.root-changelog:  CHANGELOG.md
```

## profile:py-lib      [stack.profile: py-lib]
```
pylib.language:          Python (3.12-3.14)
pylib.package-manager:   pip
pylib.build-backend:     setuptools
pylib.public-api:        certinspect (cli, fetch, parser, formatter, revocation, discover, httpfetch, models, exit_codes, render, config, state)
pylib.test-framework:    pytest
pylib.type-check:        mypy
pylib.lint:              ruff
pylib.publish:           pypi
```

## skills              [manifest]
```
skills.core:             branch, commit, ticket, bug-fix, refactor, implement, dev-flow, pr-prep, adr-status, usage-doc, docker, init-project, release, hotfix, changelog, benchmark, write-a-skill, test, review
skills.capability-gates: docker->containers · test->test · update-templates->i18n+profile:django · release->release · hotfix->lifecycle · changelog->docs · benchmark->benchmark · init-project->(always/meta) · write-a-skill->(always/meta)
```
