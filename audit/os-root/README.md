# Original-userland QEMU test: 2026-10-25

The original iPadOS userland ran, but a usable desktop did not appear. The condition for beginning a vermeer port has not been met. No physical phone operations were performed.

Tested commit: `f7638b09598f045bd8912bd7e4f61a1b09835dbf`.
UniXNU baseline: `79d81c10220caebb15da5737a4eb6c20724cc731`.
Device scripts: `xVanTuring/UniXNU-qemu@97b75b1f63c6b7e895cd7646029db741d5fe5488`.
System input: official iPad7,1 / iPadOS 17.7.11 / 21H461.

[Run 40117331798](https://github.com/ReBiliBin/UniXNU/actions/runs/40117331798) · [Final logs and screenshots](https://github.com/ReBiliBin/UniXNU/actions/runs/40117331798/artifacts/12570752670)

| Check | Observed result |
| --- | --- |
| Source build, root kernel and payload | Passed on GitHub Intel macOS, Xcode 26.6 |
| Native-user checkpoint | PC 0x1000003d4, EL0, PID 1, sysctl 0 and 4096-byte pages passed in one frozen sample |
| Full OS/SystemOS input and policy | Full-block C/RSA verification passed; project-owned regular image files |
| Original userland | Original launchd PID 1 observed from about 61 to 892 seconds; logd, configd, backboardd, runningboardd and securityd also observed |
| Display | Stage 8, frame count 0 in all 14 valid samples |
| Screenshots | 14 real 800x600 PNGs: first black, remaining 13 pixel-identical firmware/DarwinBoot diagnostics; no iPadOS desktop |
| SpringBoard | Repeated explicit crashes and restarts; initial exception/backtrace not captured |
| Home and touch | Not attempted because no UI candidate appeared |

The configured observation window was 900 seconds; actual duration was 899.157 seconds. Fourteen valid kernel-log samples contained no detected panic signature. The observer reported no collection errors and exited 2 because UI acceptance failed. The supervisor completed in 987.017 seconds without timeout, forced signals or remaining owned PIDs. QMP quit was acknowledged; QEMU and its runner exited 0. This result does not establish a specific cause for either SpringBoard crashes or zero display frames.

Evidence archives (GitHub SHA-256 verified):

| Phase | Artifact ID | Files | SHA-256 |
| --- | --- | --- | --- |
| Host | 12570580080 | 8 | 26ac1eb23ef3d63581cb1b3a40481cd98e45c5fe3bf229afe1213f1c9ffa0603 |
| Preboot | 12571020408 | 47 | ed8bee10559c19f8297c966e6d4517bf070e62c1342be980c4a52827047a3424 |
| Final | 12570752670 | 95 | 31330c5944fa441f21850801cb81b9f1c7763b283dbedd5db58e8b40e05f18d4 |

The original launchd input SHA-256 was `8cec9a3c44a443b08e977ccc5d577850316ad428c575dc01f09b018dbd5b6a25`.

Next diagnostics: capture SpringBoard's first exception/backtrace, plus Legacy init/probe/attach/start and presenter results. Require a real desktop, sustained runtime and observed Home/tap responses before considering a vermeer port. Do not infer a phone-panel, GPU, setup or memory failure from this evidence alone.

The temporary branch push trigger has been removed after this bounded test. The workflow retains a `workflow_dispatch` definition; default-branch workflow availability controls the GitHub UI's Run button ([GitHub documentation](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#workflow_dispatch)). Manual dispatch after retirement was not tested, and no new run was requested. Main and the earlier draft PR remain unchanged. The tested commit preserves the exact workflow and scripts used for this run; later retirement/documentation changes are not additional runtime validation.

Reproduction uses `.github/workflows/os-root-validation.yml` and the scripts below this directory at the tested commit. It builds from source and fetches the pinned official system inputs into an ephemeral runner; the public artifacts contain diagnostic text and screenshots, not OS images, kernel/payload binaries, private keys or RAM dumps. QEMU runs with TCG, networking disabled, project-owned regular files and no hardware passthrough. No scheduling, email or real-device operations are part of this workflow.
