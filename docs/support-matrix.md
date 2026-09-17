# Support matrix

## Policy

Supported means the **newest kernel a supported distro release ships**, or
offers as its HWE / updates kernel, and **no kernel below 6.1**. There is no
backport hunting on 5.10 / 5.14 / 5.15 series kernels: if a release's stock
kernel is below the floor, that release is unsupported, not worked around.

Two separate floors matter:

- **Runtime (kernel).** 6.1. This is where the XDP object's verifier
  requirements are met; it is also the Debian 12 kernel and the VyOS 1.4
  base, which is why 6.1 is the line.
- **Build (toolchain).** clang **>= 17**. The original blocker was that
  the BPF backend below clang 20 had no 32-bit atomic compare-and-swap;
  widening those atomics to 64-bit removed it, and clang 17 now compiles
  the object, which loads and passes the XDP test suite (17 is the lowest
  measured, and the CI toolchain matrix gates 17 through 21). This is a
  property of the build host only, not of where the package runs.
  `--check` on the target reports whether the shipped object loads on the
  running kernel.

## Measured

Object load is the support question ("does the XDP program load and
attach?"), so it is what each arm records. The build floor (clang >= 17)
is separate and is a build-host property, not a runtime one.

| arm | distro / kernel | object loads | notes |
|---|---|---|---|
| M1 | Debian 12 / 6.1 | **yes** | the floor; verified on the 6.1 kernel directly (VM booted into 6.1, not the backports 6.12) |
| M1c | Debian 12 / 6.12 (backports) | yes | current backports kernel |
| M3b | Ubuntu 24.04 / 6.8 | yes | HWE kernel |
| M2 | AlmaLinux 9 / 5.14 | **yes** | RHEL's "5.14" carries a heavily backported BPF stack and clears the bar despite the version number |
| M2b | AlmaLinux 10 / 6.12 | **yes** | |
| — | Fedora / 6.14 | yes | rpm build + load verified |
| M1b | Debian 11 / 5.10 | not captured | vanilla 5.10, below the feature bar; expected to refuse. Live capture was blocked by the bullseye archive being EOL, which is itself a reason to drop it |

The object is byte-identical across the packaging and hardening changes on
a given toolchain (md5 confirmed equal on the DUT and each arm); the load
result is a function of the kernel's BPF feature set, not the package or
the version string.

**The version floor is a statement about vanilla kernels.** "No kernel
below 6.1" holds for stock upstream kernels, where the verifier features
and stack behaviour the object relies on first appear. An enterprise
kernel that carries a low version number but backports the BPF stack -
RHEL / AlmaLinux 9's 5.14 is the example - clears the bar and loads. EL is
therefore judged by the load test, not by the 5.14 label, and both EL9 and
EL10 pass.

## Support tiers

Measured to load, hence supportable: Debian 12 (6.1) and its 6.12
backports, Ubuntu 24.04 (6.8), Fedora (6.14), AlmaLinux 9 (5.14 with the
RHEL backports) and AlmaLinux 10 (6.12).

Below the feature bar, unsupported: Debian 11 (vanilla 5.10), and Ubuntu
22.04 on its GA 5.15 kernel (its 6.8 HWE kernel is supported).

**EL9 and EL10 are both supported.** They load and function (build,
`--check` ABI-match, and live XDP attach all pass), so the enterprise arm
is judged by the load test, not by the "5.14" version string. The
"no kernel below 6.1" rule stands only for *vanilla* upstream kernels;
Debian 11 (vanilla 5.10) and Ubuntu 22.04 on its GA 5.15 kernel are below
the feature bar and remain unsupported (Ubuntu 22.04's 6.8 HWE kernel is
supported).

## Packaging

Debian and RPM packages build and install across Debian 12/13, Ubuntu 24.04
and Fedora, with the unit present and disabled, the binaries hardened
(PIE, RELRO, BIND_NOW, FORTIFY) and the BPF object left unhardened by
design. The build host must carry clang >= 17 regardless of the target
distro's own toolchain; the Debian `Build-Depends` and the RPM `BuildRequires`
hold that floor.
