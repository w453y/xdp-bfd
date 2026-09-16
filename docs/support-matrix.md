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
- **Build (toolchain).** clang **>= 20**. Below it the BPF backend has no
  32-bit atomic compare-and-swap and, on some objects, emits code the
  kernel then refuses to load; the widening to 64-bit CAS lowered this as
  far as it goes without dropping features. This is a property of the build
  host only, not of where the package runs. `--check` on the target reports
  whether the shipped object loads on the running kernel.

## Measured

| arm | distro / kernel | build | object loads | notes |
|---|---|---|---|---|
| M1 | Debian 12 / 6.1 | ok | **yes** | the floor; verified with `run-arm.sh` |
| M1c | Debian 12 / 6.12 (backports) | ok | yes | current backports kernel |
| M3b | Ubuntu 24.04 / 6.8 | ok | yes | HWE kernel |
| — | Fedora / 6.14 | ok (rpm, mock) | yes | rpm build + load verified |

The XDP object is byte-identical across the packaging and hardening changes
on a given toolchain; the load result is a function of the kernel, not the
package.

## Unsupported by policy

These releases ship a kernel below the floor and are **not supported**. Each
is worth exactly one run to record an accurate "why not" line, then never
again:

| release | kernel | reason |
|---|---|---|
| Debian 11 | 5.10 | below the 6.1 floor |
| Ubuntu 22.04 (GA) | 5.15 | below the floor; the 6.8 HWE kernel is supported, the GA kernel is not |
| EL 9 | 5.14 | below the floor |
| EL 10 | 6.12 | at/above the floor: a support candidate, pending a confirming run |

The confirming runs (M1b Debian 11, M2 EL 9, M2b EL 10) capture the exact
refusal text `--check` produces on the sub-floor kernels; until they are
recorded here the drop for Debian 11 / Ubuntu 22.04 GA / EL 9 is policy but
not yet witnessed, and EL 10's inclusion is provisional.

## Packaging

Debian and RPM packages build and install across Debian 12/13, Ubuntu 24.04
and Fedora, with the unit present and disabled, the binaries hardened
(PIE, RELRO, BIND_NOW, FORTIFY) and the BPF object left unhardened by
design. The build host must carry clang >= 20 regardless of the target
distro's own toolchain; the Debian `Build-Depends` and the RPM `BuildRequires`
hold that floor.
