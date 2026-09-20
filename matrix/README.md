# Support matrix arms

## Four ways to produce a plausible but false row

All four happened on the first run, and all four produce a row that looks
filled in. The RPM arms will reproduce them, so read these first.

- **`PRETTY_NAME` contains spaces.** A word split put the kernel version in
  the `os` field and everything else in `arch`. Ask for each fact in its
  own call.
- **Every compile line carries `-Werror`.** Grepping a build log for
  "error" therefore reports the *command* as the failure. And "failure"
  matches the success line `0 failure(s)`, so a real failure gets recorded
  as that string. Match what a failure actually says.
- **`libbpf-dev` is multiarch**, so `dpkg-query -W` needs the architecture
  qualifier or returns nothing and the field is silently empty.
- **`/usr/sbin` is not on `PATH`** for a non-login shell as a normal user
  on Debian. `ethtool` and `ip` report themselves absent on a machine where
  `dpkg -l` shows them installed, and the row records "ethtool absent"
  which is a lie.


`run-arm.sh <ssh-target> <arm-name> [object ...]` answers, for one distro,
whether it builds the engine, loads the object, and brings a session up.
One JSON object per arm on stdout; the rows live beside this file.

The object is carried from the build host and the engine is built on the
arm. That is the package's own shape, and it keeps two unrelated failures
apart: an engine built on a newer host can fail on an older glibc, or on
libbpf's versioned symbols even when the soname matches, and either would
read as "this kernel refuses us".

Several objects can be given at once. Loading more than one on the same
kernel is how a row answers whether a workaround is load-bearing across the
supported range or only at its floor.

## Building the VMs on this cluster

Things that cost a rebuild to learn, so nobody learns them twice:

- **The gateway is on `vmbr1`, not `vmbr0`.** A VM whose management NIC is
  on vmbr0 gets no DHCP and no route, boots fine, and is simply
  unreachable. Put net0 on vmbr1 with a static address.
- Management addresses are `192.168.11.<VMID>`, one per arm, from .201 up.
  The test NIC goes on `vmbr9`, an isolated bridge with no uplink and no
  gateway, addressed 10.99.0.0/24.
- Give each arm at least 2 vCPUs and `queues=4` on the virtio NIC. A
  single-queue virtio can fall back to generic XDP silently, and with
  `XDP_FLAGS_DRV_MODE` forced it fails outright. The default shape here
  takes a native attach; the row records the queue count so the
  documentation can say which shape was tested.
- `qm importdisk` against `local-zfs` can report `got timeout` while the
  zvol is in fact created. Check `zfs list -r rpool/data` before retrying,
  and destroy the strays first or the next attempt collides.
- The Debian genericcloud image has no `ethtool` and no guest agent. The
  script installs its whole tool list before any probe runs, because
  installing one half way through once cost a row its NIC fields.

An attach in generic mode is a valid functional row. It is not a timing
row: these are virtio NICs under KVM, and no latency number should be
taken from them.
