Name:           xdp-bfd
Version:        %{?_version}%{!?_version:0.0.0}
Release:        1%{?dist}
Summary:        XDP-based BFD data plane

License:        GPL-2.0-only AND MIT
URL:            https://github.com/w453y/xdp-bfd
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  clang >= 20
BuildRequires:  llvm
BuildRequires:  libbpf-devel
BuildRequires:  kernel-headers
BuildRequires:  systemd-rpm-macros
BuildRequires:  make
BuildRequires:  gcc

Recommends:     frr >= 8.4
Recommends:     bpftool

%description
xdp-bfd runs Bidirectional Forwarding Detection in the kernel with an XDP
program. It offloads the periodic transmit and the fast detection timers
from FRR's bfdd, so sub-second sessions scale without a userspace packet
for every tick. It attaches to FRR over the bfdd data-plane socket, or
runs a single static session on its own.

%prep
%autosetup

%build
# Export Fedora hardening flags (PIE, RELRO, FORTIFY) into the environment
# so they reach the userspace build; the Makefile honours CFLAGS/LDFLAGS.
%set_build_flags
make CLANG="$(command -v clang-21 || command -v clang-20 || command -v clang)" VERSION=%{version} LIBDIR=%{_libdir}/xdp-bfd %{?_smp_mflags}

%check
make check-host CLANG="$(command -v clang-21 || command -v clang-20 || command -v clang)"

%install
make install DESTDIR=%{buildroot} PREFIX=%{_prefix} SBINDIR=%{_sbindir} \
    LIBDIR=%{_libdir}/xdp-bfd UNITDIR=%{_unitdir} SYSCTLDIR=%{_sysctldir} \
    SYSCONFDIR=%{_sysconfdir} MANDIR=%{_mandir}/man8 DOCDIR=%{_docdir}/%{name} \
    VERSION=%{version}

%post
%systemd_post xdp-bfd.service
# Advisory load-and-ABI probe. Never fails the install.
if xdp-bfd --check >/dev/null 2>&1; then
    echo "xdp-bfd: the XDP object loads and is ABI-matched on this kernel ($(uname -r))."
else
    echo "xdp-bfd: the XDP object did NOT load on this kernel ($(uname -r)); advisory only." >&2
    xdp-bfd --check >&2 2>&1 || true
fi

%preun
%systemd_preun xdp-bfd.service

%postun
%systemd_postun_with_restart xdp-bfd.service

%files
%license LICENSE
%doc %{_docdir}/%{name}/README.md
%{_sbindir}/xdp-bfd
%{_sbindir}/xdp-bfd-observe
%dir %{_libdir}/xdp-bfd
%{_libdir}/xdp-bfd/bfd_xdp.o
%{_unitdir}/xdp-bfd.service
%{_sysctldir}/50-xdp-bfd.conf
%dir %{_sysconfdir}/xdp-bfd
%config(noreplace) %{_sysconfdir}/xdp-bfd/engine.conf
%{_mandir}/man8/xdp-bfd.8*
%dir %{_docdir}/%{name}/examples
%{_docdir}/%{name}/examples/frr-daemons.snippet

%changelog
* Tue Sep 15 2026 Abdul Wasey <awasey8905@gmail.com> - 0.0.0-1
- Placeholder entry. tools/build-packages.sh writes the real entries from the git tag.
