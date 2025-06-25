Name: m.fedyarov.wireguard
Summary: Userspace implementation of WireGuard in Go.
Version: 0.0.20250522
Release: 1
License: MIT License
Source0: %{name}-%{version}.tar.zst
Patch1: 0001-tools-Made-changes-to-be-used-in-ConnMan-VPN-Wire.patch
%description
Userspace implementation of WireGuard in Go.
Fully-compatible with AuroraOS.

%build
%make_build

make -C wireguard-tools/src

%install
mkdir -p %{buildroot}%{_bindir}
cp wireguard-go/wireguard-go %{buildroot}%{_bindir}/%{name}-go
cp wireguard-tools/src/wg %{buildroot}%{_bindir}/%{name}-wg

cd aurora
%make_install

%files
%{_bindir}/%{name}
%{_bindir}/%{name}-go
%{_libdir}/connman/plugins-vpn/wireguard.so

%{_bindir}/%{name}-wg
