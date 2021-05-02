Summary:        Create Iptables rule to allow inbound traffic to port 443 VAMI
Name:           iptables-vami-port-443-open
Version:        1.0
Release:        1%{?dist}
Group:          System Environment/Security
BuildArch:      noarch

Vendor:         VMware, Inc.
License:        Commercial
URL:            http://www.vmware.com/
Source0:        %{name}.service

BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root
Requires:       vmware-studio-vami-lighttpd,systemd

%description
Open an iptables firewall rule allowing inbound TCP port 443 traffic
to reach the vmware-studio-vami-lighttpd daemon.
%prep
rm -rf $RPM_BUILD_ROOT
%{__install} -d ${RPM_BUILD_ROOT}/usr/lib/systemd/system/
%{__install} -m0644 %{SOURCE0} ${RPM_BUILD_ROOT}/usr/lib/systemd/system/


%build
exit 0

#%install
exit 0

%files
%attr(0644, root, root) /usr/lib/systemd/system/iptables-vami-port-443-open.service

%doc



%changelog
* Sun Apr  3 2016 makerpm
-

