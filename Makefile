

.PHONY: rpm

rpm:
	rpmbuild --verbose -ba packages/SPECS/iptables-vami-port-443-open.spec

