#Manual Build

Deploy the PhotonOS OVA to VC

    ovftool --diskMode=thin --acceptAllEulas --powerOn Downloads/images/photon-custom-hw10-1.0-13c08b6.ova 'vi://administrator%40vsphere.local:VMware123!@192.168.50.130/dc/host/192.168.50.128/'

Install some RPMs from https://buildweb.eng.vmware.com/ob/4543807/, which could be avoided with http://www.virtuallyghetto.com/2012/06/ovf-runtime-environment.html

    scp vmware-studio-vami-tools_3.0.0.2-4446656.x86_64.rpm root@VMIP:
    rpm -i libxml2-2.9.4-1.ph1.x86_64.rpm libxml2-python-2.9.4-1.ph1.x86_64.rpm vmware-studio-vami-tools_3.0.0.2-4446656.x86_64.rpm

Install some python libraries from PhotonOS and Cheeseshop

    tdnf install -y python-setuptools
    tdnf install -y python-cryptography
    easy_install enum34 ipaddress pyasn1 idna pyvmomi


Install our custom code, including a systemd boot-time service.
    (Maybe we should make an RPM of this?)

Shut down the PhotonOS VM gracefully.

Export the OVF from VC.

    ovftool 'vi://administrator%40vsphere.local:VMware123!@192.168.50.130/dc/host/192.168.50.128/Resources/photon-vami' photon-for-josh2.ovf

Open OVF file in editor.

Add a `vmw:vServiceDependencySection` section consuming `com.vmware.vservice.extension` and citing id `installation`

    <vmw:vServiceDependencySection
            xmlns:ovf="http://schemas.dmtf.org/ovf/envelope/1"
            xmlns:vmw="http://www.vmware.com/schema/ovf"
            ovf:required="true"
            vmw:id="installation">
        <ovf:Info>A vService dependency</ovf:Info>
        <vmw:Type>com.vmware.vservice.extension</vmw:Type>
        <vmw:Name>vCenter Extension Installation</vmw:Name> 
        <vmw:Description>
             This appliance requires a binding to the vCenter Extension vService,
             which allows it to register automatically as a vCenter Extension at runtime.
        </vmw:Description>
        <vmw:Configuration />
    </vmw:vServiceDependencySection>

Modify the `VirtualHardwareSection` to include an OVF Environment transport

    <VirtualHardwareSection ovf:transport="com.vmware.guestInfo" ovf:required="true">

Add OVF Properties, including a PublicKey and CloudUrl, with no values.

Save the OVF file.

#Staging

We have a useless manfiest (sha1 hashes) and certificate (signing), since we're going to ship customized OVAs to every request.

Compute a new manifest file for only the VMDK.

    openssl sha1 photon-custom-disk1.vmdk > photon-custom-hw10.mf
    SHA1(photon-custom-disk1.vmdk)= 7405a10b95ad165e91dfbee18ebb05279c1af1d8

Copy the OVF, VMDK and simplified Manifest files to somewhere the webserver can access.

#Wait for a download request

Open the OVF file, modify the PublicKey and CloudUrl properties according to the requesting user context, retain in-memory.

Read the eCompute a new sha1 hash of the in-memory OVF "file", similar to that produced by `openssl sha1`. Combine with existing hash of the VMDK file in-memory.

    openssl sha1 *.ovf *.vmdk
    SHA1(photon-custom-hw10.ovf)= 5e35689cbdd6e26f465a962466c2c76110537e97

Compute a new certificate file `photon-custom-hw10.cert` in-memory.

Create a streaming tar file, with the in-memory OVF, in-memory MF, in-memory CERT and on-disk VMDK

    photon-custom-hw10.ovf
    photon-custom-hw10.mf
    photon-custom-hw10.cert
    photon-custom-disk1.vmdk


#Deploy

Import the OVF to VC. If using OVFTOOL, pass in the service dependency ala http://www.virtuallyghetto.com/2014/10/how-to-configure-the-vcenter-extension-vservice-using-ovftool.html

    ovftool --vService:installation=com.vmware.vim.vsm:extension_vservice photon-vami.ovf 'vi://administrator%40vsphere.local:VMware123!@192.168.50.130/dc/host/192.168.50.128'

    ovftool --acceptAllEulas --overwrite --powerOn --net:"Network 1"="VM Network" --net:"Network 2"="VM Network" --vService:installation=com.vmware.vim.vsm:extension_vservice ~/Downloads/CloudAgentVM.3/photon-cloudagentvm_OVF10.ovf 'vi://administrator%40vsphere.local:VMware123!@192.168.50.130/dc/host/192.168.50.128'


#Needed In The VA
* SSH Host Keys generated on first (every?) boot when they're missing `ssh-keygen -f /etc/ssh/ssh_host_rsa_key -N '' -t rsa`
* Firewall permitting ICMP `iptables -P INPUT ACCEPT`
* /etc/ssh/sshd_config with `PermitRootLogin yes`




#Deploy from Studio to VC

    ovftool --acceptAllEulas --overwrite --powerOn --net:"Network 1"="VM Network" --net:"Network 2"="VM Network" --vService:installation=com.vmware.vim.vsm:extension_vservice http://192.168.50.133/build/Collector.3/exports/ovf/VM_OVF10.ovf 'vi://administrator%40vsphere.local:VMware123!@192.168.50.130/dc/host/192.168.50.128'

