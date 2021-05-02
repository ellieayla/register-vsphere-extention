#!/usr/bin/env python

from __future__ import print_function, unicode_literals
import subprocess
import libxml2
import logging
import requests
import datetime
import time

from pyVmomi import vim
from pyVmomi import vmodl
from pyVmomi import SoapAdapter
from pyVim.connect import VimSessionOrientedStub

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

import ssl

try:
    from cryptography.x509 import random_serial_number
except:
    import os
    from cryptography import utils
    def random_serial_number():
        return utils.int_from_bytes(os.urandom(20), "big") >> 1

EXTENTION_KEY = "com.vmware.example.josh"

NSDICT = \
{
    'o'     :   "http://schemas.dmtf.org/ovf/environment/1",
    'xsi'   :   "http://www.w3.org/2001/XMLSchema-instance",
    'oe'    :   "http://schemas.dmtf.org/ovf/environment/1",
    've'    :   "http://www.vmware.com/schema/ovfenv",
    'evs'   :   "http://www.vmware.com/schema/vservice/ExtensionVService"
}

PEM_CERTIFICATE_FILE = "/certificate.pem"
PEM_PRIVATE_KEY = "/private.pem"

logging.basicConfig(format=u'%(asctime)s %(name)s %(levelname)s: %(message)s')
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

def get_vservice_section(xp, section):
    return xp.xpathEval("//o:Environment/ve:vServiceEnvironmentSection/" + section)[0].content

def get_or_make_certificate():
    
    try:
        with open(PEM_CERTIFICATE_FILE, 'r') as f:
            pem = f.read()
            logger.info("Read existing certificate from {0}:\n{1}".format(PEM_CERTIFICATE_FILE, pem))
        with open(PEM_PRIVATE_KEY, 'r') as f:
            private = f.read()
            logger.info("Read existing private key from {0}:\n{1}".format(PEM_PRIVATE_KEY, pem))
    except IOError:
        logger.info("No existing certificate at {0} / {1}, creating".format(PEM_CERTIFICATE_FILE, PEM_PRIVATE_KEY))
        # http://pubs.vmware.com/vsphere-60/topic/com.vmware.vsphere.ext_solutions.doc/GUID-460681E8-5FA3-4749-9D80-E845EF8D0D88.html
        # Create a self-signed X509 certificate.
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"CA"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"Palo Alto"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"VMware"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"demo.extension"),
        ])
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=10)
        ).sign(private_key, hashes.SHA256(), default_backend())
        
        pem = cert.public_bytes(serialization.Encoding.PEM)
        
        private = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption())
        with open(PEM_CERTIFICATE_FILE, 'w') as f:
            f.write(pem)
            logger.info("Wrote new certificate to {0}:\n{1}".format(PEM_CERTIFICATE_FILE, pem))
        with open(PEM_PRIVATE_KEY, 'w') as f:
            f.write(private)
            logger.info("Wrote new certificate to {0}:\n{1}".format(PEM_PRIVATE_KEY, pem))
    return (pem,private)

def wait_task(task):
    while task.info.state not in [vim.TaskInfo.State.success,
                                      vim.TaskInfo.State.error]:
        logger.info("Waiting for task %s" % str(task))
        time.sleep(1)
    if task.info.state == vim.TaskInfo.State.error:
        raise RuntimeError(task.info.error)
    return task.info

def main():
    
    
    ovfenv_xml = subprocess.check_output(["/opt/vmware/bin/ovfenv", "--dump"], bufsize=1)
    try:
        doc = libxml2.parseDoc(ovfenv_xml)
    except:
        raise RuntimeError("Unable to parse the following ovf environment: " + ovfenv_xml)
    
    xp = doc.xpathNewContext()
    for k, v in NSDICT.iteritems():
        xp.xpathRegisterNs(k, v)
    
    print(doc)
    
    SelfMoRef = get_vservice_section(xp, "evs:VCenterApi/evs:SelfMoRef")
    logger.info("Deployed on platform %s" % " ".join([a.content for a in xp.xpathEval("//o:Environment/o:PlatformSection/*")]))
    logger.info("Known as {0} in VC".format(SelfMoRef))
    
    extension_service_endpoint = get_vservice_section(xp, "evs:GuestApi/evs:URL")
    extention_service_token = get_vservice_section(xp, "evs:GuestApi/evs:Token")
    extention_service_thumbprint = get_vservice_section(xp, "evs:GuestApi/evs:X509Thumbprint")
    
    logger.info("Can register VC Extention at endpoint {0}".format(extension_service_endpoint))
    
    vc_server = get_vservice_section(xp, "evs:VCenterApi/evs:IP")
    logger.info("Can connect to VC at {0}".format(vc_server))
    certpem, private = get_or_make_certificate()
    
    ######
    logger.info("Boops")
    
    registration_document = libxml2.parseDoc('<RegisterExtension xmlns="http://www.vmware.com/schema/vservice/ExtensionVService"/>').getRootElement()
    
    
    
    Key = libxml2.newNode('Key')
    Key.setContent(EXTENTION_KEY)
    registration_document.addChild(Key)
    Certificate = libxml2.newNode('Certificate')
    Certificate.setContent(certpem)
    registration_document.addChild(Certificate)
    logger.warning(str(registration_document))
    
    logger.info("Making an HTTP POST to {0} with token {1} and this RegisterExtension body.".format(
        extension_service_endpoint,
        extention_service_token
    ))
    
    r = requests.post(
        extension_service_endpoint,
        verify=False,
        headers={'evs-token': extention_service_token, 'Content-Type': 'application/xml'},
        data=str(registration_document)
    )
    
    if r.status_code != 200:
        raise RuntimeError("Got HTTP status {0} back from registration attempt to {1}".format(r.status_code, r.url))
    logger.info("Registered extention {0}".format(EXTENTION_KEY))


    logger.info("Attempting to authenticate to {0}".format(vc_server))
    
    context = ssl._create_unverified_context()
    print(context.load_cert_chain(PEM_CERTIFICATE_FILE, keyfile=PEM_PRIVATE_KEY, password=b"passphrase"))
    
    soapStub = SoapAdapter.SoapStubAdapter(certKeyFile=PEM_PRIVATE_KEY, certFile=PEM_CERTIFICATE_FILE, host=vc_server, port=8089, httpProxyHost=vc_server, ns="vim25/5.0", sslContext=context)
    
    # TODO: pyvmomi doesn't have a way to unlock the private key with a phasephrase, and it's created with one.
    
    si = vim.ServiceInstance("ServiceInstance", soapStub)
    
    # You can't establish this connection to port 443. You need to connect to 8089??
    # https://communities.vmware.com/message/1900462?tstart=0#1900462
    si.content.sessionManager.LoginExtensionByCertificate(EXTENTION_KEY)
    
    logger.info("Authenticated to {0} as {1}={2}".format(
        si.content.about.fullName,
        si.content.sessionManager.currentSession.key,
        si.content.sessionManager.currentSession.userName
        ))
    
    
    
    motd = "This vCenter Server is now under the control of {0}".format(EXTENTION_KEY)
    logger.info("Setting MOTD to: {0}".format(motd))
    si.content.sessionManager.UpdateServiceMessage(message=motd)
    
    logger.info("Finding my own extension object and updating its description")
    my_extention = si.content.extensionManager.FindExtension(extensionKey=EXTENTION_KEY)
    
    if my_extention.description.label != "Demonstration Extention":
        my_extention.description.label = "Demonstration Extention"
        my_extention.description.summary = "Extention Demonstrating Awesomeness"
        si.content.extensionManager.UpdateExtension(extension=my_extention)
    
    if 0==len(my_extention.managedEntityInfo):
        logger.info("Adding managed entity infos")
        mei = vim.ext.ManagedEntityInfo(type="Awesome", description="The most awesome VMs")
        my_extention.managedEntityInfo.append(mei)
        si.content.extensionManager.UpdateExtension(extension=my_extention)
    
    
    container = si.content.rootFolder
    viewType = [vim.VirtualMachine] # list all the VMs
    recursive = True
    containerView = si.content.viewManager.CreateContainerView(container, viewType, recursive)

    children = containerView.view
    for vm in children:
        if "%s:%s" % (vm._wsdlName, vm._moId) == SelfMoRef:
            print(vm.name, vm, vm._moId, "This is me!")
            
            if vm.config.managedBy is None or vm.config.managedBy.extensionKey != EXTENTION_KEY:
                logger.info("Changing my VM to be managed by its own extension")
                mbi = vim.ext.ManagedByInfo(extensionKey=EXTENTION_KEY, type="Awesome")
                spec = vim.vm.ConfigSpec()
                spec.managedBy = mbi
                reconfig_task = vm.ReconfigVM_Task(spec)
                
                wait_task(reconfig_task)
                
                
            
            
            
        else:
            print(vm.name, vm, vm._moId, "not", SelfMoRef)
            
    
    """
    spec = vim.vm.ConfigSpec()
    spec.annotation = args.message
    task = vm.ReconfigVM_Task(spec)
    tasks.wait_for_tasks(si, [task])
    
    """
    return si
        
if __name__ == "__main__":
    x = main()