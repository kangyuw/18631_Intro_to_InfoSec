#!/usr/bin/python3

from OpenSSL import SSL,crypto
import socket
import certifi
import pem
import fnmatch
import urllib

# Cert Paths
## 1. Load trusted root certificates to .pem
TRUSTED_CERTS_PEM = certifi.where()

def get_cert_chain(target_domain):
    '''
    This function gets the certificate chain from the provided
    target domain. This will be a list of x509 certificate objects.
    '''
    # Set up a TLS Connection
    dst = (target_domain.encode('utf-8'), 443)
    ctx = SSL.Context(SSL.SSLv23_METHOD)
    s = socket.create_connection(dst)
    s = SSL.Connection(ctx, s)
    s.set_connect_state()
    s.set_tlsext_host_name(dst[0])

    # Send HTTP Req (initiates TLS Connection)
    s.sendall('HEAD / HTTP/1.0\n\n'.encode('utf-8'))
    s.recv(16)
    
    # Get Cert Meta Data from TLS connection
    test_site_certs = s.get_peer_cert_chain()
    s.close()
    return test_site_certs

############### Add Any Helper Functions Below

trusted_certs = pem.parse_file(TRUSTED_CERTS_PEM)

def load_trusted_root(store):
    for i in range(len(trusted_certs)):
        parsed_root = crypto.load_certificate(crypto.FILETYPE_PEM, trusted_certs[i].as_text())
        store.add_cert(parsed_root)
    return

def verify_chain(store, cert):
    store_ctx = crypto.X509StoreContext(store, cert)
    try:
        store_ctx.verify_certificate()
    except Exception:
        return False
    return True

# https://tinyurl.com/yapdrcef
def get_certificate_san(x509cert):
    all_san = ""
    ext_count = x509cert.get_extension_count()
    for i in range(0, ext_count):
        ext = x509cert.get_extension(i)
        if 'subjectAltName' in str(ext.get_short_name()):
            all_san = ext
    return all_san.__str__().split(', ')

##############################################

def x509_cert_chain_check(target_domain: str) -> bool:
    '''
    This function returns true if the target_domain provides a valid 
    x509cert and false in case it doesn't or if there's an error.
    '''
    # TODO: Complete Me!
    store = crypto.X509Store()
    valid = True
    # 1. load all trusted root into store
    load_trusted_root(store)

    # 2. load chain
    chain = get_cert_chain(target_domain)
    leaf = chain[0]
    chain = chain[1:]
    chain = chain[::-1]
    
    # verify chain
    for i in range(len(chain)):
        if verify_chain(store, chain[0]):
            store.add_cert(chain[i])
        else:
            return False
    
    # verify leaf's certification
    if verify_chain(store, leaf):
        store.add_cert(leaf)
    else:
        return False
    
    # verify leaf's domain name
    all_san = get_certificate_san(leaf)
    for i in range(len(all_san)):
        name = urllib.parse.urlparse(all_san[i])[2]
        if fnmatch.fnmatchcase(target_domain, name):
            if '.' not in target_domain[:-len(name) + 1]:
                return True
    
    return False


if __name__ == "__main__":
    
    # Standalone running to help you test your program
    print("Certificate Validator...")
    target_domain = input("Enter TLS site to validate: ")
    print("Certificate for {} verifed: {}".format(target_domain, x509_cert_chain_check(target_domain)))
