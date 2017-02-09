authX509toSAML
==============

The authX509toSAML module provides X509 authentication and attribute translation from certifate
attributes to SAML attributes.

Using the authX509toSAML authentication source with SimpleSAMLphp
==================================================================



Configuring Apache
------------------

This module assumes that the server requests a client certificate, and
stores it in the environment variable SSL_CLIENT_CERT. This can be achieved
with such a configuration:

    SSLEngine on
    # Configure the Server part of TLS
    SSLCertificateFile /etc/openssl/certs/server.crt
    SSLCertificateKeyFile /etc/openssl/private/server.key
    SSLCACertificateFile /etc/openssl/certs/ca.crt
    # Configure Client certificate authentication
    SSLVerifyClient require
    SSLVerifyDepth 1
    # Configure which CAs the server will trust for signing client certificates
    SSLCACertificatePath "/usr/share/igtf-policy/classic"
    SSLOptions +ExportCertData

Note that SSLVerifyClient can be set to optional if you want to support
both certificate and plain login authentication. Alternatively SSLVerifyClient can be
set explicitly on 
    <Location "/simplesaml/saml2/idp/SSOService.php">


Install authX509toSAML module
---------------------------------

   git clone https://github.com/jkakavas/authX509toSAML.git
   cp -r authX509toSAML /var/simplesamlphp/modules/


Setting up the authX509toSAML module
--------------------------------------

The first thing you need to do is to enable the module:

    touch /var/simplesamlphp/modules/authX509toSAML/enable

Then you must add it as an authentication source in /var/simplesamlphp/config/authsources.php . Here is an
example authsources.php entry:

    'x509' => array(
        'authX509toSAML:X509userCert',
        'authX509toSAML:cert_name_attribute': 'CN',
        'authX509toSAML:assertion_name_attribute': 'displayName',
        'authX509toSAML:assertion_dn_attribute': 'distinguishedName',
        'authX509toSAML:assetion_assurance_attribute': 'eduPersonAssurance',
        'authX509toSAML:parse_san_emails': TRUE
        'authX509toSAML:parse_policy': TRUE,
        'authX509toSAML:export_eppn': FALSE,
    ),

The configuration options are as following

* cert_name_attribute            is the name of the attribute in the certificate 
                                 where the name of the certificate subject is to be found
* assertion_name_attribute       is the attribute in the SAML assertion that the name
                                 of the certificate subject will be mapped to
* assertion_dn_attribute         is the attribute in the SAML assertion where the DN of the
                                 certificate subject will be mapped to
* assertion_dn_attribute         is the attribute in the SAML assertion where the certificatePolicy 
                                 attribute of the certificate will be mapped to
* parse_san_emails               controls whether the module will attempt to parse Subject Alternate
                                 Names to find possible email addresses for the certificate subject
* parse_policy                   controls whether the module will attempt to parse Certificate Policy
* export_eppn                    controls whether the module will attempt to parse an eduPersonPrincipalName
                                 value from the certificate subject value (i.e. for Grid Robot certificates)

All the above parameters are optional, since the code contains sane defaults for all of them (the values shown in the example above)
