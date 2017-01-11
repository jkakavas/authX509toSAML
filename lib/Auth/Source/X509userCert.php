<?php

/**
 * This class implements x509 certificate authentication in essence 
 * translating the x509 certificate to a SAML Assertion
 *
 * @author Ioannis Kakavas <ikakavas@noc.grnet.gr>
 */
class sspmod_authX509toSAML_Auth_Source_X509userCert extends SimpleSAML_Auth_Source {

    private $config;
    /**
     * Constructor for this authentication source.
     *
     * All subclasses who implement their own constructor must call this
     * constructor before using $config for anything.
     *
     * @param array $info  Information about this authentication source.
     * @param array &$config  Configuration for this authentication source.
     */
    public function __construct($info, &$config) {
        assert('is_array($info)');
        assert('is_array($config)');
        parent::__construct($info, $config);
        $this->config = $config;
        return;
    }
    /**
     * Finish a failed authentication.
     *
     * This function can be overloaded by a child authentication
     * class that wish to perform some operations on failure
     *
     * @param array &$state  Information about the current authentication.
     */
    public function authFailed(&$state) {
        $config = SimpleSAML_Configuration::getInstance();

        $t = new SimpleSAML_XHTML_Template($config,
            'authX509toSAML:X509error.php');
        $t->data['errorcode'] = $state['authX509toSAML.error'];

        $t->show();
        exit();
    }


    /**
     * 
     *
     * The client ssl authentication is already performed in Apache. This method 
     * maps the necessary attributes from the certificate to SAML attributes for
     * the Attribute Statement of the SAML Assertion.
     * .
     * On success, the user is logged in without going through the login page.
     * On failure, The authX509toSAML:X509error.php template is
     * loaded.
     *
     * @param array &$state  Information about the current authentication.
     */
    public function authenticate(&$state) {
        assert('is_array($state)');

        if (!isset($_SERVER['SSL_CLIENT_CERT']) ||
            ($_SERVER['SSL_CLIENT_CERT'] == '')) {
            $state['authX509toSAML.error'] = "NOCERT";
            $this->authFailed($state);
            assert('FALSE'); // NOTREACHED
            return;
        }

        $client_cert = $_SERVER['SSL_CLIENT_CERT'];
        $client_cert_data = openssl_x509_parse($client_cert);
        if ($client_cert_data == FALSE) {
            SimpleSAML_Logger::error('authX509toSAML: invalid cert');
            $state['authX509toSAML.error'] = "INVALIDCERT";
            $this->authFailed($state);

            assert('FALSE'); // NOTREACHED
            return;
        }
        
        $attributes = array();
        /**
         * Load values from configuration or fallback to defaults
         *
         */
        if (!array_key_exists('authX509toSAML:cert_name_attribute', $this->config)){
            $cert_name_attribute = 'CN';
        } else {
            $cert_name_attribute = $this->config['authX509toSAML:cert_name_attribute'];
        }
        if (!array_key_exists('authX509toSAML:assertion_name_attribute', $this->config)){
            $assertion_name_attribute = 'displayName';
        } else {
            $assertion_name_attribute = $this->config['authX509toSAML:assertion_name_attribute'];
        }
        if (!array_key_exists('authX509toSAML:assertion_dn_attribute', $this->config)){
            $assertion_dn_attribute = 'distinguishedName';
        } else {
            $assertion_dn_attribute = $this->config['authX509toSAML:assertion_dn_attribute'];
        }
        if (!array_key_exists('authX509toSAML:assetion_assurance_attribute', $this->config)){
            $assertion_assurance_attribute = 'eduPersonAssurance';
        } else {
            $assertion_assurance_attribute = $this->config['authX509toSAML:assertion_assurance_attribute'];
        }
        if (!array_key_exists('authX509toSAML:parse_san_emails', $this->config)){
            $parse_san_emails = true;
        } else {
            $parse_san_emails = $this->config['authX509toSAML:parse_san_emails'];
        }
        if (!array_key_exists('authX509toSAML:parse_policy', $this->config)){
            $parse_policy = true;
        } else {
            $parse_policy = $this->config['authX509toSAML:parse_policy'];
        }

        // Get the subject of the certificate
        if (array_key_exists('name', $client_cert_data)){
            $attributes[$assertion_dn_attribute] = array($client_cert_data['name']);
            $state['UserID'] = $client_cert_data['name'];
        }

        if (array_key_exists($cert_name_attribute, $client_cert_data['subject'])){
            if (array_key_exists('authX509toSAML:export_eppn', $this->config) && $this->config['authX509toSAML:export_eppn'] == true){
                $name_tokens = explode(" ", $client_cert_data['subject'][$cert_name_attribute]);
                $eppn = '';
                foreach ($name_tokens as $token){
                    if (strpos($token, '@') !== false){
                        $attributes['eduPersonPrincipalName'] = array($token);
                        $eppn = $token;
                        break;
                    }
                }
                // Now remove the eppn from the $assertion_name_attribute
                $attributes[$assertion_name_attribute] = array(str_replace($eppn,'',$client_cert_data['subject'][$cert_name_attribute]));
            } else {
                $attributes[$assertion_name_attribute] = array($client_cert_data['subject'][$cert_name_attribute]);
            }
        }
        // Attempt to parse Subject Alternate Names for email addresses
        if ($parse_san_emails){
            $attributes['mail'] = array();
            if (array_key_exists('subjectAltName', $client_cert_data['extensions'])){
                if (is_string($client_cert_data['extensions']['subjectAltName']) && substr( $client_cert_data['extensions']['subjectAltName'], 0, 6 ) === "email:"){
                    $attributes['mail'][] = str_replace('email:','',$client_cert_data['extensions']['subjectAltName']);
                } 
                else if (is_array($client_cert_data['extensions']['subjectAltName'])){
                    foreach ($client_cert_data['extensions']['subjectAltName'] as $subjectAltName){
                        if (substr( $subjectAltName, 0, 6 ) === "email:"){
                            $attributes['mail'][] = str_replace('email:','',$subjectAltName);
                        }
                    }
                }
            }
        }
        // Attempt to parse certificatePolicies extensions
        if($parse_policy){
            if (!empty($client_cert_data['extensions']['certificatePolicies']) && is_string($client_cert_data['extensions']['certificatePolicies'])) {
                $attributes[$assertion_assurance_attribute] = array();
                if (preg_match_all('/Policy: ([\d\.\d]+)/', $client_cert_data['extensions']['certificatePolicies'], $matches)) {
                    if (count($matches)>1){
                        foreach ($matches[1] as $policy){
                            $attributes[$assertion_assurance_attribute] = $policy;
                        }
                    }
                }
            }
        }

        assert('is_array($attributes)');
        $state['Attributes'] = $attributes;
        $this->authSuccesful($state);   
        assert('FALSE'); /* NOTEREACHED */
        return;
    }


    /**
     * Finish a succesfull authentication.
     *
     * This function can be overloaded by a child authentication
     * class that wish to perform some operations after login.
     *
     * @param array &$state  Information about the current authentication.
     */
    public function authSuccesful(&$state) {
        SimpleSAML_Auth_Source::completeAuth($state);

        assert('FALSE'); /* NOTREACHED */
        return;
    }

}
