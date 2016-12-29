<?php

/**
 * This class implements x509 certificate authentication in essence 
 * translating the x509 certificate to a SAML Assertion
 *
 * @author Ioannis Kakavas <ikakavas@noc.grnet.gr>
 * @package SimpleSAMLphp
 */
class sspmod_X509toSAML_Auth_Source_X509userCert extends SimpleSAML_Auth_Source {


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
            'X509toSAML:X509error.php');
        $t->data['errorcode'] = $state['X509toSAML.error'];

        $t->show();
        exit();
    }


    /**
     * Validate certificate and login
     *
     * This function try to validate the certificate.
     * On success, the user is logged in without going through
     * o login page.
     * On failure, The X509toSAML:X509error.php template is
     * loaded.
     *
     * @param array &$state  Information about the current authentication.
     */
    public function authenticate(&$state) {
        assert('is_array($state)');

        if (!isset($_SERVER['SSL_CLIENT_CERT']) ||
            ($_SERVER['SSL_CLIENT_CERT'] == '')) {
            $state['X509toSAML.error'] = "NOCERT";
            $this->authFailed($state);
            assert('FALSE'); // NOTREACHED
            return;
        }

        $client_cert = $_SERVER['SSL_CLIENT_CERT'];
        $client_cert_data = openssl_x509_parse($client_cert);
        if ($client_cert_data == FALSE) {
            SimpleSAML_Logger::error('X509toSAML: invalid cert');
            $state['X509toSAML.error'] = "INVALIDCERT";
            $this->authFailed($state);

            assert('FALSE'); // NOTREACHED
            return;
        }
        
        $attributes = array();
        /**
         * Load values from configuration or fallback to defaults
         *
         */
        if (!array_key_exists('cert_name_attribute', $config)){
            $cert_name_attribute = 'CN';
        } else {
            $cert_name_attribute = $config['cert_name_attribute'];
        }
        if (!array_key_exists('assertion_name_attribute', $config)){
            $assertion_name_attribute = 'displayName';
        } else {
            $assertion_name_attribute = $config['assertion_name_attribute'];
        }


        if (array_key_exists($cert_name_attribute, $client_cert_data['subject'])){
            $attributes[$assertion_name_attribute] = array($client_cert_data['subject'][$cert_name_attribute]);
        }
        if (array_key_exists('name', $client_cert_data)){
            $attributes['distinguishedName'] = array($client_cert_data['name']);
            $state['UserID'] = $client_cert_data['name'];
        }
        if (array_key_exists('subjectAltName', $client_cert_data['extensions'])){
            if (is_string($client_cert_data['extensions']['subjectAltName']) && substr( $client_cert_data['extensions']['subjectAltName'], 0, 6 ) === "email:"){
                $attributes['mail'] = array(str_replace('email:','',$client_cert_data['extensions']['subjectAltName']));
            } 
            else if (is_array($client_cert_data['extensions']['subjectAltName'])){
                foreach ($client_cert_data['extensions']['subjectAltName'] as $subjectAltName){
                    if (substr( $subjectAltName, 0, 6 ) === "email:"){
                        $attributes['mail'] = array(str_replace('email:','',$subjectAltName)); 
                    }
                }
            }
        }
        if (!empty($client_cert_data['extensions']['certificatePolicies']) && is_string($client_cert_data['extensions']['certificatePolicies'])) {
            SimpleSAML_Logger::debug("client_cert_data['extensions']['certificatePolicies']=" . var_export($client_cert_data['extensions']['certificatePolicies'], true));
            $attributes['eduPersonAssurance'] = array();
            if (preg_match_all('/Policy: ([\d\.\d]+)/', $client_cert_data['extensions']['certificatePolicies'], $matches)) {
                if (count($matches)>1){
                    foreach ($matches[1] as $policy){
                        $attributes['eduPersonAssurance'][] = $policy;
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
