<?php

/**
 * Authenticate using Remote User.
 *
 *
 * @author Enrico Del Fante, CA
 * @package SimpleSAMLphp
 */
class sspmod_remote_Auth_Source_REMOTE  extends SimpleSAML_Auth_Source  {

	/**
	 * The string used to identify our states.
	 */
	const STAGE_INIT = 'sspmod_remote_Auth_Source_REMOTE.state';

	/**
	 * The key of the AuthId field in the state.
	 */
	const AUTHID = 'sspmod_remote_Auth_Source_REMOTE.AuthId';


	/**
	 * @var array with ldap configuration
	 */
	private $_ldapConfig;

	/**
	 * @var remote configuration
	 */
	private $_remoteConfig;

	/**
	 * @var remote chosen validation method
	 */
	private $_validationMethod;
	/**
	 * @var remote login method
	 */
	private $_loginMethodMapping;

	private $_remoteUser;
	private $_remoteUserAttrPrefix;
	


	/**
	 * Constructor for this authentication source.
	 *
	 * @param array $info  Information about this authentication source.
	 * @param array $config  Configuration.
	 */
	public function __construct($info, $config) {
		assert('is_array($info)');
		assert('is_array($config)');

		// Call the parent constructor first, as required by the interface
		parent::__construct($info, $config);

		if (!array_key_exists('remote', $config)){
			throw new Exception('remote authentication source is not properly configured: missing [remote]');
		}


		if (!array_key_exists('ldap', $config)){
			throw new Exception('ldap authentication source is not properly configured: missing [ldap]');
		}

		$this->_remoteConfig = $config['remote'];
		$this->_ldapConfig = $config['ldap'];

		if(isset($this->_remoteConfig['authnctxcf'])){
			$this->_loginMethodMapping =  $this->_remoteConfig['authnctxcf'];
		}else{
			throw new Exception("remote login URL not specified");
		}

		if(isset($this->_remoteConfig['var_username'])){
			$this->_remoteUser =  $this->_remoteConfig['var_username'];
		}else{
			throw new Exception("var_username not specified");
		}

		if(isset($this->_remoteConfig['var_userattr_prefix'])){
			$this->_remoteUserAttrPrefix =  $this->_remoteConfig['var_userattr_prefix'];
		}else{
			throw new Exception("var_userattr_prefix not specified");
		}
	}


	/**
	 * This the most simple version of validating, this provides only authentication validation
	 *
	 * @return list username and attributes
	 */
	private function remoteValidation($headers){
		$user = $headers[$this->_remoteUser];

		$attrs = array();

		foreach($headers as $key => $value) {
			if(substr($key, 0, strlen($this->_remoteUserAttrPrefix)) === $this->_remoteUserAttrPrefix) {
				$attr = substr($key,strlen($this->_remoteUserAttrPrefix));

				$attrs[$attr] = $value;
			}
		}

		return array($user,$attrs);
	}




	/**
	 * Called by linkback, to finish validate/ finish logging in.
	 * @param state $state
	 * @return list username, and attributes
	 */
	public function finalStep(&$state) {


		$stateID = SimpleSAML_Auth_State::saveState($state, self::STAGE_INIT);
		$service =  SimpleSAML_Module::getModuleURL('remote/callback.php', array('stateID' => $stateID));

		list($username, $remoteattributes) = $this->remoteValidation($state['remote:headers']);
		$ldapattributes = array();
		if (isset($this->_ldapConfig['servers'])) {
			$ldap = new SimpleSAML_Auth_LDAP($this->_ldapConfig['servers'], $this->_ldapConfig['enable_tls']);
			$ldapattributes = $ldap->validate($this->_ldapConfig, $username);
		}
		$attributes = array_merge_recursive($remoteattributes, $ldapattributes);
		
		// Parse attributes
		try {
			$attributes = SimpleSAML\Utils\Attributes::normalizeAttributesArray($attributes);
		} catch(Exception $e) {
			throw new Exception('Invalid attributes for authentication source ' .
				AUTHID . ': ' . $e->getMessage());
		}

		$state['Attributes'] = $attributes;

		SimpleSAML_Auth_Source::completeAuth($state);
	}


	/**
	 * Log-in using remote
	 *
	 * @param array &$state  Information about the current authentication.
	 */
	public function authenticate(&$state) {
		assert('is_array($state)');

		// We are going to need the authId in order to retrieve this authentication source later
		$state[self::AUTHID] = $this->authId;

		$stateID = SimpleSAML_Auth_State::saveState($state, self::STAGE_INIT);



		$serviceUrl = SimpleSAML_Module::getModuleURL('remote/callback.php');

		$resolved_login_url = null;

		foreach ($state['saml:RequestedAuthnContext']['AuthnContextClassRef'] as $authctx) {
			
			$resolved_login_url=$this->_loginMethodMapping[$authctx];
			if(isset($resolved_login_url)) break;
			
		}

		if(!isset($resolved_login_url)) {
			$resolved_login_url = $this->_loginMethodMapping['default'];
		}


		\SimpleSAML\Utils\HTTP::redirectTrustedURL($resolved_login_url, array('stateID' => $stateID));
	}


	/**
	 * Log out from this authentication source.
	 *
	 * This function should be overridden if the authentication source requires special
	 * steps to complete a logout operation.
	 *
	 * If the logout process requires a redirect, the state should be saved. Once the
	 * logout operation is completed, the state should be restored, and completeLogout
	 * should be called with the state. If this operation can be completed without
	 * showing the user a page, or redirecting, this function should return.
	 *
	 * @param array &$state  Information about the current logout operation.
	 */
	public function logout(&$state) {
		assert('is_array($state)');
		$logoutUrl = $this->_remoteConfig['logout'];

		SimpleSAML_Auth_State::deleteState($state);
		// we want remote to log us out
		\SimpleSAML\Utils\HTTP::redirectTrustedURL($logoutUrl);
	}

}
