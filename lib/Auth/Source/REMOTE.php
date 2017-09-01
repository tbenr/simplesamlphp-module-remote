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
	const STAGE = 'sspmod_remote_Auth_Source_REMOTE.stage';

	/**
	 * The key of the AuthId field in the state.
	 */
	const AUTHID = 'sspmod_remote_Auth_Source_REMOTE.AuthId';

	/**
	 * Selected Auth Group config in the state.
	 */
	const AUTH_GROUP = 'sspmod_remote_Auth_Source_REMOTE.AuthGroup';

	/**
	 * Selected Auth Group ID config in the state.
	 */
	const AUTH_GROUPID = 'sspmod_remote_Auth_Source_REMOTE.AuthGroupID';

	/**
	 * @var array with ldap configuration
	 */
	private $_ldapConfig;

	/**
	 * @var remote configuration
	 */
	private $_remoteConfig;

	/**
	 * @var http header variable where to get logged userid (ie. REMOTE_USER)
	 */
	private $_remoteUser;

	/**
	 * @var http header variable mapping for user attributes
	 */
	private $_remoteUserAttrMap;
	
	/**
	 * @var gropus of AuthnContextClassRef for RequestedAuthnContext
	 */
	private $_raccrg;

	/**
	 * @var mapping from RequestedAuthnContextClassRefGroup to array of authentication paths elegible for authenticate
	 */
	private $_authnGroupsConfig;

	/**
	 * @var error handler Parameter Name
	 */
	private $_errorHandler_parameterName;

	/**
	 * @var error handler mapping
	 */
	private $_errorHandler_mapping;

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

		if(isset($this->_remoteConfig['RequestedAuthnContextClassRefGroups'])){
			$this->_raccrg =  $this->_remoteConfig['RequestedAuthnContextClassRefGroups'];
		}else{
			throw new Exception("RequestedAuthnContextClassRefGroups not specified");
		}

		if(isset($this->_remoteConfig['AuthnGroupsConfig'])){
			$this->_authnGroupsConfig =  $this->_remoteConfig['AuthnGroupsConfig'];

			// convert relative path to absolute path based on the current module
			foreach($this->_authnGroupsConfig as &$grpconfig) {
				foreach($grpconfig['auth_methods'] as &$method) {
					$method['url'] = SimpleSAML_Module::getModuleURL($method['url']);
				}
			}

		}else{
			throw new Exception("AuthnGroupsConfig not specified");
		}

		if(isset($this->_remoteConfig['http_var_username'])){
			$this->_remoteUser = $this->_remoteConfig['http_var_username'];
		}else{
			throw new Exception("http_var_username not specified");
		}

		if(isset($this->_remoteConfig['errorhandler'])){
			$errorhandler = $this->_remoteConfig['errorhandler'];

			if(isset($errorhandler['parameterName'])) {
				$this->_errorHandler_parameterName = $errorhandler['parameterName'];
			} else {
				throw new Exception("errorhandler parameter name not specified");
			}

			if(isset($errorhandler['mapping'])) {
				$this->_errorHandler_mapping = $errorhandler['mapping'];
			} else {
				throw new Exception("errorhandler mapping not specified");
			}

			$this->_remoteUserAttrMap = $this->_remoteConfig['errorhandler'];
		}else{
			throw new Exception("errorhandler not specified");
		}

		if(isset($this->_remoteConfig['http_var_mapping'])){
			$this->_remoteUserAttrMap = $this->_remoteConfig['http_var_mapping'];
		}else{
			throw new Exception("http_var_mapping not specified");
		}
	}


	private static function endsWith($haystack, $needle)
	{
		$length = strlen($needle);
		if ($length == 0) {
			return true;
		}

		return (substr($haystack, -$length) === $needle);
	}

	/**
	 * This function validate the state by:
	 * verifing the state consistency
	 *
	 * @return list username and attributes
	 */
	private function remoteValidation($state, $headers, $callbackURI){

		// check that callback is compatible with the current authentication group.
		$authnGrp = $state[self::AUTH_GROUP];

		$found = false;
		foreach($authnGrp['auth_methods'] as $authmethod) {
			if (self::endsWith($authmethod['url'],$callbackURI)) {
				$found = true;
				break;
			}
		}

		if (!$found) {
			SimpleSAML_Auth_State::throwException($state,
    			new SimpleSAML_Error_Exception('Authentication callbackURI non corresponding to any of the Authn Method for the current AuthnGroup'));
		}

		$user = $headers[$this->_remoteUser];
		
		if(!isset($user)) {
			SimpleSAML_Auth_State::throwException($state,
    			new SimpleSAML_Error_Exception('Cannot find user header variable'));
		}

		$attrs = array();

		foreach($headers as $key => $value) {
			// check if current http header name is present in mapping
			if(isset($this->_remoteUserAttrMap[$key])) {
				// if yes, add it in attribute array
				$attrs[$this->_remoteUserAttrMap[$key]] = $value;
			}
		}

		return array($user,$attrs);
	}


	/**
	 * determine AuthnContextClassRefGroup for a given AuthnContextClassRef
	 *
	 * @return AuthnCtx group
	 */
	private function getRACCRG($authnctx){

		foreach($this->_raccrg as $group => $actxArray) {
			assert('is_array($actxArray)');
			if(in_array($authnctx,$actxArray)) return $group;
		}

		return null;
	}

	/**
	 * function performing final authentication step. Called from frontend
	 *
 	 * @param string $state authentication state.
	 * @param array &$headers HTTP headers from request
	 * @param string &$callbackURI callbackURI used to perform authentication
	 *
	 * @return list username, and attributes
	 */
	public function finalStep(&$state, &$headers, &$callbackURI) {

		//perform validation and obtain user info
		list($username, $remoteattributes) = $this->remoteValidation($state, $headers, $callbackURI);

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

		// loop on AuthnContextClassRef searching for matching classes
		foreach ($state['saml:RequestedAuthnContext']['AuthnContextClassRef'] as $authctx) {

			$selectedRACCR = $authctx;

			$selectedGroupID = $this->getRACCRG($authctx);
			if(is_null($selectedGroupID)) continue;

			$selectedGroup = $this->_authnGroupsConfig[$selectedGroupID];
			if(isset($selectedGroup)) break;
		}

		// if no urls found, get them from default group
		if (!isset($selectedGroup)) {
			$selectedGroup = $this->_authnGroupsConfig['default'];
		}

		// check if selected group should throw an error
		if (array_key_exists('error',$selectedGroup)) {
			$error = $selectedGroup['error'];
			if(is_array($error)) {
				throw new sspmod_saml_Error($error['status'], $error['subStatus'], $error['statusMessage']);
			} else {
				throw new SimpleSAML_Error_Exception($error);
			}
			
		}

		// determine returned AuthnContext
		if (array_key_exists('AuthnContextClassRef', $selectedGroup)) {
			$state['saml:AuthnContextClassRef'] = $selectedGroup['AuthnContextClassRef'];
		} else {
			$state['saml:AuthnContextClassRef'] = $selectedRACCR;
		}

		// save group and groupID in state
		$state[self::AUTH_GROUP] = $selectedGroup;
		$state[self::AUTH_GROUPID] = $selectedGroupID;

		$stateID = SimpleSAML_Auth_State::saveState($state, self::STAGE);

		self::setStateInCookie($stateID);

		// redirect user to login
		\SimpleSAML\Utils\HTTP::redirectTrustedURL(SimpleSAML_Module::getModuleURL('remote/authstarter.php'), array('stateID' => $stateID));
	}

 public function reauthenticate(array &$state)
    {
		// always reauthenticate => we want to always go through secure reverse proxy to get HTTP headers
		$state['as:Reauth'] = true;
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

	/**
	* Set the previous authentication method per current group.
	*
	* This method remembers, for a given group, the authentication method the user selected
	* by storing its name in a cookie.
	*
	* @param string $method the user selected.
	* @param string $group id of the method the user selected.
	*/
	public function setPreviousAuth($method, $group) {
		assert('is_string($method)');
		assert('is_string($group)');

		$cookieName = 'remote_method_' . $this->authId . '_' . $group;

		$config = SimpleSAML_Configuration::getInstance();
		$params = array(
			/* We save the cookies for 90 days. */
			'lifetime' => (60*60*24*90),
			/* The base path for cookies.
			This should be the installation directory for SimpleSAMLphp. */
			'path' => $config->getBasePath(),
			'httponly' => FALSE,
		);

        \SimpleSAML\Utils\HTTP::setCookie($cookieName, $method, $params, FALSE);
	}

	/**
	* Get the previous authentication method for a given group.
	*
	* This method retrieves the authentication method that the user selected
	* last time for the same authn group, or NULL if this is the first time or remembering is disabled.
	*/
	public function getPreviousAuth($group) {
		assert('is_string($group)');

		$cookieName = 'remote_method_' . $this->authId . '_' . $group;
		if(array_key_exists($cookieName, $_COOKIE)) {
			return $_COOKIE[$cookieName];
		} else {
			return NULL;
		}
	}


	/**
	* Save current stateID in cookie, to manage get resume state when authentication methods return error to error handler
	*
	*
	* @param string $stateID current auth state.
	*/
	public static function setStateInCookie($stateID) {
		assert('is_string($state)');

		$cookieName = 'remote_method_state';

		$config = SimpleSAML_Configuration::getInstance();
		$params = array(
			/* The base path for cookies.
			This should be the installation directory for SimpleSAMLphp. */
			'path' => $config->getBasePath(), // . 'module.php/remote',
			'httponly' => TRUE,
			//'secure' => TRUE,
		);

        \SimpleSAML\Utils\HTTP::setCookie($cookieName, $stateID, $params, FALSE);
	}


	/**
	* get current stateID from cookie, to manage get resume state when authentication methods return error to error handler
	*
	*/
	public static function getStateFromCookie() {
		assert('is_string($state)');

		$cookieName = 'remote_method_state';

		if(array_key_exists($cookieName, $_COOKIE)) {
			return $_COOKIE[$cookieName];
		} else {
			return NULL;
		}
	}


	public function handleError(&$state) {

		$errorKey = $_GET[$this->_errorHandler_parameterName];

		if(isset($errorKey)) {

			$error = $this->_errorHandler_mapping[$errorKey];

			if(isset($error)) {
				SimpleSAML_Auth_State::throwException($state,
    				new sspmod_saml_Error($error['status'], $error['subStatus'], $error['statusMessage']));
			}
		}
    	
		throw new Exception("Unhandled error parameter");
	}

}