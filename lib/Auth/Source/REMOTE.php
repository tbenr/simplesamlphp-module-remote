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
	 * The key of the AuthId field in the state.
	 */
	const AUTH_GROUP = 'sspmod_remote_Auth_Source_REMOTE.AuthGroup';


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
	private $_raccrgToLoginMethods;

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

		if(isset($this->_remoteConfig['RACCRGtoLoginMethods'])){
			$this->_raccrgToLoginMethods =  $this->_remoteConfig['RACCRGtoLoginMethods'];
		}else{
			throw new Exception("RACCRGtoLoginMethods not specified");
		}

		if(isset($this->_remoteConfig['http_var_username'])){
			$this->_remoteUser =  $this->_remoteConfig['http_var_username'];
		}else{
			throw new Exception("http_var_username not specified");
		}

		if(isset($this->_remoteConfig['http_var_mapping'])){
			$this->_remoteUserAttrMap =  $this->_remoteConfig['http_var_mapping'];
		}else{
			throw new Exception("http_var_mapping not specified");
		}
	}


	/**
	 * This function extract user and attributes from passed HTTP header variables
	 *
	 * @return list username and attributes
	 */
	private function remoteValidation($headers){
		$user = $headers[$this->_remoteUser];

		if(!isset($user)) throw new Exception("cannot find user header variable");

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
	 * determine AuthnContextClassRefGroup fro a given AuthnContextClassRef
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

		// initialize urls (authentication urls associated to the RequestedAuthnContext Class Ref)
		$resolved_login_group = array();

		// loop on AuthnContextClassRef searching for matching classes
		foreach ($state['saml:RequestedAuthnContext']['AuthnContextClassRef'] as $authctx) {

			$grp = $this->getRACCRG($authctx);
			if(is_null($grp)) continue;

			$login_methods = $this->_raccrgToLoginMethods[$grp];
			if(isset($login_methods)) break;
		}

		// if no urls found, get them from default group
		if(!isset($login_methods)) {
			$login_methods = $this->_raccrgToLoginMethods['default'];
		}

		if($login_methods['session']) {
			$resolved_login_group['session'] = true;
		}
		else {
			$state['as:NoSession'] = true;
		}

		$resolved_login_group['auth_methods'] = array();

		// resolve module urls
		foreach($login_methods['auth_methods'] as $method) {
			$method['url'] = SimpleSAML_Module::getModuleURL($method['url']);

			array_push($resolved_login_group['auth_methods'],$method);
		}


		// save calculated urls in state
		$state[self::AUTH_GROUP] = $resolved_login_group;

		$stateID = SimpleSAML_Auth_State::saveState($state, self::STAGE_INIT);


		// redirect user to login
		\SimpleSAML\Utils\HTTP::redirectTrustedURL(SimpleSAML_Module::getModuleURL('remote/authstarter.php'), array('stateID' => $stateID));
	}

 public function reauthenticate(array &$state)
    {
		if(isset($state['remote:headers'])) {
			return parent::reauthenticate($state);
		}

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

}
