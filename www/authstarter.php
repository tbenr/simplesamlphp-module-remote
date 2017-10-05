<?php
/**
 * This page instantiate multiple authentication url calculated
 * by sspmod_remote_Auth_Source_REMOTE class
 *
 * @author Enrico Del Fante
 * @package SimpleSAMLphp
 */

 // Retrieve the authentication state
if (!array_key_exists('stateID', $_REQUEST)) {
	throw new SimpleSAML_Error_BadRequest('Missing stateID parameter.');
}
$stateID = $_REQUEST['stateID'];
$state = SimpleSAML_Auth_State::loadState($stateID, sspmod_remote_Auth_Source_REMOTE::STAGE);

$globalConfig = SimpleSAML_Configuration::getInstance();
$t = new SimpleSAML_XHTML_Template($globalConfig, 'remote:authstarter.php');

$t->data['auth_group'] = $state[sspmod_remote_Auth_Source_REMOTE::AUTH_GROUP];
$t->data['auth_groupid'] = $state[sspmod_remote_Auth_Source_REMOTE::AUTH_GROUPID];
$t->data['stateid'] = $stateID;

assert('array_key_exists(sspmod_remote_Auth_Source_REMOTE::AUTHID, $state)');
$sourceId = $state[sspmod_remote_Auth_Source_REMOTE::AUTHID];

$as = SimpleSAML_Auth_Source::getById($sourceId);

if ($as !== NULL) {
	$t->data['preferred'] = $as->getPreviousAuth( $state[sspmod_remote_Auth_Source_REMOTE::AUTH_GROUPID] );
} else {
	$t->data['preferred'] = -1;
}


$t->show();
exit();