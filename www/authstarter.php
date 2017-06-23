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
$state = SimpleSAML_Auth_State::loadState($stateID, sspmod_remote_Auth_Source_REMOTE::STAGE_INIT);

$globalConfig = SimpleSAML_Configuration::getInstance();
$t = new SimpleSAML_XHTML_Template($globalConfig, 'remote:authstarter.php');

$t->data['auth_methods'] = $state[sspmod_remote_Auth_Source_REMOTE::AUTH_GROUP]['auth_methods'];
$t->data['stateid'] = $stateID;
$t->data['preferred'] = NULL; // TODO


$t->show();
exit();