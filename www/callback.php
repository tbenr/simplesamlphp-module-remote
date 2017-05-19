<?php

/**
 * Handle linkback() response from CAS.
 */

if (!isset($_GET['stateID'])) {
	throw new SimpleSAML_Error_BadRequest('Missing stateID parameter.');
}
$state = SimpleSAML_Auth_State::loadState($_GET['stateID'], sspmod_remote_Auth_Source_REMOTE::STAGE_INIT);

$state['remote:headers'] = getallheaders();


// Find authentication source
assert('array_key_exists(sspmod_remote_Auth_Source_REMOTE::AUTHID, $state)');
$sourceId = $state[sspmod_remote_Auth_Source_REMOTE::AUTHID];

$source = SimpleSAML_Auth_Source::getById($sourceId);
if ($source === NULL) {
	throw new Exception('Could not find authentication source with id ' . $sourceId);
}

$source->finalStep($state);


