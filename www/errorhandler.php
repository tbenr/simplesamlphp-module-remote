<?php

$stateID = sspmod_remote_Auth_Source_REMOTE::getStateFromCookie();

if (is_null($stateID)) {
	throw new SimpleSAML_Error_BadRequest('Missing stateID cookie.');
}

/**
* check if we need to exit iframe
* folowing javascript will reload the page even if we are not in an iframe.
*/
if (!isset($_GET['uniframed'])) {
?>
<script type="text/javascript">
    window.top.location.href = window.location.href + '&uniframed=yes'; 
</script>
...please wait...
<?php
	exit;
}

/**
 * now we are on the top window, proceed with authentication
 */

$state = SimpleSAML_Auth_State::loadState($stateID, sspmod_remote_Auth_Source_REMOTE::STAGE);
$sourceId = $state[sspmod_remote_Auth_Source_REMOTE::AUTHID];
$source = SimpleSAML_Auth_Source::getById($sourceId);

$source->handleError($state);