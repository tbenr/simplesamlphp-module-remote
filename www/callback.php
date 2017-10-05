<?php
/* support for nginx\fpm */
if (!function_exists('getallheaders')) 
{ 
    function getallheaders() 
    { 
		$headers = []; 
		foreach ($_SERVER as $name => $value) 
		{ 
			if (substr($name, 0, 5) == 'HTTP_') 
			{ 
				$headers[substr($name, 5)] = $value;
			} 
		} 
		return $headers; 
    } 
} 

/**
 * receive HTTP Headers from request and call authentication finalStep
 */

if (!isset($_GET['stateID'])) {
	throw new SimpleSAML_Error_BadRequest('Missing stateID parameter.');
}

$finish_target = SimpleSAML_Module::getModuleURL('remote/finish.php');

$finish_target_parsed = parse_url($finish_target);
$message_dest_origin = $finish_target_parsed['scheme'] . '://' . $finish_target_parsed['host'];


$state = SimpleSAML_Auth_State::loadState($_GET['stateID'], sspmod_remote_Auth_Source_REMOTE::STAGE);
if(array_key_exists(sspmod_remote_Auth_Source_REMOTE::AUTH_DONE,$state)) {
?>
...an authentication process is already running...
<?php
	exit;
}

$state[sspmod_remote_Auth_Source_REMOTE::AUTH_DONE] = TRUE;


$headers = getallheaders();
$uri_parts = explode('?', $_SERVER['REQUEST_URI'], 2);
$callbackURI = $uri_parts[0];
$callbackQS = $uri_parts[1];

// Find authentication source
assert('array_key_exists(sspmod_remote_Auth_Source_REMOTE::AUTHID, $state)');
$sourceId = $state[sspmod_remote_Auth_Source_REMOTE::AUTHID];

$source = SimpleSAML_Auth_Source::getById($sourceId);
if ($source === NULL) {
	throw new Exception('Could not find authentication source with id ' . $sourceId);
}

$stateID = $source->callbackStep($state, $headers, $callbackURI);

/**
* folowing javascript will redirect to final page exiting from iframe if needed.
*/
?>
<script type="text/javascript">
	if(window.self !== window.top) {
		parent.postMessage('<?php echo $finish_target . '?' . $callbackQS; ?>','<?php echo $message_dest_origin; ?>');
	}
	else {
		window.location.href = '<?php echo $finish_target . '?' . $callbackQS; ?>';
	}
</script>
...please wait...
	
