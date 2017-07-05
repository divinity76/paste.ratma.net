<?php
declare(strict_types = 1);
require_once (__DIR__ . '/../config.inc.php');
// if (empty ( $_SESSION ['csrf_token'] )) {
// $_SESSION ['csrf_token'] = base64_encode ( random_bytes ( 14 ) );
// }
if (! empty ( $_POST )) {
	// if (! hash_equals ( $_SESSION ['csrf_token'], $_POST ['csrf_token'] ?? '')) {
	// http_response_code ( 400 );
	// die ( 'Error: CSRF token mismatch!' );
	// }
	if (empty ( $_POST ['g-recaptcha-response'] )) {
		http_response_code ( 400 );
		die ( 'you did not solve the captcha!' );
	}
	$required = array (
			'g-recaptcha-response',
			'username',
			'password' 
	);
	foreach ( $required as $tmp ) {
		if (empty ( $_POST [$tmp] )) {
			http_response_code ( 400 );
			header ( "content-type: text/plain;charset=utf8" );
			die ( 'missing required POST parameter: ' . $tmp );
		}
		$_POST [$tmp] = ( string ) $_POST [$tmp];
	}
	function validate_new_username(string $username, string &$error = NULL): bool {
		if ($username !== ltrim ( $username )) {
			$error = "starts with space(s)!";
			return false;
		}
		if ($username !== rtrim ( $username )) {
			$error = "ends with space(s)!";
			return false;
		}
		if (! mb_check_encoding ( $username, 'UTF-8' )) {
			$error = 'not valid UTF8!';
			return false;
		}
		if (preg_match ( '/[\ ]{2,}/u', $username )) {
			$error = 'contains repeating spaces!';
			return false;
		}
		if (! preg_match ( '/^[[:alnum:]\ \-\_]+$/u', $username )) {
			$error = 'contains invalid characters!';
			return false;
		}
		$mblen = mb_strlen ( $username, 'UTF-8' );
		if ($mblen < 3) {
			$error = 'username too short, must be at least 3 characters.';
			return false;
		}
		if ($mblen > 20) {
			$error = 'username long. can be no longer than 20 characters.';
			return false;
		}
		$error = '';
		return true;
	}
	$username = ( string ) $_POST ['username'];
	$error = NULL;
	if (! validate_new_username ( $username, $error )) {
		http_response_code ( 400 );
		header ( "content-type: text/plain;charset=utf8" );
		die ( 'invalid username. error: ' . $error );
	}
	if (! mb_check_encoding ( $_POST ['username'], 'UTF-8' )) {
		http_response_code ( 400 );
		header ( "content-type: text/plain;charset=utf8" );
		die ( 'username MUST be valid utf-8!' );
	}
	class RecaptchaResponse {
		public $success = false;
		public $challenge_ts = "yyyy-MM-dd'T'HH:mm:ssZZ";
		public $hostname = 'ratma.net';
		public $error_codes = array ();
	}
	require_once ('hhb_.inc.php');
	require_once (__DIR__ . DIRECTORY_SEPARATOR . 'api1' . DIRECTORY_SEPARATOR . 'api_common.inc.php');
	$resp = json_decode ( (new hhb_curl ( 'https://www.google.com/recaptcha/api/siteverify', true ))->setopt_array ( array (
			CURLOPT_POST => true,
			CURLOPT_POSTFIELDS => array (
					'secret' => RecaptchaConfig::SECRET_KEY,
					'response' => $_POST ['g-recaptcha-response'],
					'remoteip' => $_SERVER ['REMOTE_ADDR'] 
			) 
	) )->exec ()->getResponseBody (), false );
	/** @var RecaptchaResponse $resp */
	if (! $resp->success) {
		http_response_code ( 400 );
		die ( 'the captcha was not solved!' );
	}
	// all validations are now complete (except duplicate username)
	$data = array (
			':api_token' => base64url_encode ( random_bytes ( 14 ) ),
			':username' => $_POST ['username'],
			':password_hash' => p_hash ( $_POST ['password'] ) 
	);
	$stm = $db->prepare ( 'INSERT INTO `users` 
(username,password_hash,password_hash_version,api_token,register_date) VALUES
 (:username,:password_hash,1,:api_token,NOW())' );
	try {
		$stm->execute ( $data );
	} catch ( Throwable $ex ) {
		http_response_code ( 400 );
		header ( "content-type: text/plain;charset=utf8" );
		echo "some SQL error while creating your account. details:";
		echo $ex->getMessage ();
		die ();
	}
	// http_response_code ( 303 );
	// header ( "Location: " . $_SERVER ['REQUEST_URI'] );
	http_response_code ( 200 );
	header ( "content-type: text/plain;charset=utf8" );
	echo "account successfully created... \n username: " . $username . " \n api token: " . $data [':api_token'];
	die ();
}

?>
<!DOCTYPE HTML>
<html>
<head>
<title>register</title>
<script src='https://www.google.com/recaptcha/api.js'></script>
</head>
<body>
	<form method="POST">
		username: <input name="username" type="text" maxlength="40" /><br />
		password: <input name="password" type="password" /><br /> <input
			type="submit" />
		<div class="g-recaptcha"
			data-sitekey="<?=RecaptchaConfig::SITE_KEY;?>"></div>
	</form>
	<div id="rules">
		rules for username: minimum 3, and a maximum of 20, combination of
		alphanumeric UTF-8 characers and "-" and "_" and spaces. username can
		not start with, nor end with spaces, and cannot contain repeating spaces. <br />
		rules for password: minimum 1 character. (but dont blame me for
		getting hacked if you use a weak password.. or for any reason, really)
	</div>
</body>
</html>
