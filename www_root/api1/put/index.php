<?php
declare(strict_types = 1);
require_once (__DIR__ . '/../api_common.inc.php');
$resp = new Response ();
header ( "content-type: application/json" );
register_shutdown_function ( function () use (&$resp) {
	$resp = ( array ) $resp;
	foreach ( $resp as $key => $val ) {
		if (empty ( $val )) {
			unset ( $resp [$key] );
		}
	}
	if (empty ( $resp ['status_code'] )) {
		$resp ['status_code'] = 0;
	}
	echo json_encode ( $resp, JSON_NUMERIC_CHECK | JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES );
} );
$user_id = filter_var ( ($_POST ['user_id'] ?? 1), FILTER_VALIDATE_INT );
if (false === $user_id) {
	err ( 'invalid user_id supplied!' );
}
if ($user_id === 1) {
	// ANONYMOUS_UPLOADS_NEEDS_NO_TOKEN
} else {
	if (! validate_api_token ( $user_id, ( string ) ($_POST ['api_token'] ?? '') )) {
		// TODO: check, is mysql here vulnerable to a timing attack?
		err ( 'invalid api token for that user!' );
	}
}
$c = 0;
if (! empty ( $_FILES )) {
	$c += count ( $_FILES );
}
if (isset ( $_POST ['upload_raw'] )) {
	++ $c;
}
if ($c > 1) {
	err ( 'provided more than 1 paste data source!' );
}
if ($c < 1) {
	err ( 'no paste data provided!' );
}
$db->beginTransaction ();
if (! empty ( $_FILES )) {
	// file upload mode
	err ( 'FILE UPLOADS ARE NOT YET IMPLEMENTED!', 1, 500 );
} else {
	// string upload mode
	$paste = ( string ) $_POST ['upload_raw'];
	$hash = h_string ( $paste );
	$existed = false;
	$hashid = rawinsert ( $hash, strlen ( $paste ), $existed );
	$up = new Uploads ();
	if (true || empty ( $_POST ['upload_content_type'] )) {
		// --dereference if tmpfile() generates symlinks,
		// --preserve-date for performance
		// -E for better error handling (if any)
		// --brief and --mime should be obvious.
		// file --brief --mime --dereference -E --preserve-date URI
		// TODO: $existed optimizations
		$tmp = tmpfile ();
		fwrite ( $tmp, $paste, 500 );
		$tmpuri = stream_get_meta_data ( $tmp ) ['uri'];
		$tmpoutput = [ ];
		$tmpret = - 1;
		$tmpcmd = '/usr/bin/file --brief --mime --dereference -E --preserve-date ' . escapeshellarg ( $tmpuri ) . ' 2>&1';
		exec ( $tmpcmd, $tmpoutput, $tmpret );
		if ($tmpret !== 0) {
			throw new LogicException ( '/usr/bin/file returned nonzero! retval: ' . return_var_dump ( $tmpret ) . '. cmd:' . $tmpcmd );
		}
		if (count ( $tmpoutput ) !== 1) {
			throw new LogicException ( '/usr/bin/file did not return 1 line! lines: ' . return_var_dump ( $tmpoutput ) . '.  cmd:' . $tmpcmd );
		}
		$up->content_type = $tmpoutput [0];
		unset ( $tmp, $tmpuri, $tmpret, $tmpcmd, $tmpoutput );
	} else {
		// disabled for security reasons, until i can think of a SAFE way to do this...
		$up->content_type = $_POST ['upload_content_type'];
	}
	if ($existed) {
		unset ( $_POST ['upload_raw'], $paste );
	}
	$up->filename = $_POST ['upload_name'] ?? NULL;
	$up->id = NULL;
	$up->password_hash = (empty ( $_POST ['upload_password'] ) ? NULL : p_hash ( 'upload_password' ));
	$up->password_hash_version = 1; // << hardcoded
	$up->raw_file_id = $hashid;
	$up->upload_date = NULL;
	$up->user_id = $user_id;
	$up->is_hidden = $_POST ['upload_hidden'] ?? false;
	{
		$edate = filter_var ( $_POST ['expire_seconds'] ?? false, FILTER_VALIDATE_INT, [ 
				'options' => [ 
						'min_range' => 1,
						'max_range' => 1 * 60 * 60 * 24 * 365 
				] 
		] );
		if (false === $edate) {
			$edate = 1 * 60 * 60 * 24 * 365;
		}
		$up->expire_date = date ( 'Y-m-d H:i:s', time () + $edate );
		$resp->expire_date = $up->expire_date;
		unset ( $edate );
	}
	$up->insertSelf ();
	$db->commit ();
	if (! $existed) {
		file_put_contents ( UPLOAD_DIR . $hashid, $paste );
	} else {
		assert ( ! file_exists ( UPLOAD_DIR . $hashid ) );
	}
	$resp->status_code = 0;
	$resp->message = 'OK';
	$resp->url = urlencode ( $up->id );
	if ($up->is_hidden) {
		$resp->url .= '?hash=' . base64url_encode ( $hash );
	}
	if (! empty ( $up->filename ) && $up->filename !== 'untitled.txt') {
		$resp->url .= '/' . urlencode ( $up->filename );
	}
	$resp->url = $_SERVER ['REQUEST_SCHEME'] . '://paste.ratma.net/p/' . $resp->url;
}
/**
 * insert raw file record
 *
 * @param string $hash        	
 * @param bool $existed        	
 * @return int raw file id
 */
function rawinsert(string $hash, int $size, bool &$existed = NULL): int {
	global $db;
	$stm = $db->prepare ( 'INSERT INTO raw_files (hash,size) VALUES(:hash,:size) ON DUPLICATE KEY UPDATE `last_accessed` = NOW();' );
	$stm->execute ( array (
			':hash' => $hash,
			':size' => $size 
	) );
	$rc = $stm->rowCount ();
	if ($rc === 2) {
		$existed = true;
	} elseif ($rc === 1) {
		$existed = false;
	} else {
		throw new \LogicException ( 'this INSERT statement should always return 1 or 2, but it did not! returned: ' . return_var_dump ( $rc ) );
	}
	return filter_var ( $db->lastInsertId (), FILTER_VALIDATE_INT );
}
function h_file(string $filename): string {
	$hash = hash_file ( 'tiger160,4', $filename, true );
	return $hash;
}
function h_string(string $str): string {
	$hash = hash ( 'tiger160,4', $str, true );
	return $hash;
}
class Response {
	/** @var int $status_code */
	public $status_code = 1;
	/** @var string $message */
	public $message = 'unknown error';
	/** @var string $url */
	public $url = '';
	/** @var string $expire_date */
	public $expire_date = '';
	/** @var string[]|null $warnings */
	public $warnings = [ ];
}
function err(string $message, int $status_code = 1, int $http_error_code = 400) {
	global $resp;
	http_response_code ( $http_error_code );
	$resp->status_code = $status_code;
	$resp->message = 'error: ' . $message;
	die ();
}
function validate_api_token(int $user_id, string $token): bool {
	if ($user_id === 1) {
		// ANONYMOUS_UPLOADS_NEEDS_NO_TOKEN
		return true;
	}
	global $db;
	$stm = $db->prepare ( 'SELECT COUNT(*) FROM users WHERE id = ? AND api_token = ? AND api_token IS NOT NULL' );
	$stm->execute ( array (
			$user_id,
			$token 
	) );
	return ! ! ($stm->fetchAll ( PDO::FETCH_NUM ) [0] [0]);
}
