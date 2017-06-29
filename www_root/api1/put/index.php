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
	if ($existed) {
		unset ( $_POST ['upload_raw'], $paste );
	}
	$up = new Uploads ();
	$up->content_type = $_POST ['upload_content_type'] ?? NULL;
	$up->filename = $_POST ['upload_name'] ?? NULL;
	$up->id = NULL;
	$up->password_hash = (isset ( $_POST ['upload_password'] ) ? p_hash ( 'upload_password' ) : NULL);
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
	$resp->url = 'id=' . urlencode ( $up->id );
	if ($up->is_hidden) {
		$resp->url .= '&hash=' . base64url_encode ( $hash );
	}
	if (! empty ( $up->password_hash )) {
		$resp->url .= "&password=" . urlencode ( $_POST ['upload_password'] );
	}
	$resp->url .= '/' . urlencode ( $up->filename );
	$resp->url = $_SERVER ['REQUEST_SCHEME'] . '://paste.ratma.net/api1/get/' . $resp->url;
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
		throw new \LogicException ( 'this INSERT statement should always return 1 or 2, but it did not! returned: ' . hhb_var_dump ( $rc ) );
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
function base64url_encode($data) {
	return rtrim ( strtr ( base64_encode ( $data ), '+/', '-_' ), '=' );
}
function base64url_decode($data) {
	return base64_decode ( str_pad ( strtr ( $data, '-_', '+/' ), strlen ( $data ) % 4, '=', STR_PAD_RIGHT ) );
}
class Response {
	public $status_code = 1;
	public $message = 'unknown error';
	public $url = '';
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
