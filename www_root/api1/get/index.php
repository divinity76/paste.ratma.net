<?php
declare(strict_types = 1);
require_once (__DIR__ . '/../api_common.inc.php');
http_response_code ( 500 );

$id = ( string ) $_POST ['id'] ?? NULL;
if (false === $id) {
	http_response_code ( 400 );
	die ( 'invalid id!' );
}
class Res {
	public $filename;
	public $content_type;
	public $is_hidden;
	public $password_hash;
	public $expire_date;
	public $raw_file_id;
	public $raw_file_hash;
}
$stm = $db->prepare ( 'SELECT filename,content_type,is_hidden,password_hash,expire_date,raw_files.id AS raw_file_id,raw_files.hash AS raw_file_hash FROM uploads INNER JOIN raw_files ON uploads.raw_file_id = raw_files.id WHERE uploads.id= ? LIMIT 1' );
$stm->bindValue ( 1, $id, PDO::PARAM_INT );
$stm->execute ();
$row = $stm->fetchAll ( PDO::FETCH_CLASS, 'res' );
unset ( $stm );
if (empty ( $row )) {
	http_response_code ( 404 );
	die ( 'not found' );
}
$row = $row [0];
/** @var Res $row */
if (strtotime ( $row->expire_date ) <= time ()) {
	// HTTP 410 Gone, expired.
	http_response_code ( 410 );
	die ( 'this upload has expired.' );
}
if ($row->is_hidden) {
	$hash = $_POST ['hash'] ?? NULL;
	if (empty ( $hash )) {
		http_response_code ( 403 );
		die ( 'this upload is hidden, you need the hidden hash to view hidden uploads, and you did not provide one.' );
	}
	$hash = base64url_decode ( $hash );
	if (! hash_equals ( $row->raw_file_hash, $hash )) {
		http_response_code ( 403 );
		die ( 'the provided hidden hash is invalid!' );
	}
	unset ( $hash );
}
if (! empty ( $row->password_hash )) {
	$password = ( string ) $_POST ['password'] ?? NULL;
	if (empty ( $password )) {
		http_response_code ( 403 );
		die ( 'this upload is password protected, and you did not provide a password.' );
	}
	if (! p_verify ( $password, $row->password_hash )) {
		http_response_code ( 403 );
		die ( 'wrong password provided!' );
	}
}
header ( "content-type: " . $row->content_type );
// /internal_nginx_serve_upload
header ( "X-Accel-Redirect: /internal_nginx_serve_upload/" . $row->raw_file_id );
die ();//we're done here, nginx takes care of the rest.