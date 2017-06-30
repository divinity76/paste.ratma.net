<?php
declare(strict_types = 1);
// require_once ('hhb_.inc.php');
require_once (__DIR__ . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . 'api1' . DIRECTORY_SEPARATOR . 'api_common.inc.php');
header ( "content-type: text/plain;charset=utf8" );
// hhb_var_dump ( $_GET, $_POST, file_get_contents ( 'php://input' ), $_SERVER );

$info = parse_url ( $_SERVER ['REQUEST_URI'] );
if (substr ( $info ['path'], 0, strlen ( '/p/' ) ) !== '/p/') {
	http_response_code ( 400 );
	die ( 'invalid paste id!' );
}
$info ['path'] = substr ( $info ['path'], strlen ( '/p/' ) );
if (false !== strpos ( ($info ['query'] ?? ''), '/' )) {
	$info ['filename'] = substr ( $info ['query'], strpos ( $info ['query'], '/' ) + 1 );
	$info ['query'] = parse_url ( '?' . substr ( $info ['query'], 0, strpos ( $info ['query'], '/' ) ), PHP_URL_QUERY );
}
if (false !== strpos ( ($info ['path']), '/' )) {
	$info ['filename'] = substr ( $info ['path'], strpos ( $info ['path'], '/' ) + 1 );
	$info ['path'] = parse_url ( substr ( $info ['path'], 0, strpos ( $info ['path'], '/' ) ), PHP_URL_PATH );
}
parse_str ( ($info ['query'] ?? ''), $info ['query'] );
// hhb_var_dump ( $info ) & die ();
$id = filter_var ( $info ['path'], FILTER_VALIDATE_INT, [ 
		'options' => [ 
				'min_range' => 1 
		] 
] );
if (false === $id) {
	http_response_code ( 400 );
	die ( 'non-numeric paste id!' );
}
class Res {
	public $filename;
	public $content_type;
	public $is_hidden;
	public $password_hash;
	public $expire_date;
	public $raw_file_id;
	public $raw_file_hash;
	public $upload_date;
	public $raw_file_size;
}
$stm = $db->prepare ( 'SELECT upload_date,filename,content_type,is_hidden,password_hash,expire_date,raw_files.id AS raw_file_id,raw_files.size AS raw_file_size,raw_files.hash AS raw_file_hash FROM uploads INNER JOIN raw_files ON uploads.raw_file_id = raw_files.id WHERE uploads.id= ? LIMIT 1' );
$stm->bindValue ( 1, $id, PDO::PARAM_INT );
$stm->execute ();
$row = $stm->fetchAll ( PDO::FETCH_CLASS, 'res' );
unset ( $stm );
if (empty ( $row )) {
	// not found
	http_response_code ( 404 );
	die ( 'paste not found (probably deleted or expired)' );
}
$row = $row [0];
/** @var Res $row */
if (strtotime ( $row->expire_date ) <= time ()) {
	// HTTP 410 Gone, expired.
	http_response_code ( 410 );
	die ( 'this upload has expired.' );
}
if ($row->is_hidden) {
	$hash = $info ['query'] ['hash'] ?? NULL;
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
		// FIXME: better ask for password page
		die ( 'this upload is password protected, and you did not provide a password.' );
	}
	if (! p_verify ( $password, $row->password_hash )) {
		http_response_code ( 403 );
		die ( 'wrong password provided!' );
	}
}
// ///header ( "X-Accel-Redirect: /internal_nginx_serve_upload/" . $row->raw_file_id );
// ///die ();//we're done here, nginx takes care of the rest.
http_response_code ( 200 );
header ( "content-type: text/html;charset=utf8" );
?>
<!DOCTYPE HTML>
<html>
<head>
<title>paste - <?php

if (! empty ( $row->filename )) {
	echo tohtml ( $row->filename ) . ' - ';
}
echo tohtml ( ( string ) $id );
?></title>
<script
	src="https://cdn.rawgit.com/google/code-prettify/master/loader/run_prettify.js"></script>
</head>
<body>
	<pre>
<?php
echo 'filename: ' . tohtml ( ( string ) $row->filename ) . "\n";
echo 'file type:' . tohtml ( ( string ) $row->content_type ) . "\n";
echo 'upload date:' . tohtml ( ( string ) $row->upload_date ) . "\n";
echo 'expire date:' . tohtml ( ( string ) $row->expire_date ) . "\n";
echo 'size ' . tohtml ( ( string ) $row->raw_file_size ) . ' (in bytes)' . "\n";
?>
</pre>
	<pre style="background-color: aliceblue;" class="prettyprint"
		id="paste_raw">
<?php
echo tohtml ( file_get_contents ( __DIR__ . '/../../uploads/' . $row->raw_file_id ) );
?>
</pre>
</body>
</html>