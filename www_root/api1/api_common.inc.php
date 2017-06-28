<?php
declare(strict_types = 1);
require_once (__DIR__ . '/../../includes.inc.php');
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
function p_hash(string $plain): string {
	$plain = hash ( 'sha256', $plain, true );
	$plain = base64_encode ( $plain );
	// when i get better funding,
	// and my servers doesn't have to run on ATOM cpus..
	$plain = password_hash ( $plain, PASSWORD_BCRYPT, [ 
			'cost' => 5 
	] );
	return $plain;
}
function p_verify(string $plain, string $hash): bool {
	$plain = hash ( 'sha256', $plain, true );
	$plain = base64_encode ( $plain );
	return password_verify ( $plain, $hash );
}
