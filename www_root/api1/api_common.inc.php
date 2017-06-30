<?php
declare(strict_types = 1);
require_once (__DIR__ . '/../../includes.inc.php');
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
function base64url_encode($data) {
	return rtrim ( strtr ( base64_encode ( $data ), '+/', '-_' ), '=' );
}
function base64url_decode($data) {
	return base64_decode ( str_pad ( strtr ( $data, '-_', '+/' ), strlen ( $data ) % 4, '=', STR_PAD_RIGHT ) );
}
