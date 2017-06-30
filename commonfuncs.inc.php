<?php
declare(strict_types = 1);
function tohtml(string $str): string {
	return htmlentities ( $str, ENT_QUOTES | ENT_HTML401 | ENT_SUBSTITUTE | ENT_DISALLOWED, 'UTF-8', true );
}
function return_var_dump(): string // works like var_dump, but returns a string instead of printing it.
{
	$args = func_get_args (); // for <5.3.0 support ...
	ob_start ();
	call_user_func_array ( 'var_dump', $args );
	return ob_get_clean ();
}