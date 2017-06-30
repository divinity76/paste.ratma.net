<?php
declare(strict_types = 1);
require_once ('hhb_.inc.php');
header ( "content-type: text/plain;charset=utf8" );
hhb_var_dump ( $_GET, $_POST, file_get_contents ( 'php://input' ), $_SERVER );