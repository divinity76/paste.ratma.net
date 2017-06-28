<?php
declare(strict_types = 1);
class Raw_files {
	/** @var integer $id */
	public $id;
	/** @var string $hash */
	public $hash;
	/** @var integer $size */
	public $size;
	public $first_seen;
	public $last_accessed;
}
class Uploads {
	/** @var integer $id */
	public $id;
	/** @var integer $user_id */
	public $user_id;
	/** @var integer $raw_file_id */
	public $raw_file_id;
	/** @var string $filename */
	public $filename;
	/** @var string $content_type */
	public $content_type;
	/** @var boolean $is_hidden */
	public $is_hidden;
	/** @var string|null $password_hash */
	public $password_hash;
	/** @var integer $password_hash_version */
	public $password_hash_version;
	public $upload_date;
	public function insertSelf() {
		global $db;
		if (empty ( $this->id )) {
			unset ( $this->id );
		}
		if (empty ( $this->user_id )) {
			throw new LogicException ( 'user_id must not be empty at this point!' );
		}
		if (empty ( $this->raw_file_id )) {
			throw new LogicException ( 'raw_file_id must not be empty at this point!' );
		}
		if (empty ( $this->filename )) {
			unset ( $this->filename );
		}
		if (empty ( $this->content_type )) {
			unset ( $this->content_type );
		}
		if (empty ( $this->password_hash )) {
			unset ( $this->password_hash );
		}
		if (empty ( $this->password_hash_version )) {
			unset ( $this->password_hash_version );
		}
		if (empty ( $this->upload_date )) {
			unset ( $this->upload_date );
		}
		$this->is_hidden = filter_var ( $this->is_hidden, FILTER_VALIDATE_BOOLEAN );
		$arr = ( array ) $this;
		$keys = array_keys ( $arr );
		$sql = 'INSERT INTO uploads (';
		foreach ( $keys as $key ) {
			$sql .= '`' . $key . '`,';
		}
		$sql = substr ( $sql, 0, - 1 );
		$sql .= ') VALUES(';
		foreach ( $keys as $key ) {
			$sql .= ':' . $key . ',';
		}
		$sql = substr ( $sql, 0, - 1 );
		$sql .= ');';
		$db->prepare ( $sql )->execute ( $arr );
		$this->id = $db->lastInsertId ();
	}
}
class Users {
	/** @var integer $id */
	public $id;
	/** @var string $username */
	public $username;
	/** @var string|null $password_hash */
	public $password_hash;
	/** @var integer $password_hash_version */
	public $password_hash_version;
	/** @var string|null $api_token */
	public $api_token;
	public $register_date;
}
