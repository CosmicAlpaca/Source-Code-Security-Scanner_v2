<?php
// ruleid: php-weak-hash
$hash = md5($_POST['password']);

// ruleid: php-weak-hash
$hash = sha1($_GET['token']);

// ok: php-weak-hash
$hash = password_hash($_POST['password'], PASSWORD_BCRYPT);
