<?php
// ruleid: php-unsafe-deserialization
$obj = unserialize($_COOKIE['session']);

// ruleid: php-unsafe-deserialization
$data = unserialize($_POST['payload']);

// ok: php-unsafe-deserialization
$data = json_decode($_POST['payload'], true);
