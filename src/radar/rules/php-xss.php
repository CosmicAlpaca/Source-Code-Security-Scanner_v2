<?php
$name = $_GET['name'];
// ruleid: php-xss
echo $name;

$msg = $_POST['message'];
// ruleid: php-xss
print($msg);

// ok: php-xss
echo htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');
