<?php
$name = $_GET['name'];
// ruleid: php-xss
printf($name);

$data = $_POST['debug'];
// ruleid: php-xss
print_r($data);

// ok: php-xss
printf(htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8'));
