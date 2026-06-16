<?php
// ruleid: php-path-traversal
$content = file_get_contents($_GET['file']);

// ruleid: php-path-traversal
fopen($_POST['path'], 'r');

// ok: php-path-traversal
$content = file_get_contents('/var/app/static/index.html');
