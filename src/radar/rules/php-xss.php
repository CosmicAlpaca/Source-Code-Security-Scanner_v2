<?php
// ruleid: php-xss
echo $_GET['name'];

// ruleid: php-xss
echo $_POST['message'];

// ok: php-xss
echo htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');
