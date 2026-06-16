<?php
// ruleid: php-command-injection
exec($_GET['cmd']);

// ruleid: php-command-injection
system("ping " . $_POST['host']);

// ok: php-command-injection
exec(escapeshellcmd($_GET['cmd']));
