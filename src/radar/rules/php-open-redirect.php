<?php
// ruleid: php-open-redirect
header("Location: " . $_GET['next']);

// ruleid: php-open-redirect
header("Location: " . $_REQUEST['url']);

// ok: php-open-redirect
header("Location: /dashboard");
