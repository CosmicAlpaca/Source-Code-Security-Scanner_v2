<?php
// ruleid: php-file-inclusion
include($_GET['page']);

// ruleid: php-file-inclusion
require($_POST['module'] . '.php');

// ok: php-file-inclusion
$allowed = ['home', 'about', 'contact'];
$page = in_array($_GET['page'], $allowed) ? $_GET['page'] : 'home';
include('pages/' . $page . '.php');
