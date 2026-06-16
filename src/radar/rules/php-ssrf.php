<?php
$ch = curl_init();

// ruleid: php-ssrf
curl_setopt($ch, CURLOPT_URL, $_GET['url']);
curl_exec($ch);

// ruleid: php-ssrf
$response = file_get_contents($_GET['url']);

// ok: php-ssrf
curl_setopt($ch, CURLOPT_URL, 'https://internal-api.example.com/data');
