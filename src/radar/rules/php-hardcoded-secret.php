<?php

function connect()
{
    // ruleid: php-hardcoded-secret
    $password = "S3cr3tP@ss";
    // ruleid: php-hardcoded-secret
    $api_key = "sk_live_abc123";
    // ruleid: php-hardcoded-secret
    $token = "ghp_hardcodedtoken123";
    return [$password, $api_key, $token];
}

function fromEnv()
{
    // ok: php-hardcoded-secret
    $password = getenv("DB_PASSWORD");
    // ok: php-hardcoded-secret
    $username = "admin";
    return [$password, $username];
}
