<?php

function runExpr()
{
    $code = $_GET["code"];
    // ruleid: php-eval-user-input
    eval($code);
}

function runTemplate()
{
    $tpl = $_POST["tpl"];
    // ruleid: php-eval-user-input
    eval("return " . $tpl . ";");
}

function safeEval()
{
    // ok: php-eval-user-input
    eval("return 1 + 1;");
}
