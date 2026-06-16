<?php
$db = new mysqli("localhost", "user", "pass", "mydb");

// ruleid: php-sql-injection
mysqli_query($db, "SELECT * FROM users WHERE id = " . $_GET['id']);

// ruleid: php-sql-injection
$db->query("DELETE FROM sessions WHERE token = " . $_POST['token']);

// ok: php-sql-injection
$stmt = $db->prepare("SELECT * FROM users WHERE id = ?");
$stmt->bind_param("i", $_GET['id']);
$stmt->execute();
