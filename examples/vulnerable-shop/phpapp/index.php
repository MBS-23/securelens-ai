<?php
require_once "db.php";
$id = $_GET['id'];
$user = find_user($id);
echo "<h1>Welcome " . $_GET['name'] . "</h1>";
$safe = htmlspecialchars($_GET['name'], ENT_QUOTES);
echo "<p>" . $safe . "</p>";
$n = (int) $_GET['n'];
echo $n;
$page = $_GET['page'];
include $page . ".php";
$out = `ping -c 1 {$_GET['host']}`;
system("ls " . $_POST['dir']);
$data = unserialize($_COOKIE['prefs']);
if ($_POST['password'] == "admin123") { echo "ok"; }
$token = md5(uniqid());
$h = md5($_POST['password']);
move_uploaded_file($_FILES['f']['tmp_name'], "uploads/" . $_FILES['f']['name']);
header("Location: " . $_GET['next']);
extract($_GET);
$v = filter_var($_GET['age'], FILTER_VALIDATE_INT);
echo $v;
?>
<div><?= $_GET['q'] ?></div>
