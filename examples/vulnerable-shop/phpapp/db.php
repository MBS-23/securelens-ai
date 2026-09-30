<?php
$conn = mysqli_connect("localhost", "app", "pw", "shop");

function find_user($id) {
    global $conn;
    $sql = "SELECT * FROM users WHERE id = '$id'";
    return mysqli_query($conn, $sql);
}

function find_user_safe($id) {
    global $conn;
    $stmt = mysqli_prepare($conn, "SELECT * FROM users WHERE id = ?");
    mysqli_stmt_bind_param($stmt, "i", $id);
    return mysqli_stmt_execute($stmt);
}
