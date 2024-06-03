<?php
session_start();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if ($_SESSION['csrf_token'] !== $_POST['csrf_token']) {
        die('CSRF token validation failed');
    }

    require_once 'php/autoload.php';

    try {
        $database = new Database();
        $userAccess = new UserAccess($database);
        
        $newEmail = htmlspecialchars(strip_tags(trim($_POST['new_email'])));
        
        if (!filter_var($newEmail, FILTER_VALIDATE_EMAIL)) {
            throw new Exception('Invalid email format');
        }

        $stmt = $database->getConnection()->prepare("UPDATE users SET email = ? WHERE id = ?");
        $stmt->execute([$newEmail, $_SESSION['user_id']]);

        echo "Email updated successfully!";
    } catch (Exception $e) {
        echo 'Error: ' . $e->getMessage();
    }
}
?>
