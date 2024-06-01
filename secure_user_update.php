<?php
session_start();

// Check if the user is logged in
if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit;
}

// Validate CSRF token
if ($_SESSION['csrf_token'] !== $_POST['csrf_token']) {
    die('Invalid CSRF token');
}

class UserUpdate {
    private $pdo;

    public function __construct($host, $dbname, $username, $password) {
        $dsn = "mysql:host=$host;dbname=$dbname;charset=utf8mb4";
        $options = [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
        ];
        $this->pdo = new PDO($dsn, $username, $password, $options);
    }

    public function updateEmail($userId, $newEmail) {
        if (!filter_var($newEmail, FILTER_VALIDATE_EMAIL)) {
            throw new Exception('Invalid email format');
        }

        $stmt = $this->pdo->prepare("UPDATE users SET email = ? WHERE id = ?");
        $stmt->execute([$newEmail, $userId]);
    }
}

try {
    $host = 'your_host';
    $dbname = 'your_dbname';
    $username = 'your_username';
    $password = 'your_password';

    $userUpdate = new UserUpdate($host, $dbname, $username, $password);
    $newEmail = htmlspecialchars(strip_tags(trim($_POST['new_email'])));
    $userUpdate->updateEmail($_SESSION['user_id'], $newEmail);
    echo 'Email updated successfully';
} catch (Exception $e) {
    echo 'Error: ' . $e->getMessage();
}
?>
