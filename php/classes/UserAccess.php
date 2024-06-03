<?php
require_once 'Database.php';

class UserAccess {
    private $pdo;

    public function __construct(Database $database) {
        $this->pdo = $database->getConnection();
    }

    public function getUserData($userId) {
        $stmt = $this->pdo->prepare("SELECT username, email FROM users WHERE id = ?");
        $stmt->execute([$userId]);
        return $stmt->fetch();
    }

    public function generateToken() {
        return bin2hex(random_bytes(32));
    }
}
?>
