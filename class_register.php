<!-- Creating a secure registration form using PDO with an object-oriented 
approach involves implementing various security measures such as token generation, 
password salting and hashing, SQL injection prevention, input validation, 
XSS protection, and CSRF protection. 
Below is an example of how to achieve this in PHP: -->

<?php
require_once 'Database.php';

class UserRegistration {
    private $pdo;

    public function __construct(Database $database) {
        $this->pdo = $database->getConnection();
    }

    public function generateToken() {
        return bin2hex(random_bytes(32));
    }

    public function validateInput($data) {
        return htmlspecialchars(strip_tags(trim($data)));
    }

    public function register($username, $email, $password, $csrfToken) {
        session_start();
        if ($_SESSION['csrf_token'] !== $csrfToken) {
            throw new Exception('Invalid CSRF token');
        }

        $username = $this->validateInput($username);
        $email = $this->validateInput($email);

        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            throw new Exception('Invalid email format');
        }

        if (strlen($password) < 8) {
            throw new Exception('Password must be at least 8 characters long');
        }

        $salt = bin2hex(random_bytes(16));
        $passwordHash = password_hash($password . $salt, PASSWORD_BCRYPT);

        $stmt = $this->pdo->prepare("INSERT INTO users (username, email, password, salt) VALUES (?, ?, ?, ?)");
        $stmt->execute([$username, $email, $passwordHash, $salt]);

        return "Registration successful!";
    }
}
?>
