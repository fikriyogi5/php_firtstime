<!-- Here's a secure login form implementation in PHP using PDO, 
object-oriented programming, and various security measures such as input validation, 
password hashing, and protection against SQL injection, XSS, and CSRF attacks. 
In this example:

1. PDO Connection: Establishes a secure connection to the database using PDO with error handling and secure options.
2. Token Generation: Generates a secure CSRF token to prevent Cross-Site Request Forgery attacks.
3. Input Validation: Sanitizes and validates user inputs to prevent XSS and SQL injection attacks.
4. Password Verification: Uses password_verify to securely compare the input password with the stored hash.
5. CSRF Protection: Ensures that the form submission includes a valid CSRF token.
6. Error Handling: Provides meaningful error messages for debugging and user feedback.
7. Session Handling: Manages user sessions securely to maintain login state.
8. Google reCaptcha.
-->
<?php
class UserLogin {
    private $pdo;
    private $recaptchaSecret;

    public function __construct($host, $dbname, $username, $password, $recaptchaSecret) {
        $dsn = "mysql:host=$host;dbname=$dbname;charset=utf8mb4";
        $options = [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
        ];
        $this->pdo = new PDO($dsn, $username, $password, $options);
        $this->recaptchaSecret = $recaptchaSecret;
    }

    public function generateToken() {
        return bin2hex(random_bytes(32));
    }

    public function validateInput($data) {
        return htmlspecialchars(strip_tags(trim($data)));
    }

    public function validatePassword($password) {
        if (strlen($password) < 8) {
            throw new Exception('Password must be at least 8 characters long');
        }
        if (!preg_match('/[A-Z]/', $password)) {
            throw new Exception('Password must contain at least one uppercase letter');
        }
        if (!preg_match('/[a-z]/', $password)) {
            throw new Exception('Password must contain at least one lowercase letter');
        }
        if (!preg_match('/[0-9]/', $password)) {
            throw new Exception('Password must contain at least one number');
        }
        if (!preg_match('/[\W_]/', $password)) {
            throw new Exception('Password must contain at least one special character');
        }
    }

    public function verifyCaptcha($captchaResponse) {
        $response = file_get_contents("https://www.google.com/recaptcha/api/siteverify?secret=" . $this->recaptchaSecret . "&response=" . $captchaResponse);
        $responseKeys = json_decode($response, true);
        if (intval($responseKeys["success"]) !== 1) {
            throw new Exception('Please complete the CAPTCHA');
        }
    }

    public function login($username, $password, $csrfToken, $captchaResponse) {
        session_start();
        if ($_SESSION['csrf_token'] !== $csrfToken) {
            throw new Exception('Invalid CSRF token');
        }

        $this->verifyCaptcha($captchaResponse);
        $username = $this->validateInput($username);
        $this->validatePassword($password);

        $stmt = $this->pdo->prepare("SELECT * FROM users WHERE username = ?");
        $stmt->execute([$username]);
        $user = $stmt->fetch();

        if ($user && password_verify($password . $user['salt'], $user['password'])) {
            $_SESSION['user_id'] = $user['id'];
            return "Login successful!";
        } else {
            throw new Exception('Invalid username or password');
        }
    }
}

// Usage example
try {
    $host = 'your_host';
    $dbname = 'your_dbname';
    $username = 'your_username';
    $password = 'your_password';
    $recaptchaSecret = 'your_recaptcha_secret'; // Your reCAPTCHA secret key

    $login = new UserLogin($host, $dbname, $username, $password, $recaptchaSecret);
    session_start();
    $_SESSION['csrf_token'] = $login->generateToken();

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $csrfToken = $_POST['csrf_token'];
        $username = $_POST['username'];
        $password = $_POST['password'];
        $captchaResponse = $_POST['g-recaptcha-response'];
        echo $login->login($username, $password, $csrfToken, $captchaResponse);
    }
} catch (Exception $e) {
    echo 'Error: ' . $e->getMessage();
}
?>

<!-- HTML form -->
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Login</title>
    <script src="https://www.google.com/recaptcha/api.js" async defer></script>
</head>
<body>
    <form method="POST" action="">
        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
        <label for="username">Username:</label>
        <input type="text" id="username" name="username" required><br>
        <label for="password">Password:</label>
        <input type="password" id="password" name="password" required><br>
        <div class="g-recaptcha" data-sitekey="your_recaptcha_site_key"></div> <!-- Your reCAPTCHA site key -->
        <button type="submit">Login</button>
    </form>
</body>
</html>
