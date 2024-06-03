<?php
require_once 'php/autoload.php';

try {
    $database = new Database();
    $recaptchaSecret = 'your_recaptcha_secret';
    $login = new UserLogin($database, $recaptchaSecret);

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
        <div class="g-recaptcha" data-sitekey="your_recaptcha_site_key"></div>
        <button type="submit">Login</button>
    </form>
</body>
</html>
