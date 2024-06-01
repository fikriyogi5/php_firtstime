<?php
require_once 'Database.php';
require_once 'class_register.php';

try {
    $database = new Database();
    $registration = new UserRegistration($database);
    session_start();
    $_SESSION['csrf_token'] = $registration->generateToken();

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $csrfToken = $_POST['csrf_token'];
        $username = $_POST['username'];
        $email = $_POST['email'];
        $password = $_POST['password'];
        echo $registration->register($username, $email, $password, $csrfToken);
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
    <title>Register</title>
</head>
<body>
    <form method="POST" action="">
        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
        <label for="username">Username:</label>
        <input type="text" id="username" name="username" required><br>
        <label for="email">Email:</label>
        <input type="email" id="email" name="email" required><br>
        <label for="password">Password:</label>
        <input type="password" id="password" name="password" required><br>
        <button type="submit">Register</button>
    </form>
</body>
</html>
