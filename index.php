<!-- Explanation:
Session Management: The user_access.php page checks if the user is logged in by verifying the session. If not, it redirects to the login page.
CSRF Protection: The form includes a CSRF token to prevent CSRF attacks. This token is validated in update_user.php.
Input Validation and Sanitization: User inputs are sanitized using htmlspecialchars and strip_tags. Additionally, the email is validated using filter_var.
Prepared Statements: All database interactions use prepared statements to prevent SQL injection.
Logout: The logout.php script ends the user session and redirects to the login page. -->
<?php
session_start();

// Check if the user is logged in
if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit;
}

require_once 'php/autoload.php';

try {
    $database = new Database();
    $userAccess = new UserAccess($database);
    $_SESSION['csrf_token'] = $userAccess->generateToken();
    $userData = $userAccess->getUserData($_SESSION['user_id']);
} catch (Exception $e) {
    echo 'Error: ' . $e->getMessage();
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>User Access</title>
</head>
<body>
    <h1>Welcome, <?php echo htmlspecialchars($userData['username']); ?>!</h1>
    <p>Email: <?php echo htmlspecialchars($userData['email']); ?></p>

    <form method="POST" action="update_user.php">
        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
        <label for="new_email">New Email:</label>
        <input type="email" id="new_email" name="new_email" required><br>
        <button type="submit">Update Email</button>
    </form>

    <form method="POST" action="logout.php">
        <button type="submit">Logout</button>
    </form>
</body>
</html>
