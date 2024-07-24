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

        $table = htmlspecialchars(strip_tags(trim($_POST['table'])));
        $action = htmlspecialchars(strip_tags(trim($_POST['action'])));
        $response = '';

        switch ($action) {
            case 'create':
                $columns = $_POST['columns'];
                $values = $_POST['values'];
                
                if (count($columns) !== count($values)) {
                    throw new Exception('Columns and values count mismatch');
                }

                $columns_str = implode(", ", array_map(fn($col) => htmlspecialchars(strip_tags(trim($col))), $columns));
                $placeholders = implode(", ", array_fill(0, count($values), '?'));
                
                $stmt = $database->getConnection()->prepare("INSERT INTO $table ($columns_str) VALUES ($placeholders)");
                $stmt->execute($values);

                $response = "Record created successfully in $table!";
                break;

            case 'read':
                $id = htmlspecialchars(strip_tags(trim($_POST['id'])));
                
                $stmt = $database->getConnection()->prepare("SELECT * FROM $table WHERE id = ?");
                $stmt->execute([$id]);

                $result = $stmt->fetch(PDO::FETCH_ASSOC);
                $response = json_encode($result);
                break;

            case 'update':
                $id = htmlspecialchars(strip_tags(trim($_POST['id'])));
                $columns = $_POST['columns'];
                $values = $_POST['values'];

                if (count($columns) !== count($values)) {
                    throw new Exception('Columns and values count mismatch');
                }

                $update_str = implode(", ", array_map(fn($col) => htmlspecialchars(strip_tags(trim($col))) . " = ?", $columns));
                
                $stmt = $database->getConnection()->prepare("UPDATE $table SET $update_str WHERE id = ?");
                $stmt->execute([...$values, $id]);

                $response = "Record updated successfully in $table!";
                break;

            case 'delete':
                $id = htmlspecialchars(strip_tags(trim($_POST['id'])));
                
                $stmt = $database->getConnection()->prepare("DELETE FROM $table WHERE id = ?");
                $stmt->execute([$id]);

                $response = "Record deleted successfully from $table!";
                break;

            default:
                throw new Exception('Invalid action');
        }

        echo $response;
    } catch (Exception $e) {
        echo 'Error: ' . $e->getMessage();
    }
}
?>



<?php
session_start();
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
$csrf_token = $_SESSION['csrf_token'];
?>
3. HTML Form Example
Here's how you can create an HTML form to interact with the script for different CRUD operations.

Create
html
Salin kode
<form method="POST" action="your_script.php">
    <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
    <input type="hidden" name="action" value="create">
    <input type="hidden" name="table" value="users">

    <!-- Add fields for the columns you want to insert -->
    <input type="text" name="columns[]" value="email">
    <input type="email" name="values[]">

    <button type="submit">Create</button>
</form>
Read
html
Salin kode
<form method="POST" action="your_script.php">
    <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
    <input type="hidden" name="action" value="read">
    <input type="hidden" name="table" value="users">
    
    <label for="id">ID:</label>
    <input type="text" name="id">
    
    <button type="submit">Read</button>
</form>
Update
html
Salin kode
<form method="POST" action="your_script.php">
    <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
    <input type="hidden" name="action" value="update">
    <input type="hidden" name="table" value="users">

    <label for="id">ID:</label>
    <input type="text" name="id">

    <!-- Add fields for the columns you want to update -->
    <input type="text" name="columns[]" value="email">
    <input type="email" name="values[]">

    <button type="submit">Update</button>
</form>
Delete
html
Salin kode
<form method="POST" action="your_script.php">
    <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
    <input type="hidden" name="action" value="delete">
    <input type="hidden" name="table" value="users">
    
    <label for="id">ID:</label>
    <input type="text" name="id">
    
    <button type="submit">Delete</button>
</form>
4. Script
Ensure your PHP script (your_script.php) handles the form submissions as shown in the previous response.

Summary
Create: Submits column names and values to insert a new record.
Read: Submits an ID to retrieve a record.
Update: Submits an ID, column names, and values to update an existing record.
Delete: Submits an ID to delete a record.
You can create similar forms for other tables by changing the table value and adjusting the column inputs as needed.