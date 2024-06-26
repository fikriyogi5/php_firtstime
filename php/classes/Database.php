<?php
class Database {
    private $host = 'localhost';
    private $dbname = 'secure';
    private $username = 'root';
    private $password = '';
    private $pdo;

    public function __construct() {
        $dsn = "mysql:host=$this->host;dbname=$this->dbname;charset=utf8mb4";
        $options = [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
        ];
        $this->pdo = new PDO($dsn, $this->username, $this->password, $options);
    }


    public function getConnection() {
        return $this->pdo;
    }
    
}
?>
