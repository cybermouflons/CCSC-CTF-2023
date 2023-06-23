<?php
session_start();

$server = "db";
$db_user = "dbuser";
$db_pass = "dbpass";
$dbname = "test_db";
$dsn = "mysql:host=$server;dbname=$dbname";


// Create a new PDO instance
try {
    $pdo = new PDO($dsn, $db_user, $db_pass);
    
    // Set additional PDO attributes if needed
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->setAttribute(PDO::ATTR_EMULATE_PREPARES, false);
    
    // Perform database operations using the $pdo object
    
} catch (PDOException $e) {
    echo "Connection failed: " . $e->getMessage();
}

// Check if admin user exists, if not migrate DB
try {
$stmt = $pdo->prepare("SELECT * FROM users WHERE username='admin'");
$stmt->execute();
$results = $stmt->fetch(PDO::FETCH_ASSOC);
if(!$results){
    migrate($pdo);
}
} catch (PDOException $e) {
    migrate($pdo);
}



// Database migration

function migrate($pdo) {

    // Create users table
    dropTable($pdo, 'tasks');
    dropTable($pdo, 'users');
    try {
        $stmt = $pdo->prepare("create table users (
            id INT(6) unsigned auto_increment primary key,
            username varchar(30) not null,
            password varchar(32) not null
        )");
        $stmt->execute();
    } catch (PDOException $e) {
        throw $e;
    }

     // Create tasks table
     
     try {
         $stmt = $pdo->prepare("create table tasks (
            id INT(6) unsigned auto_increment primary key,
            title varchar(254) not null,
            description text,
            is_completed boolean default FALSE,
            user_id INT(6) unsigned,
            FOREIGN KEY (user_id) REFERENCES users(id)
         )");
         $stmt->execute();
     } catch (PDOException $e) {
         throw $e;
     }


    // Create admin user
    try {   
        $admin_password = md5('artificialness12');
        $stmt = $pdo->prepare("INSERT INTO users (username, password) VALUES ('admin', ?)");
        $stmt->bindParam(1, $admin_password, PDO::PARAM_STR);
        $stmt->execute();
    } catch (PDOException $e) {
        throw $e;
    }
}

function log_error($user_agent, $ip){

    $file = 'error_logs.txt';

    $text = "Invalid Login Attempt - " . $ip . " - ". $user_agent . "\n";

    file_put_contents($file, $text, FILE_APPEND);

}

// Dynamic drop table function
function dropTable($pdo, $tableName) {
    try {
        $stmt = $pdo->prepare("DROP TABLE if exists $tableName");
        $stmt->execute();
    } catch (PDOException $e) {
        throw $e;
    }
}


// I dont know why we used binding anyways
function get_task($pdo,$id){
    $stmt = $pdo->prepare("select * from tasks where id='$id'");
    $stmt->execute();
    $task = $stmt->fetch(PDO::FETCH_ASSOC);
    return $task;
}

function get_user_tasks($pdo,$id){
    $stmt = $pdo->prepare("select * from tasks where user_id=:user_id");
    $stmt->bindParam(':user_id', $id);
    $stmt->execute();
    $tasks = $stmt->fetchAll(PDO::FETCH_ASSOC);
    return $tasks;
}

function add_task($pdo, $title, $description, $user_id){
    try{
        $stmt = $pdo->prepare("insert into tasks (title, description, is_completed, user_id) values (
                :title,
                :description,
                false,
                :user_id
            )");
        $stmt->bindValue(':title', $title);
        $stmt->bindValue(':description', $description);
        // $stmt->bindValue(':is_complete', FALSE);
        $stmt->bindValue(':user_id', $user_id);
        $stmt->execute();
    } catch (PDOException $e) {
        throw $e;
    }
    
}

function delete_task($pdo, $id){
    try{
        $stmt = $pdo->prepare("delete from tasks where id = :id");
        $stmt->bindParam(':id', $id);
        $stmt->execute();
    } catch (PDOException $e) {
        throw $e;
    }
    
}

function username_exists($pdo, $username){
    try{
        $stmt = $pdo->prepare("SELECT * FROM users WHERE username=:username");
        $stmt->bindValue(':username', $username);
        $stmt->execute();
        $results = $stmt->fetch(PDO::FETCH_ASSOC);
    } catch (PDOException $e) {
        throw $e;
    }

    return $results;
}

function login($pdo, $username,$password){
	//hash password with md5
	$password = md5($password);

    $stmt = $pdo->prepare("SELECT * FROM users WHERE username=? and password=?");
    $stmt->bindParam(1, $username, PDO::PARAM_STR);
    $stmt->bindParam(2, $password, PDO::PARAM_STR);
    $stmt->execute();
    $results = $stmt->fetch(PDO::FETCH_ASSOC);

    // var_dump($results);

	if($results){
		//fill the result to session variable
		$_SESSION['id'] = $results['id'];
		$_SESSION['username'] = $results['username'];
		return TRUE;
	}else{
		return FALSE;
	}
}

// User signup 

function register($pdo, $username, $password){
    try {
        $password = md5($password);
        $stmt = $pdo->prepare("insert into users (username, password) values (?, ?)");
        $stmt->bindParam(1, $username, PDO::PARAM_STR);
        $stmt->bindParam(2, $password, PDO::PARAM_STR);
        $stmt->execute();
        return true;
    } catch (PDOException $e) {
        throw $e;
    }
}

