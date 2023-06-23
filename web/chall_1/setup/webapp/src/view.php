<?php
require("config.php");

if(!$_SESSION['id']){
  header("Location: /login.php");
}

if(isset($_POST['id'])) {
    $id = $_POST['id'];
    $task = get_task($pdo, $id);
    if(!$task){
        echo "ERROR 404 - Task not found";
        exit();
    }
}else{
    echo "I'm sorry, im going to need a task id -.-";
    exit();
}

?>

<!DOCTYPE html>
<html lang="en">
    <head>
        <meta charset="utf-8" />
        <meta http-equiv="x-ua-compatible" content="ie=edge" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-rbsA2VBKQhggwzxH7pPCaAqO46MgnOM80zW1RWuH61DGLwZJEdK2Kadq2F9CUG65" crossorigin="anonymous">    <title>My Tasks</title>
        <link rel="stylesheet" href="css/style.css" />
        <title>Task Details</title>
    </head>

    <body>
    <section class="vh-100 gradient-custom-task">
    <div class="container py-5 h-100">
      <div class="row d-flex justify-content-center align-items-center h-100">
        <div class="col col-8">
          <div class="card rounded-3">
            <div class="card-body p-4">

                <h4 class="text-center my-3 pb-3">Task Details</h4>
                
                <ul class="list-group list-group-flush col-6">
                    <li class="list-group-item">Title: <?= $task['title']?></li>
                    <li class="list-group-item">Description: <?= $task['description']?></li>
                    <li class="list-group-item">Complete: <?= $task['is_completed'] ? 'Yes' : 'No'; ?> </li>
                </ul>
        
                <div class="mt-5">
                    <a href="/index.php" class="btn btn-primary">Go back</a>
                    <button class="btn btn-danger" onclick="del_task(<?= $task['id']?>)">Delete</button>
                </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </section>

  <form id="delete_task" action="/index.php" method="post">
        <input type="hidden" name="id" id="task_id">
        <input type="hidden" name="method" value="delete">
  </form>

  
    </body>
    <script src="https://code.jquery.com/jquery-3.3.1.slim.min.js" integrity="sha384-q8i/X+965DzO0rT7abK41JStQIAqVgRVzpbzo5smXKp4YfRvH+8abtTE1Pi6jizo" crossorigin="anonymous"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.14.7/umd/popper.min.js" integrity="sha384-UO2eT0CpHqdSJQ6hJty5KVphtPhzWj9WO1clHTMGa3JDZwrnQq4sF86dIHNDz0W1" crossorigin="anonymous"></script>
    <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/js/bootstrap.min.js" integrity="sha384-JjSmVgyd0p3pXB1rRibZUAYoIIy6OrQ6VrjIEaFf/nJGzIxFDsf4x0xIM+B07jRM" crossorigin="anonymous"></script>
    <script>

        function del_task(id){
            document.getElementById("task_id").value = id;
            document.getElementById("delete_task").submit();
        }

    </script>
  </html>
