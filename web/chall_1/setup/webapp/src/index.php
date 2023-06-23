<?php
require("config.php");

  if(!$_SESSION['id']){
    header("Location: /login.php");
    exit();
  }

  if($_SESSION['id'] == 1){
    header("Location: /admin.php");
    exit();
  }

  if($_POST['method'] == 'delete'){
    $id = $_POST['id'];
    delete_task($pdo, $id);
  }

  if(isset($_POST['submit'])) {
    $title= $_POST['title'];
    $description = $_POST['description'];   

    // Check if name has been entered
    if(empty($_POST['title'])) {
        $err= 'Title is required';
    }
    // check if a password has been entered and if it is a valid password
    else if(empty($_POST['description'])) {
        $err = 'Description is required';
    } else {
        add_task($pdo, $title, $description, $_SESSION['id']);
    }
  }
  $tasks = get_user_tasks($pdo, $_SESSION['id']);
?>

<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta http-equiv="x-ua-compatible" content="ie=edge" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-rbsA2VBKQhggwzxH7pPCaAqO46MgnOM80zW1RWuH61DGLwZJEdK2Kadq2F9CUG65" crossorigin="anonymous">    <title>My Tasks</title>
    <link rel="stylesheet" href="css/style.css" />
  </head>

  <body>

  <section class="vh-100 gradient-custom-task">
    <div class="container py-5 h-100">
      <div class="row d-flex justify-content-center align-items-center h-100">
        <div class="col col-10">
          <div class="card rounded-3">
            <div class="card-body p-4">

              <h4 class="text-center my-3 pb-3">Task List</h4>

              <table class="table mb-4">
                <thead>
                  <tr>
                    <th scope="col">No.</th>
                    <th scope="col">Title</th>
                    <th scope="col">Description</th>
                    <th scope="col">Completed</th>
                    <th scope="col">Actions</th>
                  </tr>
                </thead>
                <tbody>
              
                  <?php foreach ($tasks as $task): ?>
                    <tr>
                      <th scope="row"><?= $task['id']?></th>
                      <td><?= $task['title']?></td>
                      <td><?= $task['description']?></td>
                      <td><input type="checkbox" <?= $task['is_completed'] ? 'checked' : ''; ?>></td>
                      <td><button class="btn btn-info" onclick="view_task(<?= $task['id']?>)">View</button></td>
                    </tr>
                  <?php endforeach; ?>
                 
                </tbody>
              </table>
          
              <form class="mb-5 mt-5" id="add_task" role="form" method="post" action="/index.php">
                <div class="row">
                  <div class="mb-3 col-8">
                    <label for="title" class="form-label">New Task</label>
                    <input type="text" class="form-control" id="title" placeholder="Title" name="title">
                  </div>
                  <div class="mb-3 col-8">
                    <label for="description" class="form-label">Description</label>
                    <textarea class="form-control" id="description" rows="3" name="description" ></textarea>
                  </div>
                </div>
                <?php
                  if($err){
                    echo "<div class='mb-4'><p class='text-danger'> $err </p></div>";
                  } 
                ?>
                <button type="submit" name="submit" class="btn btn-dark">Add Task</button>
                <a href="/logout.php" class="btn btn-danger">Logout</a>
              </form>
            </div>
          </div>
        </div>
      </div>
    </div>
  </section>

  <form id="view_task" action="/view.php" method="post">
        <input type="hidden" name="id" id="taskIdInput">
  </form>

  </body>
  <script src="https://code.jquery.com/jquery-3.3.1.slim.min.js" integrity="sha384-q8i/X+965DzO0rT7abK41JStQIAqVgRVzpbzo5smXKp4YfRvH+8abtTE1Pi6jizo" crossorigin="anonymous"></script>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.14.7/umd/popper.min.js" integrity="sha384-UO2eT0CpHqdSJQ6hJty5KVphtPhzWj9WO1clHTMGa3JDZwrnQq4sF86dIHNDz0W1" crossorigin="anonymous"></script>
  <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/js/bootstrap.min.js" integrity="sha384-JjSmVgyd0p3pXB1rRibZUAYoIIy6OrQ6VrjIEaFf/nJGzIxFDsf4x0xIM+B07jRM" crossorigin="anonymous"></script>

  <script>

    function view_task(id){
        document.getElementById("taskIdInput").value = id;
        document.getElementById("view_task").submit();
    }

  </script>

  </html>
