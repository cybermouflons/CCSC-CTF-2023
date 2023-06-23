<?php
require("config.php");

if($_SESSION['id']){
    if($_SESSION['id'] != 1){
        echo "Your not the admin :o";
        exit();
    }
}else{
    header("Location: /index.php");
}

?>

<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta http-equiv="x-ua-compatible" content="ie=edge" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-rbsA2VBKQhggwzxH7pPCaAqO46MgnOM80zW1RWuH61DGLwZJEdK2Kadq2F9CUG65" crossorigin="anonymous">    <title>My Tasks</title>


    <title>Admin page</title>

    <link rel="stylesheet" href="css/style.css" />
  </head>

  <body>

    <section class="vh-100 gradient-custom-task">
      <div class="container py-5 h-100">
        <div class="row d-flex justify-content-center align-items-center h-100">
          <div class="col col-8">
            <div class="card rounded-3">
              <div class="card-body p-4">

                  <h4 class="text-center my-3 pb-3">Welcome back <?= $_SESSION['username'] ?></h4>
                  
                  <div class="mb-3">Here are the application error logs:</div>
                  <pre class="border border-dark border-2 rounded rounded-2 p-3"><?php include('error_logs.txt'); ?></pre>
          
                  <a href="/logout.php" class="btn btn-danger">Logout</a>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>

  </body>
  <script src="https://code.jquery.com/jquery-3.3.1.slim.min.js" integrity="sha384-q8i/X+965DzO0rT7abK41JStQIAqVgRVzpbzo5smXKp4YfRvH+8abtTE1Pi6jizo" crossorigin="anonymous"></script>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.14.7/umd/popper.min.js" integrity="sha384-UO2eT0CpHqdSJQ6hJty5KVphtPhzWj9WO1clHTMGa3JDZwrnQq4sF86dIHNDz0W1" crossorigin="anonymous"></script>
  <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/js/bootstrap.min.js" integrity="sha384-JjSmVgyd0p3pXB1rRibZUAYoIIy6OrQ6VrjIEaFf/nJGzIxFDsf4x0xIM+B07jRM" crossorigin="anonymous"></script>
</html>
