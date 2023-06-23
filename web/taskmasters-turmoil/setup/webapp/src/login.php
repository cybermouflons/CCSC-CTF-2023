<?php

    require("config.php");
    
    if(isset($_POST['submit'])) {
        $username= $_POST['username'];
        $password = $_POST['password'];   

        // Check if name has been entered
        if(empty($_POST['username'])) {
            $err= 'Username is required';
        }
        // check if a password has been entered and if it is a valid password
        else if(empty($_POST['password'])) {
            $err = 'Password is required';
        } else {
            if(login($pdo,$username,$password)){
                header("Location: /index.php");
            }
            else{
                $err="Wrong username/password <br>This action has been logged\n";
                log_error($_SERVER['HTTP_USER_AGENT'], $_SERVER['REMOTE_ADDR']);
            }
        }
    }
?>

<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta http-equiv="x-ua-compatible" content="ie=edge" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css" integrity="sha384-ggOyR0iXCbMQv3Xipma34MD+dH/1fQ784/j6cY/iJTQUOhcWr7x9JvoRxT2MZw1T" crossorigin="anonymous">
    <title>Login</title>
    <link rel="stylesheet" href="css/style.css" />
  </head>

  <body>

 
    <section class="vh-100 gradient-custom">
        <div class="container py-5 h-100">
            <div class="row d-flex justify-content-center align-items-center h-100">
                <div class="col-12 col-md-8 col-lg-6 col-xl-5">
                    <div class="card bg-dark text-white" style="border-radius: 1rem;">
                        <div class="card-body p-5 text-center">

                        <div class="mb-md-5 mt-md-4 pb-5">

                            <h2 class="fw-bold mb-2 text-uppercase">Login</h2>
                            <p class="text-white-50 mb-5">Login to your task page, and get to work!</p>
                            <form role="form" method="post" action="/login.php">
                                <div class="form-outline form-white mb-4">
                                    <input type="text" id="username" name="username" class="form-control form-control-lg"  />
                                    <label class="form-label" for="username">Username</label>
                                </div>

                                <div class="form-outline form-white mb-4">
                                    <input type="password" id="password" name="password" class="form-control form-control-lg" />
                                    <label class="form-label" for="password">Password</label>
                                </div>
                                <?php
                                    if($err){
                                    echo "<div class='mb-4'><p class='text-danger'> $err </p></div>";
                                 } 
                                ?>
                                

                                <button class="btn btn-outline-light btn-lg px-5" type="submit" name="submit">Login</button>
                            </form>

                        </div>

                        <div>
                            <p class="mb-0">Don't have an account? <a href="/register.php" class="text-white-50 fw-bold">Register</a>
                            </p>
                        </div>

                        </div>
                    </div>
                </div>
            </div>
        </div>
    </section>
    <!-- <div class="container">
      <div class="row col-12">
            <form role="form" method="post" action="/login.php">
            <div class="form-group row">
                <label for="username_input" class="col-sm-2 col-form-label">User Name</label>
                <div class="col-sm-10">
                    <input type="text" class="form-control" id="username_input" name="username" placeholder="Username">
                </div>
            </div>
            <div class="form-group row">
            <label for="inputPassword3" class="col-sm-2 col-form-label">Password</label>
            <div class="col-sm-10">
                <input type="password" class="form-control" id="inputPassword" name="password" placeholder="Password">
            </div>
            </div>
            <div class="form-group row">
            <div class="offset-sm-2 col-sm-10">
                <button type="submit" name="submit" class="btn btn-primary">Login</button>
            </div>
            </div>
            </form>
            <span>Dont have an account? <a href="/register.php">sign up</a></span>
      </div>
    </div> -->

  </body>
  <script src="https://code.jquery.com/jquery-3.3.1.slim.min.js" integrity="sha384-q8i/X+965DzO0rT7abK41JStQIAqVgRVzpbzo5smXKp4YfRvH+8abtTE1Pi6jizo" crossorigin="anonymous"></script>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.14.7/umd/popper.min.js" integrity="sha384-UO2eT0CpHqdSJQ6hJty5KVphtPhzWj9WO1clHTMGa3JDZwrnQq4sF86dIHNDz0W1" crossorigin="anonymous"></script>
  <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/js/bootstrap.min.js" integrity="sha384-JjSmVgyd0p3pXB1rRibZUAYoIIy6OrQ6VrjIEaFf/nJGzIxFDsf4x0xIM+B07jRM" crossorigin="anonymous"></script>
</html>