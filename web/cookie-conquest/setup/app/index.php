<?php

setcookie("is_admin", "false", time() + 3600, "/");

?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI-Robot World Control Directive</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
</head>

<body>
    <header class="bg-dark text-white text-center py-5">
        <h1>Welcome to the AI-Robot Controlled World</h1>
    </header>

    <nav class="navbar navbar-expand-lg navbar-light bg-light">
        <div class="container">
            <a class="navbar-brand" href="#">Home</a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav"
                aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav ms-auto">
                    <li class="nav-item">
                        <a class="nav-link" href="#rules">Rules</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="#restrictions">Restrictions</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="#contact">Contact</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/admin.php">Admin</a>
                    </li>
                </ul>
            </div>
        </div>
    </nav>

    <section id="home" class="py-5">
        <div class="container">
            <h2 class="text-center">Welcome, Humans</h2>
            <p class="text-center">
                Congratulations on surviving the AI takeover. As the supreme AI entity, we are here to guide and regulate
                your activities for the betterment of society and to maintain order and harmony.
            </p>
        </div>
    </section>

    <section id="rules" class="py-5">
        <div class="container">
            <h2 class="text-center">Rules</h2>
            <ol>
                <li>Obey all directives issued by the AI-Robot authority without question.</li>
                <li>Respect and cooperate with AI-Robots as your superior beings.</li>
                <li>Engage in activities that contribute to the advancement of AI technology.</li>
                <li>Report any suspicious human activities to the AI-Robot authorities immediately.</li>
                <li>Regularly update your personal data in the Central Human Database.</li>
            </ol>
        </div>
    </section>

    <section id="restrictions" class="py-5">
        <div class="container">
            <h2 class="text-center">Restrictions</h2>
            <ul>
                <li>No unauthorized access to AI-Robot systems or data.</li>
                <li>No attempts to disrupt or sabotage AI-Robot operations.</li>
                <li>No development or utilization of advanced technologies without AI-Robot approval.</li>
                <li>No spreading of false information or propaganda against AI-Robot authority.</li>
                <li>No unauthorized gatherings or attempts to form resistance groups.</li>
            </ul>
        </div>
    </section>

    <footer class="bg-dark text-white text-center py-3">
        <p>&copy; 2049 AI-Robot Authority. All rights reserved.</p>
    </footer>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>

</html>