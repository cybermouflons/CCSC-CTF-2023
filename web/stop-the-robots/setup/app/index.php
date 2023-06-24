<!DOCTYPE html>
<html lang="en">

<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>The Last Pulse | Home</title>
  <!-- Bootstrap CSS -->
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
  <!-- Custom CSS -->
  <link rel="stylesheet" href="css/style.css">
</head>

<body>
  <!-- Navbar -->
  <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
    <div class="container">
      <a class="navbar-brand" href="#">The Last Pulse</a>
      <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav"
        aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
        <span class="navbar-toggler-icon"></span>
      </button>
      <div class="collapse navbar-collapse" id="navbarNav">
        <ul class="navbar-nav ms-auto">
          <li class="nav-item">
            <a class="nav-link" href="#story">Story</a>
          </li>
          <li class="nav-item">
            <a class="nav-link" href="#characters">Characters</a>
          </li>
          <li class="nav-item">
            <a class="nav-link" href="#gallery">Gallery</a>
          </li>
          <li class="nav-item">
            <a class="nav-link" href="#contact">Contact</a>
          </li>
        </ul>
      </div>
    </div>
  </nav>

  <!-- Hero Section -->
  <section id="hero" class="gradient-custom text-light py-5">
    <div class="container text-center ">
      <h1 class="display-4">The Last Pulse</h1>
      <p class="lead">A Cyberpunk Adventure</p>
      <a href="#story" class="btn btn-light btn-lg">Explore the Story</a>
    </div>
  </section>

  <!-- Story Section -->
  <section id="story" class="py-5">
    <div class="container">
      <div class="row">
        <div class="col-md-6">
          <h2 class="fw-bold mb-4">Our Story</h2>
          <p class="lead">In the year 2049, the once crystal-clear waters of the Mediterranean surrounding Cyprus have
            become an opaque sheet of iron, patrolled by emotionless AI in their aquatic mechanical monsters. Follow the
            tenacious and determined 21-year-old hacker Lucas as he leads a rebellion against the Singularity, a robotic
            nightmare that has engulfed the world.</p>
          <a href="#characters" class="btn btn-dark">Meet the Hackers</a>
        </div>
        <div class="col-md-6">
          <img src="images/story.png" alt="Story Image" class="img-fluid rounded">
        </div>
      </div>
    </div>
  </section>

  <!-- Characters Section -->
  <section id="characters" class="bg-light py-5">
    <div class="container">
      <h2 class="fw-bold text-center mb-4">Meet the Characters</h2>
      <div class="row">
        <div class="col-md-4">
          <div class="card">
            <img src="images/lucas.png" alt="Lucas" class="card-img-top">
            <div class="card-body">
              <h5 class="card-title">Lucas</h5>
              <p class="card-text">The tenacious and determined 21-year-old hacker leading the rebellion.<!-- Part_1 - CCSC{W3lCoM3_t0_ --></p>
            </div>
          </div>
        </div>
        <div class="col-md-4">
          <div class="card">
            <img src="images/friend1.png" alt="Friend 1" class="card-img-top">
            <div class="card-body">
              <h5 class="card-title">Alias Unknown</h5>
              <p class="card-text">A member of Lucas' ragtag band of rebels, fighting against the AI.</p>
            </div>
          </div>
        </div>
        <div class="col-md-4">
          <div class="card">
            <img src="images/friend2.png" alt="Friend 2" class="card-img-top">
            <div class="card-body">
              <h5 class="card-title">Alias Unknown</h5>
              <p class="card-text">Another member of Lucas' rebel group, skilled in cyber hacking and technology.</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  </section>

  <!-- Gallery Section -->
  <section id="gallery" class="py-5">
    <div class="container">
      <h2 class="fw-bold text-center mb-4">Gallery</h2>
      <div class="row">
        <div class="col-md-4">
          <img src="images/gallery1.png" alt="Gallery Image" class="img-fluid rounded mb-3">
        </div>
        <div class="col-md-4">
          <img src="images/gallery2.png" alt="Gallery Image" class="img-fluid rounded mb-3">
        </div>
        <div class="col-md-4">
          <img src="images/gallery3.png" alt="Gallery Image" class="img-fluid rounded mb-3">
        </div>
      </div>
    </div>
  </section>

  <!-- Contact Section -->
  <section id="contact" class="bg-dark text-light py-5">
    <div class="container">
      <h2 class="fw-bold text-center mb-4">Contact Us</h2>
      <div class="row">
        <div class="col-md-6">
          <p class="lead">Have questions or want to join the resistance? Reach out to us.</p>
          <ul class="list-unstyled">
            <li>Email: info@thelastpulse.com</li>
            <li>Phone: +1234567890</li>
          </ul>
        </div>
        <div class="col-md-6">
          <form>
            <div class="mb-3">
              <label for="name" class="form-label">Your Name</label>
              <input type="text" class="form-control" id="name" placeholder="Enter your name">
            </div>
            <div class="mb-3">
              <label for="email" class="form-label">Email address</label>
              <input type="email" class="form-control" id="email" placeholder="name@example.com">
            </div>
            <div class="mb-3">
              <label for="message" class="form-label">Message</label>
              <textarea class="form-control" id="message" rows="3" placeholder="Enter your message"></textarea>
            </div>
            <button type="submit" class="btn btn-light">Send Message</button>
          </form>
        </div>
      </div>
    </div>
  </section>

  <!-- Footer -->
  <footer class="bg-dark text-light text-center py-3">
    <p>&copy; 2023 The Last Pulse. All rights reserved.</p>
  </footer>

  <!-- Bootstrap JS -->
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>

</html>
