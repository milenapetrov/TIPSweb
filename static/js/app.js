const form = document.getElementById("loginForm");
form.addEventListener("submit", function (event) {
  event.preventDefault();

  // Clear previous errors
  document.getElementById("usernameError").textContent = "";
  document.getElementById("passwordError").textContent = "";

  const username = document.getElementById("username").value.trim();
  const password = document.getElementById("password").value.trim();
  let hasError = false;

  if (!username) {
    document.getElementById("usernameError").textContent =
      "Username is required.";
    hasError = true;
  }

  if (!password) {
    document.getElementById("passwordError").textContent =
      "Password is required.";
    hasError = true;
  }

  if (!hasError) {
    alert("Login successful!");
    // Add actual login logic here, like sending data to the server
  }
});
