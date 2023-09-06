<?php
// Include your database connection code here
$dbHost = 'localhost'; // Your database host (e.g., 'localhost')
$dbUser = 'jazy006'; // Your database username
$dbPass = '123456'; // Your database password
$dbName = 'psa_app'; // Your database name (psa_app in your case)

// Create a database connection
$conn = new mysqli($dbHost, $dbUser, $dbPass, $dbName);

// Check the connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Check if the form was submitted
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Check if the submitted form is for registration or login based on the submit button clicked
    if (isset($_POST['register'])) {
        // Registration form submitted
        // Retrieve data from the registration form
        $username = $_POST['username'];
        $password = $_POST['password'];
        $loginType = $_POST['login_type'];
        $fname = $_POST['fname'];
        $lname = $_POST['lname'];
        $company = $_POST['company'];
        $email = $_POST['email'];

        // You should perform data validation and sanitation here as needed

        // Check if the username is unique
        $checkQuery = "SELECT * FROM users WHERE username = ?";
        $stmt = $conn->prepare($checkQuery);
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows > 0) {
            // Username already exists
            echo "Username already exists. Please choose a different username.";
        } else {
            // Hash the password (you should use a more secure hashing method)
            $hashedPassword = password_hash($password, PASSWORD_DEFAULT);

            // Insert user data into the 'users' table
            $insertUserQuery = "INSERT INTO users (username, password, login_type) VALUES (?, ?, ?)";
            $stmt = $conn->prepare($insertUserQuery);
            $stmt->bind_param("sss", $username, $hashedPassword, $loginType);
            
            // Check if the user record was inserted successfully
            if ($stmt->execute()) {
                $user_id = $stmt->insert_id; // Get the user ID of the inserted record

                // Insert user data into the 'user_details' table
                $insertDetailsQuery = "INSERT INTO user_details (user_id, first_name, last_name, company_name, email) VALUES (?, ?, ?, ?, ?)";
                $stmt2 = $conn->prepare($insertDetailsQuery);
                $stmt2->bind_param("issss", $user_id, $fname, $lname, $company, $email);

                // Check if the user details were inserted successfully
                if ($stmt2->execute()) {
                    // Registration successful
                    echo "Registration successful. You can now <a href='login.html'>login</a>.";
                } else {
                    // Registration failed
                    echo "Registration failed. Please try again later.";
                }

                $stmt2->close();
            } else {
                // Registration failed
                echo "Registration failed. Please try again later.";
            }
        }

        // Close the database connection
        $stmt->close();
    } elseif (isset($_POST['login'])) {
        // Login form submitted
        // Retrieve data from the login form
        $username = $_POST['username'];
        $password = $_POST['password'];
        $loginType = $_POST['login_type'];

        // You should perform data validation and sanitation here as needed

        // Check if the username exists in the database
        $checkQuery = "SELECT * FROM users WHERE username = ?";
        $stmt = $conn->prepare($checkQuery);
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows > 0) {
            // Username exists, check the password
            $user = $result->fetch_assoc();
            if (password_verify($password, $user['password'])) {
                // Password is correct, log the user in
                // You can set a session here to maintain the login state
                session_start();
                $_SESSION['username'] = $username;
                $_SESSION['login_type'] = $loginType;

                // Redirect the user to a dashboard or another page
                header("Location: dashboard.php");
                exit;
            } else {
                // Password is incorrect
                echo "Incorrect password. Please try again.";
            }
        } else {
            // Username does not exist
            echo "Username not found. Please check your username.";
        }

        // Close the database connection
        $stmt->close();
    }

    // Close the overall database connection
    $conn->close();
}
?>
