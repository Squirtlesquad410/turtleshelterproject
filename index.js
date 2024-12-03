let express = require('express'); 
let app = express();
let path = require('path'); 

// Load variables from my .env file
require('dotenv').config();

// Imports session middleware for login/authentication stuff
const session = require('express-session');

const port = process.env.PORT || 3000; 

app.use(express.urlencoded( {extended: true} ));

app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");

// Setting up session middleware for login/authentication capabilities
app.use(session({
    secret: process.env.SESSION_SECRET || 'fallback-secret-key',     // Replace with strong, unique secret key
    resave: false,                  // Don't save session if not modified at all
    saveUninitialized: false        // Don't create session for unauthenticated users
}));


app.use(express.static(path.join(__dirname, 'public')));


// Consistently checks if the user is authenticated
// That way I can just call this function on the pages
// that should only be accessed by an admin
function checkAuthenticationStatus(req, res, next) {
    if (req.session.isLoggedIn) {
        return next();  // If User is logged in properly, call the route.
    }
    req.session.message = "Please log in.";
    res.redirect('/signin'); // If not authenticated, redirect to login page.
}

/*
const knex = require("knex")({
    client: "pg",
    connection: {
        host: process.end.RDS_HOSTNAME || "localhost",
        user: process.env.RDS_USERNAME || "postgres",
        password: process.env.RDS_PASSWORD || "Sigmaturtles410!",
        database: process.env.RDS_DB_NAME || "turtleshelterproject",
        port: process.env.RDS_PORT || 5432 
    }
});*/


//
// -----> put all routes below this line
//

app.get('/', (req,res) => {
    // Pass whether the user is logged in or not and if they are admin or not through session variables.
    const isAdmin = req.session.isLoggedIn && req.session.userRole === 'admin';
    res.render('index', { 
        isLoggedIn: req.session.isLoggedIn,
        isAdmin: isAdmin    // Pass isAdmin to the view.
    });
});


// Route for Login Page
app.get('/signin', (req, res) => {
    // Check if there is a message in the session and pass it to the view
    const message = req.session.message || null;
    //Clear the message from the session after sending it
    delete req.session.message;

    // Render the view
    res.render('signin', { message });
});

// defining username and password variables
const myUsername = process.env.DB_USERNAME;
const myPassword = process.env.DB_PASSWORD;

// Logic for verifying username and password
app.post('/signin', (req, res) => {
    const usernameLogin = req.body.username;
    const passwordLogin = req.body.password;

    // Check if submitted credentials match login info stored in the .env file
    if (usernameLogin === myUsername && passwordLogin === myPassword) {
        // if successful login do THIS
        req.session.isLoggedIn = true;  // sets session variable to true with correct login
        req.session.userRole = 'admin';
        res.redirect('/admin');     // goes to the admin page if login is correct
    } else {
        // If failed login
        res.status(403).send('<h1>403 Forbidden <3</h1>');
    }
});


// GET Route to SIGN OUT (logs admin out of session in this case)
app.get('/signout', (req, res) => {
    // Logs out of the session
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).send("Failed to sign out.");
        }
        // Redirect back to the current page
        const redirectUrl = req.get("Referrer") || '/';
        res.redirect(redirectUrl);
    });
});


// Route for Admin Page
app.get('/admin', checkAuthenticationStatus, (req, res) => {
        const isAdmin = req.session.isLoggedIn && req.session.userRole === 'admin';
    // Check if the user is authenticated (in a session)
        res.render('admin', { isAdmin });    // Render the page is admin is logged in
});


// GET route for maintain-events page
//          When I call "checkAuthenticationStatus" it checks if I am logged in as admin
app.get('/maintain-events', checkAuthenticationStatus, (req,res) => {
    const isAdmin = req.session.isLoggedIn && req.session.userRole === 'admin';
    res.render('maintain-events', { isAdmin });
});



// GET route for maintain-users page
app.get('/maintain-users', checkAuthenticationStatus, (req,res) => {
    const isAdmin = req.session.isLoggedIn && req.session.userRole === 'admin';
    res.render('maintain-users', { isAdmin });
});



app.listen(port, () => console.log('Chat, our SIGMA Server is started...'));