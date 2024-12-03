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


const knex = require("knex")({
    client: "pg",
    connection: {
        host: process.env.RDS_HOSTNAME || "localhost",
        user: process.env.RDS_USERNAME || "postgres",
        password: process.env.RDS_PASSWORD || "Sigmaturtles410!", // CHANGE BACK BEFORE PUSH
        database: process.env.RDS_DB_NAME || "turtleshelterproject",
        port: process.env.RDS_PORT || 5432,
        ssl: process.env.DB_SSL ? {rejectUnauthorized: false} : false
    }
});



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
app.get('/maintain-events', checkAuthenticationStatus, async (req, res) => {
    try {
        const isAdmin = req.session.isLoggedIn && req.session.userRole === 'admin';

        if (!isAdmin) {
            return res.status(403).send('Access denied');
        }

        // Get the current page from the query string, default to page 1
        const currentPage = parseInt(req.query.page) || 1;
        const itemsPerPage = 10; // Number of events per page

        // Extract filters from the query string
        const { address, description, organization, city, state, zip,event_date } = req.query;

        // Calculate the offset for pagination
        const offset = (currentPage - 1) * itemsPerPage;

        // Start building the base query
        let query = knex('event_info as e')
            .join('event_date_options as eo', function() {
                this.on('e.event_id', '=', 'eo.event_id')
                    .andOn('eo.date_preference_order', '=', knex.raw('?', [1]));
            })
            .join('sewing_ability as sa', 'e.sewing_ability_id', 'sa.sewing_ability_id')
            .join('venues as v', 'e.venue_id', 'v.venue_id')
            .select(
                'e.event_id',
                knex.raw("TO_CHAR(eo.event_date, 'MM-DD-YY') AS event_date"),
                'e.organization_name',
                'e.event_description',
                'e.organizer_email',
                'e.event_type',
                'e.estimated_attendance',
                'e.num_children_under_10',
                'e.num_teens',
                'e.num_help_set_up',
                'e.num_sewers',
                'sa.sewing_ability_description',
                'e.num_sewing_machines',
                'e.num_sergers',
                knex.raw("CONCAT(v.street_address, ', ', v.city, ', ', v.state, ' ', v.ZIP) AS full_address"),
                'e.notes',
                'e.event_status',
                'e.jen_story',
                'e.contribute_materials_cost'
            )
            .limit(itemsPerPage)
            .offset(offset);

        // Apply filters if they exist
        if (address) {
            query = query.whereRaw('LOWER(v.street_address) LIKE ?', [`%${address.toLowerCase()}%`]);
        }
        if (description) {
            query = query.whereRaw('LOWER(e.event_description) LIKE ?', [`%${description.toLowerCase()}%`]);
        }
        if (organization) {
            query = query.whereRaw('LOWER(e.organization_name) LIKE ?', [`%${organization.toLowerCase()}%`]);
        }
        if (city) {
            query = query.whereRaw('LOWER(v.city) LIKE ?', [`%${city.toLowerCase()}%`]);
        }
        if (state) {
            query = query.whereRaw('LOWER(v.state) LIKE ?', [`%${state.toLowerCase()}%`]);
        }
        if (zip) {
            query = query.whereRaw('v.ZIP LIKE ?', [`%${zip}%`]);
        }
        if (event_date) {
            // Ensure the date is in the format YYYY-MM-DD for comparison
            query = query.whereRaw('TO_CHAR(eo.event_date, \'YYYY-MM-DD\') = ?', [event_date]);
        }

        // Execute the query to fetch the filtered and paginated events
        const events = await query;

        // Query the total number of events for pagination controls, applying the same filters
        let countQuery = knex('event_info as e')
            .join('event_date_options as eo', function() {
                this.on('e.event_id', '=', 'eo.event_id')
                    .andOn('eo.date_preference_order', '=', knex.raw('?', [1]));
            })
            .join('venues as v', 'e.venue_id', 'v.venue_id')
            .join('sewing_ability as sa', 'e.sewing_ability_id', 'sa.sewing_ability_id')
            .count('e.event_id as count');

        if (address) {
            countQuery = countQuery.whereRaw('LOWER(v.street_address) LIKE ?', [`%${address.toLowerCase()}%`]);
        }
        if (description) {
            countQuery = countQuery.whereRaw('LOWER(e.event_description) LIKE ?', [`%${description.toLowerCase()}%`]);
        }
        if (organization) {
            countQuery = countQuery.whereRaw('LOWER(e.organization_name) LIKE ?', [`%${organization.toLowerCase()}%`]);
        }
        if (city) {
            countQuery = countQuery.whereRaw('LOWER(v.city) LIKE ?', [`%${city.toLowerCase()}%`]);
        }
        if (state) {
            countQuery = countQuery.whereRaw('LOWER(v.state) LIKE ?', [`%${state.toLowerCase()}%`]);
        }
        if (zip) {
            countQuery = countQuery.whereRaw('v.ZIP LIKE ?', [`%${zip}%`]);
        }
        if (event_date) {
            countQuery = countQuery.whereRaw('TO_CHAR(eo.event_date, \'YYYY-MM-DD\') = ?', [event_date]);
        }

        const totalEvents = await countQuery.first();
        const totalPages = Math.ceil(totalEvents.count / itemsPerPage);

        // Render the maintain-events page with events, pagination data, and filter values
        res.render('maintain-events', {
            isAdmin,
            events,
            currentPage,
            totalPages,
            addressFilter: address,
            descriptionFilter: description,
            organizationFilter: organization,
            cityFilter: city,
            stateFilter: state,
            zipFilter: zip,
            dateFilter: event_date
        });
    } catch (err) {
        console.error('Error fetching events:', err);
        res.status(500).send('An error occurred while fetching events.');
    }
});





// GET route for maintain-users page
app.get('/maintain-users', checkAuthenticationStatus, (req,res) => {
    const isLoggedIn = req.session.isLoggedIn || false;
    const isAdmin = req.session.isLoggedIn && req.session.userRole === 'admin';
    res.render('maintain-users', { isLoggedIn, isAdmin });
});

// GET route for Event Request Form page (for volunteers)
app.get('/request-an-event', (req,res) => {
    const isLoggedIn = req.session.isLoggedIn || false;
    const isAdmin = req.session.userRole === 'admin';
    
    res.render('request-an-event', { 
        isLoggedIn: isLoggedIn,
        isAdmin: isAdmin 
    });
});


// GET route for volunteer.ejs view
app.get('/volunteer', (req, res) => {
    const isLoggedIn = req.session.isLoggedIn || false;
    const isAdmin = req.session.userRole === 'admin';

    res.render('volunteer', {
        isLoggedIn: isLoggedIn,
        isAdmin: isAdmin
    });
});



app.listen(port, () => console.log('Chat, our SIGMA Server is started...'));