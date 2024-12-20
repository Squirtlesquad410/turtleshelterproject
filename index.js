let express = require('express'); 
let app = express();
let path = require('path'); 
let moment = require('moment'); // Use moment.js for date/time formatting


// Load variables from my .env file
require('dotenv').config();

// Imports session middleware for login/authentication stuff
const session = require('express-session');

const port = process.env.PORT || 3000; 

app.use(express.urlencoded( {extended: true} ));
app.use(express.json()); // Parses JSON payloads

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
        host: "awseb-e-wx74xhj2vt-stack-awsebrdsdatabase-dbcyxq8zvwk9.c3okg6w2omlf.us-west-2.rds.amazonaws.com",
        user: "postgres",
        password: "Sigmaturtles410!", 
        database: "turtleshelterproject",
        port: 5432,
        ssl: { rejectUnauthorized: false, }
    },
});


const bcrypt = require('bcryptjs');


const hashPassword = async (plainTextPassword) => {
  const saltRounds = 10; // Higher = more secure but slower
  const hashedPassword = await bcrypt.hash(plainTextPassword, saltRounds);
  return hashedPassword;
};

//
// -----> put all routes below this line
//

app.get('/jen', (req,res) => {
    const isLoggedIn = req.session.isLoggedIn || false;
    const isAdmin = req.session.userRole === 'admin';
    res.render("jen", { isLoggedIn, isAdmin });
});
app.get('/about-us', (req,res) => {
    const isLoggedIn = req.session.isLoggedIn || false;
    const isAdmin = req.session.userRole === 'admin';
    res.render("about-us", { isLoggedIn, isAdmin });
});

app.get('/donate', (req,res) => {
    const isLoggedIn = req.session.isLoggedIn || false;
    const isAdmin = req.session.userRole === 'admin';
    res.render("donate", { isLoggedIn, isAdmin });
});



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
    const isAdmin = req.session.isLoggedIn && req.session.userRole === 'admin';
    const isLoggedIn = req.session.isLoggedIn || false;
    const message = req.session.message || null;
    //Clear the message from the session after sending it
    delete req.session.message;

    // Render the view
    res.render('signin', { message, isAdmin, isLoggedIn });
});


// Logic for verifying username and password
app.post('/signin', async (req, res) => {
    const usernameLogin = req.body.username;
    const passwordLogin = req.body.password;

    try {
        // First, check admin users
        const admin = await knex('admins').where('username', usernameLogin).first();

        if (admin) {
            // Compare the provided password with the hashed password for admin
            const isPasswordCorrect = await bcrypt.compare(passwordLogin, admin.hashed_password);

            if (isPasswordCorrect) {
                // If admin login is successful
                req.session.isLoggedIn = true;
                req.session.userRole = 'admin';
                req.session.isAdmin = true;
                req.session.username = admin.username;
                req.session.email=admin.email
                return res.redirect('/admin');
            }
        }

        // If not an admin, check regular users
        const user = await knex('users').where('username', usernameLogin).first();

        if (user) {
            // Compare the provided password with the hashed password for user
            const isPasswordCorrect = await bcrypt.compare(passwordLogin, user.hashed_password);

            if (isPasswordCorrect) {
                // If user login is successful
                req.session.isLoggedIn = true;
                
                req.session.userRole = 'user';
                req.session.username = user.username;
                req.session.email=user.email
                return res.redirect('/');
            }
        }

        // If no matching user found in either admin or users table
        req.session.message = 'Invalid username or password.';
        res.redirect('/signin');

    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).send('Internal Server Error');
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
        const isLoggedIn = req.session.isLoggedIn || false;
    // Check if the user is authenticated (in a session)
        res.render('admin', { isAdmin, isLoggedIn });    // Render the page is admin is logged in
});


// route for upcoming events
app.get('/upcoming-events',  async (req, res) => {
    const isUser = req.session.isLoggedIn && req.session.userRole === 'user';
    const isLoggedIn = req.session.isLoggedIn || false;


    const isAdmin = req.session.isLoggedIn && req.session.userRole === 'admin';
    const currentDate = moment().format('YYYY-MM-DD');
    const nextMonthDate = moment().add(1, 'month').format('YYYY-MM-DD');
    // Fetch events for the next month
    const events = await knex('event_info as e').join('event_date_options as eo', function() {
        this.on('e.event_id', '=', 'eo.event_id')
            .andOn('eo.date_preference_order', '=', knex.raw('?', [1]));
        })
            .join('venues as v', 'e.venue_id', 'v.venue_id')
            .leftJoin('volunteer_participation as vp', 'e.event_id', 'vp.event_id') // Join for counting
    
        .select(
            'e.event_id',
            'e.event_description',
            knex.raw("TO_CHAR(eo.event_date, 'MM-DD-YY') AS event_date"),
            knex.raw("TO_CHAR(eo.start_time, 'HH12:MI am') AS start_time"),
            knex.raw("TO_CHAR(eo.end_time, 'HH12:MI am') AS end_time"),
            knex.raw(
                "CONCAT(street_address, ', ', city, ', ', state, ' ', zip) AS full_address"
            ),
            'v.city',
            knex.raw('COUNT(vp.vol_id) as volunteer_count') // Count of volunteers per event
            )
            .whereBetween('eo.event_date', [currentDate, nextMonthDate])
            .where('event_status','approved')
            .groupBy(
                'e.event_id',
                'e.event_description',
                'eo.event_date',
                'eo.start_time',
                'eo.end_time',
                'v.city',
                'v.street_address',
                'v.state',
                'v.zip'
            )
        
    try {
        
        
        const { email } = req.session;
        if (isUser){
        const volunteer = await knex('volunteer_info')
        .select('vol_id')
        .where('vol_email', email)
        .first();
    
        const vol_id = volunteer?.vol_id;
        
        // Check which events the volunteer has joined
        for (let event of events) {
            if (vol_id) {
                const participation = await knex('volunteer_participation')
                    .where({ vol_id, event_id: event.event_id })
                    .first();
                event.isJoined = !!participation; // true if participation exists
            } else {
                event.isJoined = false; // Not logged in, default to false
            }
        }
    }
    

        // Add additional formatting and flags for the frontend
        const formattedEvents = events.map(event => ({
            ...event,
            date_formatted: moment(event.event_date).format('MMMM DD, YYYY'), // Use event_event_date
            start_time_formatted: moment(event.start_time, 'HH:mm:ss').format('h:mm A'),
            end_time_formatted: moment(event.end_time, 'HH:mm:ss').format('h:mm A'),
        }));

        // Get unique cities for filtering
        const cities = [...new Set(events.map(event => event.city))];

        res.render('upcoming-events', {
            events: formattedEvents,
            cities,
            isUser,
            isLoggedIn,
            isAdmin
            
             // Pass session for login status check
        });
    } catch (err) {
        console.error('Error fetching upcoming events:', err);
        res.status(500).send('Internal Server Error');
    }
});

// post route to join event
app.post('/join-event', async (req, res) => {
    try {
        const { email } = req.session;
        const { eventId } = req.body;
        if (!email) {
            return res.status(401).send(email);
        }

        const volunteer = await knex('volunteer_info')
    .select('vol_id')
    .where('vol_email', email)
    .first();
    
    const vol_id = volunteer?.vol_id;
        if (!vol_id) {
            return res.status(404).send('Volunteer not found. Please log in.');
        }
        if (!eventId) {
            return res.status(400).send('Event ID is required.');
        }
        
        // Check if the user is already signed up for the event
        const existingParticipation = await knex('volunteer_participation')
            .where({ vol_id, event_id: eventId })
            .first();

        if (existingParticipation) {
            return res.status(400).send('You have already joined this event.');
        }

        // Insert the new participation record
        await knex('volunteer_participation').insert({
            vol_id,
            event_id: eventId,
        });

        res.status(200).send('Successfully joined the event.');
    } catch (err) {
        console.error('Error joining event:', err);
        res.status(500).send('Internal Server Error');
    }
});

app.post('/withdraw-event', async (req, res) => {
    try {
        // Retrieve volunteer ID from the session
        const { email } = req.session;
        const vol = await knex('volunteer_info').select('vol_id').where('vol_email', email).first();

        if (!vol) {
            return res.status(401).send('Unauthorized. Please log in.');
        }

        const { eventId } = req.body;
        if (!eventId) {
            return res.status(400).send('Event ID is missing.');
        }

        // Delete participation record
        const result = await knex('volunteer_participation')
            .where({ vol_id: vol.vol_id, event_id: eventId })
            .del();

        if (result) {
            res.status(200).send('Successfully withdrew from the event.');
        } else {
            res.status(404).send('Participation record not found.');
        }
    } catch (err) {
        console.error('Error withdrawing from event:', err);
        res.status(500).send('Internal Server Error');
    }
});


// Route for Add Admin Page
app.get('/add-admin', checkAuthenticationStatus, (req, res) => {
    const isAdmin = req.session.isLoggedIn && req.session.userRole === 'admin';
    const isLoggedIn = req.session.isLoggedIn || false;
    let errorMessage= null
    res.render('add-admin', { errorMessage, isAdmin, isLoggedIn });
});


// Route to add new admin to database
app.post('/add-admin', async (req, res) => {
    const isAdmin = req.session.isLoggedIn && req.session.userRole === 'admin';
    const isLoggedIn = req.session.isLoggedIn || false;
    try {
        // Extract data from the form
        const { email, first_name, last_name, username, password } = req.body;

        // Check for existing user with the same email or username
        const existingAdminOrUser = async (email, username) => {
            try {
                // Check in the admins table
                const adminMatch = await knex('admins')
                    .where('email', email)
                    .orWhere('username', username)
                    .first();
        
                // Check in the users table
                const userMatch = await knex('users')
                    .where('email', email)
                    .orWhere('username', username)
                    .first();
        
                // Return true if a match is found in either table
                return adminMatch || userMatch;
            } catch (error) {
            console.error('Error checking for existing admin or user:', error);
            throw error;
        }
    };
    const existingRecord = await existingAdminOrUser(email,username);
        
    
        if (existingRecord) {
            // Email or username already exists
            let errorMessage = 'An account with this ';
            if (existingRecord.email === email) {
                errorMessage += 'email ';
            }
            if (existingRecord.username === username) {
                errorMessage += (errorMessage.includes('email') ? 'and ' : '') + 'username ';
            }
            errorMessage += 'already exists. Please try again with different credentials.';
            
            return res.status(400).render('add-admin', { 
                errorMessage,isAdmin, isLoggedIn
            });
        }
        // Hash the password
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        // Insert into the database
        await knex('admins').insert({
            email,
            first_name,
            last_name,
            username,
            hashed_password: hashedPassword
        });

        // Redirect to the admin page or confirmation
        res.redirect('/admin');
    } catch (error) {
        console.error('Error adding admin:', error);
        res.status(500).send('Internal Server Error');
    }
});

// Route for Add user Page
app.get('/add-user', checkAuthenticationStatus, (req, res) => {
    const isAdmin = req.session.isLoggedIn && req.session.userRole === 'admin';
    const isLoggedIn = req.session.isLoggedIn || false;
    let errorMessage= null
    res.render('add-user', { errorMessage, isAdmin, isLoggedIn });
});

app.post('/add-user', async (req, res) => {
    const isAdmin = req.session.isLoggedIn && req.session.userRole === 'admin';
    const isLoggedIn = req.session.isLoggedIn || false;
    try {
        // Extract data from the form
        const { email, first_name, last_name, username, password } = req.body;

        // Check for existing user with the same email or username
        // Check for existing user with the same email or username
        const existingAdminOrUser = async (email, username) => {
            try {
                // Check in the admins table
                const adminMatch = await knex('admins')
                    .where('email', email)
                    .orWhere('username', username)
                    .first();
        
                // Check in the users table
                const userMatch = await knex('users')
                    .where('email', email)
                    .orWhere('username', username)
                    .first();
        
                // Return true if a match is found in either table
                return adminMatch || userMatch;
            } catch (error) {
            console.error('Error checking for existing admin or user:', error);
            throw error;
        }
    };
            const existingRecord = await existingAdminOrUser(email,username);
    
        if (existingRecord) {
            // Email or username already exists
            let errorMessage = 'An account with this ';
            if (existingRecord.email === email) {
                errorMessage += 'email ';
            }
            if (existingRecord.username === username) {
                errorMessage += (errorMessage.includes('email') ? 'and ' : '') + 'username ';
            }
            errorMessage += 'already exists. Please try again with different credentials.';
            
            return res.status(400).render('add-user', { 
                errorMessage,isAdmin, isLoggedIn
            });
        }
        // Hash the password
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        // Insert into the database
        await knex('users').insert({
            email,
            first_name,
            last_name,
            username,
            hashed_password: hashedPassword
        });

        // Redirect to the admin page or confirmation
        res.redirect('/maintain-users');
    } catch (error) {
        console.error('Error adding user:', error);
        res.status(500).send('Internal Server Error');
    }
});
// GET route for edit-admin.ejs
app.get('/edit-user/:id', checkAuthenticationStatus, (req, res) => {
    const isLoggedIn = req.session.isLoggedIn || false;
    const isAdmin = req.session.isLoggedIn && req.session.userRole === 'admin';

    knex.select("email",
                "first_name",
                "last_name",
                "username"
                )
        .from("users")
        .where("email", req.params.id)
        .then(users => {
            res.render('edit-user', { isLoggedIn, isAdmin, users });
        }).catch(err => {
            console.log(err);
            res.status(500).json({err});
        });
});

// POST route for edit-admin.ejs
app.post('/edit-user/:id', async  (req, res) => {
    try {
        const id = req.params.id;

        // Extract updated values from the request body
        const {
            email,
            first_name,
            last_name,
            username
        } = req.body;

        // Update the user's details in the database
        await knex('users')
            .where('email', id)
            .update({
                email,
                first_name,
                last_name,
                username
            });

        // Redirect to a success page or back to the user list
        res.redirect('/maintain-users'); // Adjust the redirection as needed
    } catch (err) {
        console.error('Error updating user:', err);
        res.status(500).send('An error occurred while updating the user.');
    }
});


// GET route for maintain-events page
//          When I call "checkAuthenticationStatus" it checks if I am logged in as admin
app.get('/maintain-events', checkAuthenticationStatus, async (req, res) => {
    try {
        const isLoggedIn = req.session.isLoggedIn || false;
        const isAdmin = req.session.isLoggedIn && req.session.userRole === 'admin';

        // Get the current page from the query string, default to page 1
        const currentPage = parseInt(req.query.page) || 1;
        const itemsPerPage = 10; // Number of events per page

        // Extract filters from the query string
        const { address, description, organization, city, state, zip, event_date, event_status } = req.query;

        // Calculate the offset for pagination
        const offset = (currentPage - 1) * itemsPerPage;

        // Subquery to aggregate items produced
        const itemsSubquery = knex('items_produced')
            .select('event_id')
            .select(
                knex.raw(`
                    json_agg(
                        json_build_object(
                            'item_description', item_description, 
                            'quantity', quantity
                        )
                    ) as items_produced
                `)
            )
            .groupBy('event_id');

        // Start building the base query
        let query = knex('event_info as e')
            .join('event_date_options as eo', function() {
                this.on('e.event_id', '=', 'eo.event_id')
                    .andOn('eo.date_preference_order', '=', knex.raw('?', [1]));
            })
            .join('sewing_ability as sa', 'e.sewing_ability_id', 'sa.sewing_ability_id')
            .join('venues as v', 'e.venue_id', 'v.venue_id')
            .leftJoin(itemsSubquery.as('ip'), 'e.event_id', 'ip.event_id')
            .select(
                'e.event_id',
                knex.raw("TO_CHAR(eo.event_date, 'MM-DD-YY') AS event_date"),
                knex.raw("TO_CHAR(eo.start_time, 'HH12:MI am') AS start_time"),
                knex.raw("TO_CHAR(eo.end_time, 'HH12:MI am') AS end_time"),
                'e.organization_name',
                'e.event_description',
                'e.organizer_first_name',
                'e.organizer_last_name',
                'e.organizer_phone',
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
                'e.contribute_materials_cost',
                'ip.items_produced'
            )
            .orderBy('eo.event_date')
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
        if (event_status) {
            query = query.whereRaw('LOWER(e.event_status) LIKE ?', [`%${event_status.toLowerCase()}%`]);
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
        if (event_status) {
            countQuery = countQuery.whereRaw('LOWER(e.event_status) LIKE ?', [`%${event_status.toLowerCase()}%`]);
        }

        const totalEvents = await countQuery.first();
        const totalPages = Math.ceil(totalEvents.count / itemsPerPage);

        // Render the maintain-events page with events, pagination data, and filter values
        res.render('maintain-events', {
            isLoggedIn,
            isLoggedIn,
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
            dateFilter: event_date,
            eventStatusFilter: event_status
        });
    } catch (err) {
        console.error('Error fetching events:', err);
        res.status(500).send('An error occurred while fetching events.');
    }
});


// GET route for add-event.ejs
app.get('/add-event', checkAuthenticationStatus, (req, res) => {
    const isLoggedIn = req.session.isLoggedIn || false;
    const isAdmin = req.session.isLoggedIn && req.session.userRole === 'admin';
    res.render('add-event', { isLoggedIn, isAdmin });
});




// GET route to edit an event
app.get('/edit-event/:id', checkAuthenticationStatus, (req, res) => {
    const isLoggedIn = req.session.isLoggedIn || false;
    const isAdmin = req.session.isLoggedIn && req.session.userRole === 'admin';
    const id = req.params.id;
    // Fetch the main event info
    knex('event_info')
        .where('event_id', id)
        .first()
        .then(events => {
            if (!events) {
                return res.status(404).send('Event not found');
            }
            // Fetch the venue and event_date_options in parallel
            return Promise.all([
                knex('venues').where('venue_id', events.venue_id).first(),
                knex('event_date_options').where('event_id', events.event_id),
                knex('items_produced').where('event_id', events.event_id)
            ]).then(([venues, event_date_options, items_produced]) => {
             // Transform items_produced into an object for easy access in template
                const itemsProducedObj = {};
                items_produced.forEach(item => {
                    itemsProducedObj[item.item_description.toLowerCase()] = item.quantity;
                });
                // Render the edit-event form with all required data
                res.render('edit-event', {
                    isLoggedIn,
                    isAdmin,
                    events,
                    venues,
                    event_date_options,
                    items_produced: itemsProducedObj
                });
            });
        })
        .catch(error => {
            console.error('Error fetching data:', error);
            res.status(500).send('Internal Server Error');
        });
});
app.post('/edit-event/:id', checkAuthenticationStatus, (req, res) => {
    const eventId = req.params.id;
    const {
        event_description,
        organization_name,
        organizer_first_name,
        organizer_last_name,
        organizer_phone,
        organizer_email,
        street_address,
        city,
        state,
        zip,
        space_size,
        event_type,
        event_date,
        start_time,
        end_time,
        estimated_attendance,
        num_children_under_10,
        num_teens,
        num_help_set_up,
        num_sewers,
        sewing_ability_id,
        num_sewing_machines,
        num_sergers,
        jen_story,
        contribute_materials_cost,
        event_status,
        notes,
        pockets_quantity,
        collars_quantity,
        envelopes_quantity,
        vests_quantity
    } = req.body;
    
    const itemsToInsert = [];
    const itemTypes = [
        { name: 'Pockets', quantity: pockets_quantity },
        { name: 'Collars', quantity: collars_quantity },
        { name: 'Envelopes', quantity: envelopes_quantity },
        { name: 'Vests', quantity: vests_quantity }
    ];
    // First, update event_info table
    knex('event_info')
        .where('event_id', eventId)
        .update({
            event_description,
            organization_name,
            organizer_first_name,
            organizer_last_name,
            organizer_phone,
            organizer_email,
            event_type,
            estimated_attendance,
            num_children_under_10,
            num_teens,
            num_help_set_up,
            num_sewers,
            sewing_ability_id,
            num_sewing_machines,
            num_sergers,
            jen_story: jen_story ? 'Y' : 'N',
            contribute_materials_cost: contribute_materials_cost ? 'Y' : 'N',
            event_status,
            notes,

        })
        .then(() => {
            // Get the venue_id from the event_info record
            return knex('event_info')
                .where('event_id', eventId)
                .select('venue_id')
                .first();
                
        })
        .then(() => {
            return knex('items_produced')
                .where('event_id', eventId)
                .del();
        })
        .then(() => {
            // Insert new items with non-zero quantities
            const itemsToInsert = itemTypes
                .filter(item => item.quantity > 0)
                .map(item => ({
                    event_id: eventId,
                    item_description: item.name,
                    quantity: item.quantity
                }));

            // Only insert if there are items to insert
            if (itemsToInsert.length > 0) {
                return knex('items_produced').insert(itemsToInsert);
            }
        })
        .then(event => {
            if (event && event.venue_id) {
                const venueId = event.venue_id;

                // Update the venues table
                return knex('venues')
                    .where('venue_id', venueId)
                    .update({
                        street_address,
                        city,
                        state,
                        zip,
                        space_size
                    });
            } 
            
        })
        .then(() => {
            // Optionally update the event_date_options table
            if (event_date || start_time || end_time) {
                // Check if a record exists for this event in the event_date_options table
                return knex('event_date_options')
                    .where('event_id', eventId)
                    .first()
                    .then(existingRecord => {
                        if (existingRecord) {
                            // Update the record if it exists
                            return knex('event_date_options')
                                .where('event_id', eventId)
                                .update({
                                    event_date,
                                    start_time,
                                    end_time
                                });
                        } else {
                            // Insert a new record if it doesn't exist
                            return knex('event_date_options').insert({
                                event_id: eventId,
                                event_date,
                                start_time,
                                end_time
                            });
                        }
                    });
            }
        })
        .then(() => {
            // After all updates are successful, redirect or render a success page
            res.redirect('/maintain-events');
        })
        .catch(error => {
            console.error('Error:', error);
            res.status(500).send('An error occurred while updating the event');
        });
});




// POST route to delete an event
app.post('/delete-event/:id', (req, res) => {
    const event_id = req.params.id;
  
    knex('event_info')
      .where('event_id', event_id)
      .del() // Deletes the event with the specified ID
      .then(() => {
        res.redirect('/maintain-events'); // Redirect to a relevant page after deletion
      })
      .catch(error => {
        console.error('Error deleting event:', error);
        res.status(500).send('Internal Server Error');
      });
  });

  // get request for maintain-users page
  app.get('/maintain-users', checkAuthenticationStatus, async (req,res) => {
    try {
        const isLoggedIn = req.session.isLoggedIn || false;
        const isAdmin = req.session.isLoggedIn && req.session.userRole === 'admin';

        // Get the current page from the query string, default to page 1
        const currentPage = parseInt(req.query.page) || 1;
        const itemsPerPage = 10; // Number of events per page

        // Extract filters from the query string
        const { first_name,
            last_name,
            email,
            username,
            } = req.query;


        // Start building the base query
        let query = knex('admins as a')
            .select(
                'a.admin_id as id',
                'a.first_name',
                'a.last_name',
                'a.email',
                'a.username',
                knex.raw('\'admin\' as role')
            )
            .union([knex.from('users as u')
            .select(
                'u.user_id as id',
                'u.first_name',
                'u.last_name',
                'u.email',
                'u.username',
                knex.raw('\'user\' as role')
            )])
            .limit(itemsPerPage)
            .offset((currentPage - 1) * itemsPerPage);
            
            

        // Execute the query to fetch the filtered and paginated events
        const admins = await query;

        // Now adjust the count query to include both tables
        let countQuery = knex('admins as a')
        .union([
            knex('users as u')
                .select('u.user_id') // Just a placeholder column for count
        ])
        .count('* as count');

        // Get the total count of users and admins
        const totalCountResult = await countQuery.first();
        const totalCount = totalCountResult.count;

        // Calculate total pages
        const totalPages = Math.ceil(totalCount / itemsPerPage);

        // Render the maintain-events page with events, pagination data, and filter values
        res.render('maintain-users', {
            isLoggedIn,
            isLoggedIn,
            isAdmin,
            admins,
            currentPage,
            totalPages
        });
    } catch (err) {
        console.error('Error fetching admins:', err);
        res.status(500).send('An error occurred while fetching admins.');
    }
});

// POST route to delete a user


  // POST route to delete a user
app.post('/delete-user/:id', (req, res) => {
    const email = req.params.id;
  
    knex('users')
      .where('email', email)
      .del() // Deletes the user with the specified ID
      .then(() => {
        res.redirect('/maintain-users'); // Redirect to a relevant page after deletion
      })
      .catch(error => {
        console.error('Error deleting user:', error);
        res.status(500).send('Internal Server Error');
      });
  });

// GET route for maintain-volunteers page
app.get('/maintain-volunteers', checkAuthenticationStatus, async (req,res) => {
    try {
        const isLoggedIn = req.session.isLoggedIn || false;
        const isAdmin = req.session.isLoggedIn && req.session.userRole === 'admin';

        // Get the current page from the query string, default to page 1
        const currentPage = parseInt(req.query.page) || 1;
        const itemsPerPage = 10; // Number of events per page

        // Extract filters from the query string
        const { vol_first_name,
            vol_last_name,
            city,
            willing_to_teach_sewing,
            willing_to_lead } = req.query;


        // Convert 'true' / 'false' string to boolean so my filters can work
        const willing_to_teach_sewingFilter = willing_to_teach_sewing === 'true' ? true : willing_to_teach_sewing === 'false' ? false : undefined;
        const willing_to_leadFilter = willing_to_lead === 'true' ? true : willing_to_lead === 'false' ? false : undefined;
        
        // Calculate the offset for pagination
        const offset = (currentPage - 1) * itemsPerPage;

        // Start building the base query
        let query = knex('volunteer_info as v')
            .join('sewing_ability as sa', 'v.sewing_ability_id', 'sa.sewing_ability_id')
            .select(
                'v.vol_id',
                'v.vol_first_name',
                'v.vol_last_name',
                'v.vol_email',
                'v.vol_phone',
                'v.street_address',
                'v.city',
                'v.state',
                'v.zip',
                'sa.sewing_ability_description',
                'v.willing_to_teach_sewing',
                'v.willing_to_lead',
                'v.finding_source',
                'v.monthly_hours_available'
            )
            .orderBy('v.vol_last_name')
            .limit(itemsPerPage)
            .offset(offset);

        // Apply filters if they exist
        if (vol_first_name) {
            query = query.whereRaw('LOWER(v.vol_first_name) LIKE ?', [`%${vol_first_name.toLowerCase()}%`]);
        }
        if (vol_last_name) {
            query = query.whereRaw('LOWER(v.vol_last_name) LIKE ?', [`%${vol_last_name.toLowerCase()}%`]);
        }
        if (city) {
            query = query.whereRaw('LOWER(v.city) LIKE ?', [`%${city.toLowerCase()}%`]);
        }
        if (willing_to_teach_sewingFilter !== undefined) {
            query = query.where('v.willing_to_teach_sewing', willing_to_teach_sewingFilter);
        }
        if (willing_to_leadFilter !== undefined) {
            query = query.where('v.willing_to_lead', willing_to_leadFilter);
        }

        // Execute the query to fetch the filtered and paginated events
        const volunteers = await query;

        // Query the total number of events for pagination controls, applying the same filters
        let countQuery = knex('volunteer_info as v')
            .join('sewing_ability as sa', 'v.sewing_ability_id', 'sa.sewing_ability_id')
            .count('v.vol_id as count');

            if (vol_first_name) {
                countQuery = countQuery.whereRaw('LOWER(v.vol_first_name) LIKE ?', [`%${vol_first_name.toLowerCase()}%`]);
            }
            if (vol_last_name) {
                countQuery = countQuery.whereRaw('LOWER(v.vol_last_name) LIKE ?', [`%${vol_last_name.toLowerCase()}%`]);
            }
            if (city) {
                countQuery = countQuery.whereRaw('LOWER(v.city) LIKE ?', [`%${city.toLowerCase()}%`]);
            }
            if (willing_to_teach_sewingFilter !== undefined) {
                countQuery = countQuery.where('v.willing_to_teach_sewing', willing_to_teach_sewingFilter);
            }
            if (willing_to_leadFilter !== undefined) {
                countQuery = countQuery.where('v.willing_to_lead', willing_to_leadFilter);
            }

        const totalVolunteers = await countQuery.first();
        const totalPages = Math.ceil(totalVolunteers.count / itemsPerPage);

        // Render the volunteers page with events, pagination data, and filter values
        res.render('maintain-volunteers', {
            isLoggedIn,
            isLoggedIn,
            isAdmin,
            volunteers,
            currentPage,
            totalPages,
            first_nameFilter: vol_first_name,
            last_nameFilter: vol_last_name,
            cityFilter: city,
            willing_to_leadFilter: willing_to_lead,
            willing_to_teach_sewingFilter: willing_to_teach_sewing,
        });
    } catch (err) {
        console.error('Error fetching volunteers:', err);
        res.status(500).send('An error occurred while fetching volunteers.');
    }
});

// POST route to delete a volunteer
app.post('/delete-volunteer/:id', (req, res) => {
    const vol_id = req.params.id;
  
    knex('volunteer_info')
      .where('vol_id', vol_id)
      .del() // Deletes the adminwith the specified ID
      .then(() => {
        res.redirect('/maintain-volunteers'); // Redirect to a relevant page after deletion
      })
      .catch(error => {
        console.error('Error deleting volunteer:', error);
        res.status(500).send('Internal Server Error');
      });
  });

// GET route for Event Request Form page (for volunteers)
app.get('/request-an-event', (req, res) => {
    const isLoggedIn = req.session.isLoggedIn || false;
    const isAdmin = req.session.userRole === 'admin';
    res.render('request-an-event',{isLoggedIn,isAdmin});
});

// POST route for Event Requests Form Page
app.post('/request-an-event', async (req, res) => {  
        const {
            street_address,
            city,
            state,
            zip,
            space_size,
            organization_name,
            event_description,
            organizer_first_name,
            organizer_last_name,
            organizer_phone,
            organizer_email,
            event_type,
            estimated_attendance,
            num_children_under_10,
            num_teens,
            num_help_set_up,
            num_sewers,
            sewing_ability_id,
            num_sewing_machines,
            num_sergers,
            jen_story,
            contribute_materials_cost,
            
            event_date,
            start_time,
            end_time,
            notes
        } = req.body;
    
    const event_status='pending'
    const date_preference_order=1
        try {
            await knex.transaction(async (trx) => {
                // Step 1: Insert into the venues table
                const [insertedVenue] = await trx('venues')
                    .insert({
                        street_address,
                        city,
                        state,
                        zip: parseInt(zip),
                        space_size: space_size
                    })
                    .returning('venue_id'); // Adjust based on your table schema
    
                const venue_id = typeof insertedVenue === 'object' ? insertedVenue.venue_id : insertedVenue;
    
                // Step 2: Insert into the event_info table
                const [insertedEvent] = await trx('event_info')
                    .insert({
                        venue_id, // Reference the new venue_id
                        organization_name,
                        event_description,
                        organizer_first_name,
                        organizer_last_name,
                        organizer_phone,
                        organizer_email,
                        event_type,
                        estimated_attendance: parseInt(estimated_attendance),
                        num_children_under_10: parseInt(num_children_under_10),
                        num_teens: parseInt(num_teens),
                        num_help_set_up: parseInt(num_help_set_up),
                        num_sewers: parseInt(num_sewers),
                        sewing_ability_id: parseInt(sewing_ability_id),
                        num_sewing_machines,
                        num_sergers,
                        jen_story: jen_story === 'Yes',
                        contribute_materials_cost,
                        event_status,
                        notes
                    })
                    .returning('event_id');
    
                console.log('Event Created:', insertedEvent);
    
                // Step 3: Insert into the event_date_options table
                await trx('event_date_options').insert({
                    event_id: typeof insertedEvent === 'object' ? insertedEvent.event_id : insertedEvent,
                    event_date,
                    start_time,
                    end_time,
                    date_preference_order,
                });
            });
    
            res.redirect('/');
        } catch (error) {
            console.error('Error creating event:', error);
            res.status(500).send('Internal Server Error');
        }
    });
    


// GET route for volunteer.ejs view
app.get('/volunteer', (req, res) => {
    const isLoggedIn = req.session.isLoggedIn || false;
    const isAdmin = req.session.userRole === 'admin';
    let errorMessage= null
    res.render('volunteer', { errorMessage,
        isLoggedIn: isLoggedIn,
        isAdmin: isAdmin
    });
});
app.post('/volunteer', async (req, res) => {
    const isLoggedIn = req.session.isLoggedIn || false;
    const isAdmin = req.session.isLoggedIn && req.session.userRole === 'admin';
    // Extract form values from req.body with destructuring
    const {
        first_name,
        last_name,
        email,
        phone,
        street_address,
        city,
        state,
        zip,
        monthly_hours_available, 
        finding_source,
        sewing_ability_id,
        willing_to_teach_sewing,
        willing_to_lead,
        username,
        password,
    } = req.body;

    // Convert required fields to the correct types
    const parsedFindingSource = parseInt(finding_source, 10);
    const parsedSewingAbilityId = parseInt(sewing_ability_id, 10);
    const parsedNumHours = parseInt(monthly_hours_available, 10);
    const teachSewing = willing_to_teach_sewing === 'Y'; // Convert checkbox to boolean
    const lead = willing_to_lead === 'Y'; // Convert checkbox to boolean

    // Check for existing user with the same email or username
    const existingAdminOrUser = async (email, username) => {
        try {
            // Check in the admins table
            const adminMatch = await knex('admins')
                .where('email', email)
                .orWhere('username', username)
                .first();
    
            // Check in the users table
            const userMatch = await knex('users')
                .where('email', email)
                .orWhere('username', username)
                .first();
    
            // Return true if a match is found in either table
            return adminMatch || userMatch;
        } catch (error) {
        console.error('Error checking for existing admin or user:', error);
        throw error;
    }
};
const existingRecord = await existingAdminOrUser(email,username);
    

    if (existingRecord) {
        // Email or username already exists
        let errorMessage = 'An account with this ';
        if (existingRecord.email === email) {
            errorMessage += 'email ';
        }
        if (existingRecord.username === username) {
            errorMessage += (errorMessage.includes('email') ? 'and ' : '') + 'username ';
        }
        errorMessage += 'already exists. Please try again with different credentials.';
        
        return res.status(400).render('volunteer', { 
            errorMessage,isAdmin, isLoggedIn
        });
    }

    // Hash the password
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    
    try {
        // Insert the new volunteer into the database
        await knex.transaction(async (trx) => {
            await trx('volunteer_info').insert({
                vol_first_name: first_name,
                vol_last_name: last_name,
                vol_email: email,
                vol_phone: phone,
                street_address: street_address,
                city: city,
                state: state,
                zip: zip,
                monthly_hours_available: parsedNumHours,
                finding_source: parsedFindingSource,
                sewing_ability_id: parsedSewingAbilityId,
                willing_to_teach_sewing: teachSewing,
                willing_to_lead: lead,
            });
        
            await trx('users').insert({
                first_name: first_name,
                last_name: last_name,
                email: email,
                username: username,
                hashed_password: hashedPassword,
            });
        });
        

        // Redirect to the home page or a thank-you page
        res.redirect('/');
    } catch (error) {
        console.error('Error adding Volunteer:', error.message);
        res.status(500).send('Internal Server Error');
    }
});




// GET route for add-volunteer.ejs
app.get('/add-volunteer', checkAuthenticationStatus, (req, res) => {
    const isLoggedIn = req.session.isLoggedIn || false;
    const isAdmin = req.session.isLoggedIn && req.session.userRole === 'admin';
    let errorMessage= null
    res.render('add-volunteer', { errorMessage, isLoggedIn, isAdmin });
});



// GET route for edit-volunteer.ejs
app.get('/edit-volunteer/:id', checkAuthenticationStatus, async (req, res) => {
    try {
        const isLoggedIn = req.session.isLoggedIn || false;
        const isAdmin = req.session.isLoggedIn && req.session.userRole === 'admin';
        const vol_id = req.params.id;
        let errorMessage = null

        // Query the database to get the volunteer's details
        const volunteer = await knex('volunteer_info')
            .select(
                'vol_id',
                'vol_first_name',
                'vol_last_name',
                'vol_email',
                'vol_phone',
                'street_address',
                'city',
                'state',
                'zip',
                'monthly_hours_available',
                'finding_source',
                'sewing_ability_id',
                'willing_to_teach_sewing',
                'willing_to_lead'
            )
            .where('vol_id', vol_id)
            .first();

        if (!volunteer) {
            return res.status(404).send('Volunteer not found');
        }

        // Render the edit form with the volunteer's details
        res.render('edit-volunteer', { errorMessage, isLoggedIn, isAdmin, volunteer });
    } catch (err) {
        console.error('Error fetching volunteer:', err);
        res.status(500).send('An error occurred while fetching the volunteer.');
    }
});


// post route for edit-volunteer
app.post('/edit-volunteer/:id', checkAuthenticationStatus, async (req, res) => {
    try {
        const vol_id = req.params.id;

        // Extract updated values from the request body
        const {
            vol_first_name,
            vol_last_name,
            vol_email,
            vol_phone,
            street_address,
            city,
            state,
            zip,
            monthly_hours_available,
            finding_source,
            sewing_ability_id,
            willing_to_teach_sewing,
            willing_to_lead
        } = req.body;

        // Update the volunteer's details in the database
        await knex('volunteer_info')
            .where('vol_id', vol_id)
            .update({
                vol_first_name,
                vol_last_name,
                vol_email,
                vol_phone,
                street_address,
                city,
                state,
                zip,
                monthly_hours_available,
                finding_source,
                sewing_ability_id,
                willing_to_teach_sewing: willing_to_teach_sewing ? 'Y' : 'N',
                willing_to_lead: willing_to_lead ? 'Y' : 'N',
            });

        // Redirect to a success page or back to the volunteer list
        res.redirect('/maintain-volunteers'); // Adjust the redirection as needed
    } catch (err) {
        console.error('Error updating volunteer:', err);
        res.status(500).send('An error occurred while updating the volunteer.');
    }
});




// GET route for edit-admin.ejs
app.get('/edit-admin/:id', checkAuthenticationStatus, (req, res) => {
    const isLoggedIn = req.session.isLoggedIn || false;
    const isAdmin = req.session.isLoggedIn && req.session.userRole === 'admin';

    knex.select("email",
                "first_name",
                "last_name",
                "username"
                )
        .from("admins")
        .where("email", req.params.id)
        .then(admins => {
            res.render('edit-admin', { isLoggedIn, isAdmin, admins });
        }).catch(err => {
            console.log(err);
            res.status(500).json({err});
        });
});

// POST route for edit-admin.ejs
app.post('/edit-admin/:id', async  (req, res) => {
    try {
        const id = req.params.id;

        // Extract updated values from the request body
        const {
            email,
            first_name,
            last_name,
            username
        } = req.body;

        // Update the user's details in the database
        await knex('admins')
            .where('email', id)
            .update({
                email,
                first_name,
                last_name,
                username
            });

        // Redirect to a success page or back to the user list
        res.redirect('/maintain-users'); // Adjust the redirection as needed
    } catch (err) {
        console.error('Error updating user:', err);
        res.status(500).send('An error occurred while updating the user.');
    }
});

app.get('/send-email/:id', checkAuthenticationStatus, async (req, res) => {
    try {
        const isAdmin = req.session.isLoggedIn && req.session.userRole === 'admin';
        const isLoggedIn = req.session.isLoggedIn || false;

        const volunteerID = parseInt(req.params.id, 10)
        if (isNaN(volunteerID)) {
            return res.status(400).send('Invalid vol_id. It must be a valid number.')
        }
        
        const eventdata = await knex("event_info as EI")
            .join("event_date_options as EDO", "EI.event_id", "EDO.event_id")
            .join("venues as VEN", "EI.venue_id", "VEN.venue_id")
            .select(
                    "VEN.street_address",
                    "VEN.city", // The event details should be 
                    "VEN.state",    // a drop-down to select
                    "VEN.zip",
                    "EDO.start_time",
                    "EDO.end_time",
                    "EDO.event_date",
                    "EI.organization_name",
                    "EI.event_description"
            )
            .first();

        const volunteerdata = await knex("volunteer_info")
        .select(
        "vol_first_name",
        "vol_email")
        .where("vol_id", volunteerID)
        .first()

        if (!volunteerdata || !eventdata) {
            return res.status(404).send("No volunteer or event data associated with vol_id");
        }

        eventdata.vol_first_name = volunteerdata.vol_first_name;
        eventdata.vol_email=volunteerdata.vol_email;

        // Converts military time to AM/PM format
        const timeParts = eventdata.start_time.split(':');
        const hours = parseInt(timeParts[0], 10);
        const minutes = timeParts[1];
        const amPM = hours >= 12 ? 'PM' : 'AM';
        const formattedTime = `${((hours + 11) % 12 + 1)}:${minutes} ${amPM}`;

        // Formats the event_date to a cleaner format
        const eventDate = new Date(eventdata.event_date);
        const formattedDate = eventDate.toLocaleDateString('en-US', {
            weekday: 'long', // e.g., "Fri"
            month: 'short',   // e.g., "Dec"
            day: '2-digit',   // e.g., "20"
            year: 'numeric'   // e.g., "2024"
        });

        // Renders email template with dynamic values
        res.render('send-email', {
            isAdmin,
            isLoggedIn,
            vol_email: volunteerdata.vol_email,
            subject: `Volunteer Opportunity in ${eventdata.city}, ${eventdata.state} on ${formattedDate}`,
            volunteer_name: volunteerdata.vol_first_name,
            city: eventdata.city,
            state: eventdata.state,
            event_date: formattedDate,
            start_time: formattedTime
        });
    } catch (error) {
        console.error(error);
        res.status(500).send(error.message || 'An error occured')
    }
});

app.get('/view-participants/:id', checkAuthenticationStatus, async (req, res) => {
    const isAdmin = req.session.isLoggedIn && req.session.userRole === 'admin';
    const isLoggedIn = req.session.isLoggedIn || false;

    const eventID = parseInt(req.params.id);

    try {
        const eventParticipationData = await knex('volunteer_info as v')
            .join('volunteer_participation as vp', 'v.vol_id', 'vp.vol_id')
            .join('event_info as e', 'vp.event_id', 'e.event_id')
            .select(
                'v.vol_first_name',
                'v.vol_last_name',
                'v.vol_email',
                'v.vol_phone',
                'e.event_description',
                'e.organization_name'
            )
            .where('vp.event_id', eventID);

        // Pass the data to the template
        res.render('view-participants', { eventParticipationData, isLoggedIn, isAdmin });
    } catch (error) {
        console.error(error);
        res.status(500).send('An error occurred while fetching participant data.');
    }
});
app.get('/record-events', checkAuthenticationStatus, async (req, res) => {
    try {
        const isLoggedIn = req.session.isLoggedIn || false;
        const isAdmin = req.session.isLoggedIn && req.session.userRole === 'admin';

        // Get the current page from the query string, default to page 1
        const currentPage = parseInt(req.query.page) || 1;
        const itemsPerPage = 10; // Number of events per page

        // Extract filters from the query string
        const { address, description, organization, city, state, zip, event_date } = req.query;

        // Calculate the offset for pagination
        const offset = (currentPage - 1) * itemsPerPage;

        // Subquery to aggregate items produced
        const itemsSubquery = knex('items_produced')
            .select('event_id')
            .select(
                knex.raw(`
                    json_agg(
                        json_build_object(
                            'item_description', item_description, 
                            'quantity', quantity
                        )
                    ) as items_produced
                `)
            )
            .groupBy('event_id');

        // Start building the base query
        let query = knex('event_info as e')
            .join('event_date_options as eo', function() {
                this.on('e.event_id', '=', 'eo.event_id')
                    .andOn('eo.date_preference_order', '=', knex.raw('?', [1]));
            })
            .join('sewing_ability as sa', 'e.sewing_ability_id', 'sa.sewing_ability_id')
            .join('venues as v', 'e.venue_id', 'v.venue_id')
            .leftJoin(itemsSubquery.as('ip'), 'e.event_id', 'ip.event_id')
            .select(
                'e.event_id',
                knex.raw("TO_CHAR(eo.event_date, 'MM-DD-YY') AS event_date"),
                knex.raw("TO_CHAR(eo.start_time, 'HH12:MI am') AS start_time"),
                knex.raw("TO_CHAR(eo.end_time, 'HH12:MI am') AS end_time"),
                'e.organization_name',
                'e.event_description',
                'e.organizer_first_name',
                'e.organizer_last_name',
                'e.organizer_phone',
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
                'e.contribute_materials_cost',
                'ip.items_produced'
                
            )
            .where('e.event_status', 'approved')
            .orderBy('eo.event_date')
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

        // Render the record-events page with events, pagination data, and filter values
        res.render('record-events', {
            isLoggedIn,
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
            dateFilter: event_date,
            
        });

    } catch (err) {
        console.error('Error fetching events:', err);
        res.status(500).send('An error occurred while fetching events.');
    }
});

// complete event route
app.get('/complete-event/:id', checkAuthenticationStatus, (req, res) => {
    const isLoggedIn = req.session.isLoggedIn || false;
    const isAdmin = req.session.isLoggedIn && req.session.userRole === 'admin';
    const id = req.params.id;
    // Fetch the main event info
    knex('event_info')
        .where('event_id', id)
        .first()
        .then(events => {
            if (!events) {
                return res.status(404).send('Event not found');
            }
            // Fetch the venue and event_date_options in parallel
            return Promise.all([
                knex('items_produced').where('event_id', events.event_id)
            ]).then(([items_produced]) => {
             // Transform items_produced into an object for easy access in template
                const itemsProducedObj = {};
                items_produced.forEach(item => {
                    itemsProducedObj[item.item_description.toLowerCase()] = item.quantity;
                });
                // Render the edit-event form with all required data
                res.render('complete-event', {
                    isLoggedIn,
                    isAdmin,
                    events,
                    items_produced: itemsProducedObj
                });
            });
        })
        .catch(error => {
            console.error('Error fetching data:', error);
            res.status(500).send('Internal Server Error');
        });
});
app.post('/complete-event/:id', checkAuthenticationStatus, (req, res) => {
    const isLoggedIn = req.session.isLoggedIn || false;
    const isAdmin = req.session.isLoggedIn && req.session.userRole === 'admin';
    const eventId = req.params.id;
    const {
        
        estimated_attendance,
        pockets_quantity,
        collars_quantity,
        envelopes_quantity,
        vests_quantity,
       
    } = req.body;
    const event_status ='completed'
    const itemsToInsert = [];
    const itemTypes = [
        { name: 'Pockets', quantity: pockets_quantity },
        { name: 'Collars', quantity: collars_quantity },
        { name: 'Envelopes', quantity: envelopes_quantity },
        { name: 'Vests', quantity: vests_quantity }
    ];
    // First, update event_info table
    knex('event_info')
        .where('event_id', eventId)
        .update({
            
            estimated_attendance,
            event_status

        })
        
        .then(() => {
            return knex('items_produced')
                .where('event_id', eventId)
                .del();
        })
        .then(() => {
            // Insert new items with non-zero quantities
            const itemsToInsert = itemTypes
                .filter(item => item.quantity > 0)
                .map(item => ({
                    event_id: eventId,
                    item_description: item.name,
                    quantity: item.quantity
                }));

            // Only insert if there are items to insert
            if (itemsToInsert.length > 0) {
                return knex('items_produced').insert(itemsToInsert);
            }
        })
        
            
        
        .then(() => {
            // After all updates are successful, redirect or render a success page
            res.redirect('/record-events');
        })
        .catch(error => {
            console.error('Error:', error);
            res.status(500).send('An error occurred while updating the event');
        });
});

app.post('/disapprove-event/:id', checkAuthenticationStatus, (req, res) => {
    const eventId = req.params.id;
    const event_status ='pending'
    knex('event_info')
        .where('event_id', eventId)
        .update({
            
            event_status

        })
        .then(() => {
            // After all updates are successful, redirect or render a success page
            res.redirect('/record-events');
        })
        .catch(error => {
            console.error('Error:', error);
            res.status(500).send('An error occurred while updating the event');
        });
});


app.get('/pending-events', checkAuthenticationStatus, async (req, res) => {
    try {
        const isLoggedIn = req.session.isLoggedIn || false;
        const isAdmin = req.session.isLoggedIn && req.session.userRole === 'admin';

        // Get the current page from the query string, default to page 1
        const currentPage = parseInt(req.query.page) || 1;
        const itemsPerPage = 10; // Number of events per page

        // Extract filters from the query string
        const { address, description, organization, city, state, zip, event_date, event_status } = req.query;

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
                knex.raw("TO_CHAR(eo.start_time, 'HH12:MI am') AS start_time"),
                knex.raw("TO_CHAR(eo.end_time, 'HH12:MI am') AS end_time"),
                'e.organization_name',
                'e.event_description',
                'e.organizer_first_name',
                'e.organizer_last_name',
                'e.organizer_phone',
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
                'e.event_status',
                knex.raw("CONCAT(v.street_address, ', ', v.city, ', ', v.state, ' ', v.ZIP) AS full_address"),
                'e.notes',
                'e.jen_story',
                'e.contribute_materials_cost',
            )
            .where('e.event_status', 'pending')
            .orderBy('eo.event_date')
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
        res.render('pending-events', {
            isLoggedIn,
            isLoggedIn,
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
            dateFilter: event_date,
        });
    } catch (err) {
        console.error('Error fetching events:', err);
        res.status(500).send('An error occurred while fetching events.');
    }
});

app.post('/approve-event/:id', checkAuthenticationStatus, (req, res) => {
    const eventId = req.params.id;
    const isLoggedIn = req.session.isLoggedIn || false;
    const isAdmin = req.session.isLoggedIn && req.session.userRole === 'admin';
    const event_status ='approved'
    knex('event_info')
        .where('event_id', eventId)
        .update({
            event_status
        })
        .then(() => {
            // After all updates are successful, redirect or render a success page
            res.redirect('/pending-events');
        })
        .catch(error => {
            console.error('Error:', error);
            res.status(500).send('An error occurred while updating the event');
        });
});

app.post('/decline-event/:id', checkAuthenticationStatus, (req, res) => {
    const eventId = req.params.id;
    const isLoggedIn = req.session.isLoggedIn || false;
    const isAdmin = req.session.isLoggedIn && req.session.userRole === 'admin';
    const event_status ='declined'
    knex('event_info')
        .where('event_id', eventId)
        .update({
            event_status
        })
        .then(() => {
            // After all updates are successful, redirect or render a success page
            res.redirect('/maintain-events');
        })
        .catch(error => {
            console.error('Error:', error);
            res.status(500).send('An error occurred while updating the event');
        });
});


app.listen(port, () => console.log('The server has started.'));
