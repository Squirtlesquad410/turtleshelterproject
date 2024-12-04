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
        host: "awseb-e-wx74xhj2vt-stack-awsebrdsdatabase-dbcyxq8zvwk9.c3okg6w2omlf.us-west-2.rds.amazonaws.com",
        user: "postgres",
        password: "Sigmaturtles410!", // CHANGE BACK BEFORE PUSH
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

const username=process.env.DB_USERNAME
const password=process.env.DB_PASSWORD

// Logic for verifying username and password
app.post('/signin', async (req, res) => {
    const usernameLogin = username//req.body.username || ;
    const passwordLogin = password // req.body.password || ;

    try {
        // Query the database to find the user by username
        const admin = await knex('admins').where('username', usernameLogin).first();

        if (!admin) {
            // If the username does not exist, send an error message
            req.session.message = 'Invalid username or password.';
            return res.redirect('/signin');
        }

        // Compare the provided password with the hashed password
        const isPasswordCorrect = true//await bcrypt.compare(passwordLogin, admin.hashed_password);

        if (isPasswordCorrect) {
            // If login is successful
            req.session.isLoggedIn = true; // Mark the session as logged in
            req.session.userRole = 'admin'; // Set the user role
            req.session.username = admin.username; // Optional: Store the username
            res.redirect('/admin'); // Redirect to the admin page
        } else {
            // If the password is incorrect
            req.session.message = 'Invalid username or password.';
            res.redirect('/signin');
        }
    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).send('Internal Server Error');
    }
});



// // Logic for verifying username and password
// app.post('/signin', (req, res) => {
//     const usernameLogin = req.body.username;
//     const passwordLogin = req.body.password;

//     // Check if submitted credentials match login info stored in the .env file
//     if (usernameLogin === myUsername && passwordLogin === myPassword) {
//         // if successful login do THIS
//         req.session.isLoggedIn = true;  // sets session variable to true with correct login
//         req.session.userRole = 'admin';
//         res.redirect('/admin');     // goes to the admin page if login is correct
//     } else {
//         // If failed login
//         res.status(403).send('<h1>403 Forbidden <3</h1>');
//     }
// });


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

// Route for Add Admin Page
app.get('/add-admin', (req, res) => {
    const isAdmin = req.session.isLoggedIn && req.session.userRole === 'admin';
    res.render('add-admin', { isAdmin });
});


// Route to add new admin to database
app.post('/add-admin', async (req, res) => {
    try {
        // Extract data from the form
        const { email, first_name, last_name, username, password } = req.body;

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
            dateFilter: event_date
        });
    } catch (err) {
        console.error('Error fetching events:', err);
        res.status(500).send('An error occurred while fetching events.');
    }
});


// GET route for edit-event.ejs
app.get('/edit-event/:id', checkAuthenticationStatus, (req, res) => {
    knex.select()
    .from("event_info")
    .then()
    const isLoggedIn = req.session.isLoggedIn || false;
    const isAdmin = req.session.isLoggedIn && req.session.userRole === 'admin';
    res.render('edit-event', { isLoggedIn, isAdmin });
});


// GET route for add-event.ejs
app.get('/add-event', checkAuthenticationStatus, (req, res) => {
    const isLoggedIn = req.session.isLoggedIn || false;
    const isAdmin = req.session.isLoggedIn && req.session.userRole === 'admin';
    res.render('add-event', { isLoggedIn, isAdmin });
});



// GET route for edit-event/:id
app.get('/edit-event/:id', (req, res) => {
    const event_id = req.params.id;

    knex("event_info")
        .where('event_id', event_id)
        .first() // ensures only one record is fetched
        .then(event => {
            if (!event) {
                return res.status(404).send("Event not found");
            }
            res.render('edit-event', { event });
        })
        .catch(err => {
            console.error(err);
            res.status(500).send("An error occurred");
        });
});

// POST route to update database with edited changes for the event
app.post('/edit-event/:id', (req, res) => {
    const event_id = req.params.id;

    // Prepares updated event data from form submission
    const updatedEvent = {
        //
    }
})



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

        // Calculate the offset for pagination
        const offset = (currentPage - 1) * itemsPerPage;

        // Start building the base query
        let query = knex('admins as a')
            .select(
                'a.admin_id',
                'a.first_name',
                'a.last_name',
                'a.email',
                'a.username',
            )
            .orderBy('a.last_name')
            .limit(itemsPerPage)
            .offset(offset);


        // Execute the query to fetch the filtered and paginated events
        const admins = await query;

        // Query the total number of events for pagination controls, applying the same filters
        let countQuery = knex('admins as a')

           
            .count('a.admin_id as count');

        const totalAdmins = await countQuery.first();
        const totalPages = Math.ceil(totalAdmins.count / itemsPerPage);

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
app.post('/delete-admin/:id', (req, res) => {
    const admin_id = req.params.id;
  
    knex('admins')
      .where('email', admin_id)
      .del() // Deletes the adminwith the specified ID
      .then(() => {
        res.redirect('/maintain-users'); // Redirect to a relevant page after deletion
      })
      .catch(error => {
        console.error('Error deleting admin:', error);
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
                'v.city',
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
        if (willing_to_teach_sewing) {
            query = query.whereRaw('LOWER(v.willing_to_teach_sewing) LIKE ?', [`%${willing_to_teach_sewing.toLowerCase()}%`]);
        }
        if (willing_to_lead) {
            query = query.whereRaw('LOWER(v.willing_to_lead) LIKE ?', [`%${willing_to_lead.toLowerCase()}%`]);
        }

        // Execute the query to fetch the filtered and paginated events
        const volunteers = await query;

        // Query the total number of events for pagination controls, applying the same filters
        let countQuery = knex('volunteer_info as v')

            .join('sewing_ability as sa', 'v.sewing_ability_id', 'sa.sewing_ability_id')
            .count('v.vol_id as count');

            if (vol_first_name) {
                query = query.whereRaw('LOWER(v.vol_first_name) LIKE ?', [`%${vol_first_name.toLowerCase()}%`]);
            }
            if (vol_last_name) {
                query = query.whereRaw('LOWER(v.vol_last_name) LIKE ?', [`%${vol_last_name.toLowerCase()}%`]);
            }
            if (city) {
                query = query.whereRaw('LOWER(v.city) LIKE ?', [`%${city.toLowerCase()}%`]);
            }
            if (willing_to_teach_sewing) {
                query = query.whereRaw('LOWER(v.willing_to_teach_sewing) LIKE ?', [`%${willing_to_teach_sewing.toLowerCase()}%`]);
            }
            if (willing_to_lead) {
                query = query.whereRaw('LOWER(v.willing_to_lead) LIKE ?', [`%${willing_to_lead.toLowerCase()}%`]);
            }

        const totalVolunteers = await countQuery.first();
        const totalPages = Math.ceil(totalVolunteers.count / itemsPerPage);

        // Render the maintain-events page with events, pagination data, and filter values
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
            organization_name,
            event_description,
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
            event_status,
            event_date,
            start_time,
            end_time,
        } = req.body;
    
        try {
            await knex.transaction(async (trx) => {
                // Step 1: Insert into the venues table
                const [insertedVenue] = await trx('venues')
                    .insert({
                        street_address,
                        city,
                        state,
                        zip: parseInt(zip),
                    })
                    .returning('venue_id'); // Adjust based on your table schema
    
                const venue_id = typeof insertedVenue === 'object' ? insertedVenue.venue_id : insertedVenue;
    
                // Step 2: Insert into the event_info table
                const [insertedEvent] = await trx('event_info')
                    .insert({
                        venue_id, // Reference the new venue_id
                        organization_name,
                        event_description,
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
                    })
                    .returning('event_id');
    
                console.log('Event Created:', insertedEvent);
    
                // Step 3: Insert into the event_date_options table
                await trx('event_date_options').insert({
                    event_id: typeof insertedEvent === 'object' ? insertedEvent.event_id : insertedEvent,
                    event_date,
                    start_time,
                    end_time,
                });
            });
    
            res.redirect('/admin');
        } catch (error) {
            console.error('Error creating event:', error);
            res.status(500).send('Internal Server Error');
        }
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
app.post('/volunteer', async (req, res) => {
    // Extract form values from req.body with destructuring
    const {
        first_name,
        last_name,
        email,
        phone,
        city,
        monthly_hours_available, // Assuming you have a `num_hours` field for available hours
        finding_source,
        sewing_ability_id,
        willing_to_teach_sewing,
        willing_to_lead,
    } = req.body;

    // Convert required fields to the correct types
    const parsedFindingSource = parseInt(finding_source, 10);
    const parsedSewingAbilityId = parseInt(sewing_ability_id, 10);
    const parsedNumHours = parseInt(monthly_hours_available, 10);
    const teachSewing = willing_to_teach_sewing === 'Y'; // Convert checkbox to boolean
    const lead = willing_to_lead === 'Y'; // Convert checkbox to boolean

    try {
        // Insert the new volunteer into the database
        await knex('volunteer_info').insert({
            vol_first_name: first_name,
            vol_last_name: last_name,
            vol_email: email,
            vol_phone: phone,
            city: city,
            monthly_hours_available: parsedNumHours,
            finding_source: parsedFindingSource,
            sewing_ability_id: parsedSewingAbilityId,
            willing_to_teach_sewing: teachSewing,
            willing_to_lead: lead,
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
    res.render('add-volunteer', { isLoggedIn, isAdmin });
});



// GET route for edit-volunteer.ejs
app.get('/edit-volunteer', checkAuthenticationStatus, (req, res) => {
    const isLoggedIn = req.session.isLoggedIn || false;
    const isAdmin = req.session.isLoggedIn && req.session.userRole === 'admin';
    res.render('edit-volunteer', { isLoggedIn, isAdmin });
});



app.listen(port, () => console.log('Chat, our SIGMA Server is started...'));