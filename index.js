let express = require('express'); 
let app = express();
let path = require('path'); 

const port = process.env.PORT || 3000; 

app.use(express.urlencoded( {extended: true} ));

app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");


const knex = require("knex")({
    client: "pg",
    connection: {
        host: process.end.RDS_HOSTNAME || "localhost",
        user: process.env.RDS_USERNAME || "postgres",
        password: process.env.RDS_PASSWORD || "Sigmaturtles410!",
        database: process.env.RDS_DB_NAME || "turtleshelterproject",
        port: process.env.RDS_PORT || 5432 
    }
});


app.use(express.static(path.join(__dirname, 'public')));
// -----> put all routes below

app.get('/', (req,res) => {
    res.render('index');
});

app.listen(port, () => console.log('server started'));