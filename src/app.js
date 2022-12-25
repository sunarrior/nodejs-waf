const config = require('./configuration/configuration')
const cors = require('cors')
const morgan = require('morgan')
const express = require('express')
const bodyParser = require("body-parser");

var app = express();

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

let port;

if (config.env != 'DEV') {
    port = config.port;
} else {
    port = 3000
}

app.use(morgan('dev'));
app.use(express.json());

app.use((req, res, next) => {
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
    res.header("Access-Control-Allow-Methods", "GET,PUT,POST,DELETE");
    next();
});

app.use(cors());
app.use('/api', require('./routes')(app));

app.listen(port, () => {
    console.log("Server is listening at port: " + port);
    console.log("Debug del server: ");
});

module.exports = app