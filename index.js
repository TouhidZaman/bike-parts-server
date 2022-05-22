const express = require("express");
const cors = require("cors");
require("dotenv").config();
const app = express();

//PORT SETUP
const port = process.env.PORT || 5000;

//Middleware
app.use(cors());
app.use(express.json());


//API Endpoints
app.get("/", (req, res) => {
    res.send({
        success: true,
        message: "hello from bike-parts-manufacturer server",
        developedBy: "Muhammad Touhiduzzaman",
    });
});

//Listening to port
app.listen(port, () => {
    console.log("bike-parts-manufacturer server is listening to port", port);
});