const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const jwt = require("jsonwebtoken");
const express = require("express");
const cors = require("cors");
require("dotenv").config();
const app = express();

//PORT SETUP
const port = process.env.PORT || 5000;

//Middleware
app.use(cors());
app.use(express.json());

//For Token verification
const verifyJWT = (req, res, next) => {
    const authHeader = req.headers?.authorization;
    if (!authHeader) {
        return res
            .status(401)
            .send({ success: false, message: "Unauthorized Access" });
    } else {
        const token = authHeader.split(" ")[1];

        // verify a token symmetric
        jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, function (err, decoded) {
            if (err) {
                return res
                    .status(403)
                    .send({ success: false, message: "Forbidden Access" });
            }
            // console.log("decoded", decoded);
            req.decoded = decoded;
            next();
        });
    }
};

//MongoDB Config
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.puprz.mongodb.net/?retryWrites=true&w=majority`;
const client = new MongoClient(uri, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    serverApi: ServerApiVersion.v1,
});

// API Endpoints
async function run() {
    try {
        await client.connect();
        const userCollection = client.db("bikePartsDB").collection("users");
        const productCollection = client.db("bikePartsDB").collection("products");
        const reviewCollection = client.db("bikePartsDB").collection("reviews");

        //Creating user and getting token for user
        app.put("/users/:email", async (req, res) => {
            const email = req.params?.email;
            const user = req.body;

            const filter = { email };
            const options = { upsert: true };
            const updateDoc = {
                $set: user,
            };

            const result = await userCollection.updateOne(
                filter,
                updateDoc,
                options
            );
            const accessToken = jwt.sign(
                { email },
                process.env.ACCESS_TOKEN_SECRET,
                {
                    expiresIn: "1d",
                }
            );
            // console.log(result, accessToken);
            res.send({ result, accessToken });
        });

        //Admin verification Middleware to prevent unauthorized actions
        //Note: Note it is dependent on verifyJWT. so place it after verifyJWT
        const verifyAdmin = async (req, res, next) => {
            const requester = req.decoded?.email;
            const user = await userCollection.findOne({ email: requester });
            if (user.role === "admin") {
                // console.log("admin verified");
                next();
            } else {
                return res
                    .status(403)
                    .send({ success: false, message: "Forbidden Access" });
            }
        };

        //Updating user role
        app.put("/users/admin/:email", verifyJWT, verifyAdmin, async (req, res) => {
            const email = req.params?.email;
            const role = req.body?.role;
            // console.log(role);
            const filter = { email };
            const updateDoc = {
                $set: {
                    role,
                },
            };
            const result = await userCollection.updateOne(filter, updateDoc);
            res.send(result);
        });

        //Admin checker api
        app.get("/admin/:email", verifyJWT, async (req, res) => {
            const email = req.params?.email;
            const user = await userCollection.findOne({ email });
            const isAdmin = user?.role === "admin";
            res.send({ admin: isAdmin });
        });

        //Getting all registered users
        app.get("/users", verifyJWT, async (req, res) => {
            const users = await userCollection.find().toArray();
            res.send(users);
        });

        ///////////////////////////////
        ///// Products APIs ///////////
        ///////////////////////////////

        //Inserting a Product
        app.post("/products", verifyJWT, verifyAdmin, async (req, res) => {
            const product = req.body;
            const result = await productCollection.insertOne(product);
            res.send(result);
        });

        //Getting all products
        app.get("/products", async (req, res) => {
            let products = [];
            if (req.query?.limitTo) {
                const limit = parseInt(req.query?.limitTo);
                products = await productCollection.find().limit(limit).toArray();
            } else {
                products = await productCollection.find().toArray();
            }
            res.send(products);
        });

        //Getting a specific product using product Id
        app.get("/products/:id", async (req, res) => {
            const productId = req.params?.id;
            try {
                const query = { _id: ObjectId(productId) };
                const product = await productCollection.findOne(query);
                res.send(product);
            } catch (error) {
                res.status(400).send({
                    success: false,
                    message: "Invalid Product Id",
                });
            }
        });

        //Updating a product
        app.put("/products/:id", verifyJWT, verifyAdmin, async (req, res) => {
            const productId = req.params?.id;
            const updatedProduct = req.body;
            try {
                const filter = { _id: ObjectId(productId) };

                const updateDoc = {
                    $set: {
                        ...updatedProduct,
                    },
                };
                const result = await productCollection.updateOne(filter, updateDoc);
                res.send(result);
            } catch (error) {
                res.status(400).send({
                    success: false,
                    message: "Invalid Product Id",
                });
            }
        });

        //Deleting a product
        app.delete("/products/:id", verifyJWT, verifyAdmin, async (req, res) => {
            const productId = req.params?.id;
            try {
                const filter = { _id: ObjectId(productId) };
                const result = await productCollection.deleteOne(filter);
                res.send(result);
            } catch (error) {
                res.status(400).send({
                    success: false,
                    message: "Invalid Product Id",
                });
            }
        });

        ///////////////////////////////
        ///// Review APIs ///////////
        ///////////////////////////////

        //Inserting a Review
        app.post("/reviews/:addedBy", verifyJWT, async (req, res) => {
            const email = req.params?.addedBy;
            const decodedEmail = req.decoded?.email;
            if (email === decodedEmail) {
                const review = req.body;
                const result = await reviewCollection.insertOne(review);
                return res.send(result);
            } else {
                res.status(403).send({
                    success: false,
                    message: "Forbidden Access",
                });
            }
        });

        //Getting all reviews
        app.get("/reviews", async (req, res) => {
            const reviews = await reviewCollection.find().toArray();
            res.send(reviews);
        });
    } finally {
        //   await client.close();
    }
}
run().catch(console.dir);

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
