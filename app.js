const dbConnect = require('./db/dbconnect')
const bcrypt = require("bcrypt");
const port = 8000;
const auth = require("./auth");

const User = require("./db/userModel");
const express = require('express');

var bodyParser = require('body-parser')
const jwt = require('jsonwebtoken')

const app = express();


// Middleware to parse JSON
app.use(express.json());

// Middleware to parse URL-encoded data
app.use(express.urlencoded({ extended: true }));


// register endpoint
app.post("/register", (request, response) => {


    // hash the password
    const { email, password } = request.body;

    // Validate request body
    if (!email || !password) {
        return response.status(400).send({
            message: "Email and password are required",
        });
    }

    bcrypt
      .hash(password, 10)
      .then((hashedPassword) => {
        // create a new user instance and collect the data
        const user = new User({
          email: email,
          password: hashedPassword,
        });
  
        // save the new user
        user.save()
          // return success if the new user is added to the database successfully
          .then((result) => {
            response.status(201).send({
              message: "User Created Successfully",
              result,
            });
          })
          // catch error if the new user wasn't added successfully to the database
          .catch((error) => {
            response.status(500).send({
              message: "Error creating user",
              error,
            });
          });
      })
      // catch error if the password hash isn't successful
      .catch((e) => {
        response.status(500).send({
          message: "Password was not hashed successfully",
          e,
        });
      });
  });



app.post("/login", (request, response)=>{
    User.findOne({email: request.body.email})
    .then((user)=>{
            bcrypt.compare(request.body.password, user.password)
            .then((passwordCheck)=>{

                if(!passwordCheck){
                    return response.status(400).send({
                        message: 'Password doesnot match',
                        e
                    });
                }

                // create JWT token
                const token = jwt.sign(
                    {
                        userId: user._id,
                        userEmail: user.email
                    },
                    'Random-token',
                    {expiresIn: '24h'}

                );

                return response.status(200).send({
                    message: "Login successful",
                    email: user.email,
                    token
                })

            })
            .catch((e)=>{
                return response.status(404).send({
                    message: "Password doesn't match",
                    e
                });
            })
        }
    )
    .catch((e)=>{
        response.status(404).send({
            message: 'Email Not Found',
            e
        })
    })
})


app.listen(port,function(err){
    if(err){
        console.log("Error int running the server:",err);
    }
    console.log("The server is up and running in the port",port);
});

// free endpoint
app.get("/free-endpoint", (request, response) => {
    response.json({ message: "You are free to access me anytime" });
});
  
// authentication endpoint
app.get("/auth-endpoint", auth, (request, response) => {
    try{
        return response.json({ message: "You are authorized to access me" });
    }catch (e) {
        return response.status(401).json({ message: "You are not authorized to access this page" })
    }
});


dbConnect()

// Curb Cores Error by adding a header here
app.use((req, res, next) => {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader(
      "Access-Control-Allow-Headers",
      "Origin, X-Requested-With, Content, Accept, Content-Type, Authorization"
    );
    res.setHeader(
      "Access-Control-Allow-Methods",
      "GET, POST, PUT, DELETE, PATCH, OPTIONS"
    );
    next();
});