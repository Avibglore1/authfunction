const mongoose = require('mongoose');
const express = require('express');
const app = express();
const dotenv = require('dotenv');
const cookieParser = require('cookie-parser');
dotenv.config();

const dbLink = `mongodb+srv://${process.env.DB_USERNAME}:${process.env.DB_PASSWORD}@cluster0.98clx.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

mongoose.connect(dbLink).then(function(connection){
    console.log('connected to db');
}).catch(err => console.log(err));

// const { createUser, getAllUser, getUser, deleteUser } = require("./userController");
const UserModel = require("./userModel");

app.use(express.json());
app.use(cookieParser())

const jwt = require("jsonwebtoken");
const util = require("util");
const { stat } = require('fs');
const promisify = util.promisify;
const promisdiedJWTsign = promisify(jwt.sign);
const promisdiedJWTverify = promisify(jwt.verify);




async function signupHandler(req,res){
    try{
        const userObject = req.body;
        if(!userObject.email || !userObject.password || userObject.password != userObject.confirmPassword){
            return res.status(400).json({
                message: 'required data missing',
                status: 'failure'
            })
        }

        const user = await UserModel.findOne({email: userObject.email});
        if (user){
            return res.status(400).json({
                message: 'user is already logged in',
                status: 'success'
            })
        }

        const newUser = await UserModel.create(userObject);
        res.status(201).json({
            message: 'signup successful',
            status: 'success'
        })
    }catch(err){
        console.log('err', err);
        res.status(500).json({
            message: err.message,
            status: 'failure'
        })
    }
}

async function loginHandler(req,res){
    try{
        const {email, password} = req.body;
        const user = await UserModel.findOne({email});
        if(!user){
            return res.status(400).json({
                message:"user not found",
                status: 'failure'
            })
        }

        if(password != user.password){
            return res.status(400).json({
                message: 'Invalid username or password',
                status: 'failure'
            })
        }

        const authToken = await promisdiedJWTsign({id: user["_id"]},process.env.SECRET_KEY );
        res.cookie('jwt', authToken,{
            maxAge: 24*60*60,
            httpOnly: true,
        });

        res.status(200).json({
            message: 'user login successfull',
            status: 'success'
        })
    }catch(err){
        console.log(err);
        res.status(500).json({
            message: 'Internal Server error',
            status: 'failure',
            user
        })
    }
}

async function protectRouteMiddleware(req, res, next){
    try{
        const token = req.cookies.jwt;

        if(!token){
            res.status(400).json({
                message: 'Invalid user',
                status:'failure'
            })
        }

        const decryptedToken = await promisdiedJWTverify(token, process.env.SECRET_KEY);
        req.id = decryptedToken.id;

        next();
    }catch(err){
        console.log('err', err);
        res.status(500).json({
            message: 'Internal server error',
            status: 'failure'
        })
    }
}

async function isAdminMiddleWare(req,res,next){
    const id = req.id;
    const user = await UserModel.findOne(id);

   if(user.role != 'admin'){
    return res.status(400).json({
        message: 'invalid user',
        status: 'failure'
    });
   }

   next();
}

async function profileHandler(req,res){
    try{
        const userId = req.id;
        const user = await UserModel.findOne({id: userId});
        if(!user){
            res.status(400).json({
                message: 'invalid user',
                status:'failure'
            })
        }

        res.status(200).json({
            user:user,
            status: 'success'
        })
    }catch(err){
        console.log('err',err);
        res.status(500).json({
            message: 'invalid user request',
            status: 'failure'
        });
    }
}

async function logoutHandler(req,res){
    try{
        res.clearCookie('jwt', {path: '/'});
        res.json({
            message: 'logout successfull',
            status: 'success' 
        })
    }catch(err){
        console.log('err', err);
        res.status(500).json({
            message: 'internal server error',
            status: 'failure'
        })
    }
}

app.post("/signup", signupHandler);
app.post('/login', loginHandler);
app.get("/profile", protectRouteMiddleware, profileHandler);
app.get("/user", protectRouteMiddleware, isAdminMiddleWare);


app.listen(3000, function(){
    console.log('Server started at port 3000');
})
app.get('/logout', logoutHandler)