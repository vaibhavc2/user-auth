import express from 'express';
import path from 'path';
import mongoose from 'mongoose';
import cookieParser from 'cookie-parser';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';


const PORT = 5000;


// setting up server using express
const app = express();

app.set('view engine', 'ejs');



// connecting database
mongoose.connect("mongodb://127.0.0.1:27017", {
    dbName: "user-auth"
}).then(() => {
    console.log('Connected to Database successfully!');
}).catch((err) => {
    console.log(err);
});

const userSchema = new mongoose.Schema({
    name: String,
    email: String,
    password: String,
});

const User = mongoose.model("user", userSchema);



// middleware to set up static 'public' folder
app.use(express.static(path.join(path.resolve(), 'public')));
// middleware to access data from the form
app.use(express.urlencoded({ extended: true }));
// middleware to access the cookies
app.use(cookieParser());



// listen to the PORT and give the status of the server
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});


const secretOrPrivateKey = "wj@zPa$#FesUjfhgSdGHw";

// middleware request handler function
const isAuthenticated = async (req, res, next) => {
    const { token } = req.cookies;
    
    if(token) {
        
        const decoded = jwt.verify(token, secretOrPrivateKey);

        req.user = await User.findById(decoded._id);

        next(); // calls the next request handler
    }
    else {
        res.redirect('/login');
    }

}


// APIs

// app.get('/', (req, res) => {
//     // console.log(req.cookies.token);
//     // const token = req.cookies.token;   // OR use the following using destructuring:
//     const { token } = req.cookies;

//     if(token) {
//         res.render('logout');
//     }
//     else {
//         res.render('login');
//     }
// });

app.get('/', isAuthenticated, (req, res) => {
    res.render('logout', { name: req.user.name });
});

app.get('/login', (req, res) => {
    // res.redirect('/');
    res.render('login');
});

app.get('/signup', (req, res) => {
    res.render('signup');
})

app.post('/login', async (req, res) => {

    const { email, password } = req.body;

    const user = await User.findOne({ email });

    if(!user) return res.redirect('/signup');

    const isMatch = await bcrypt.compare(password, user.password);

    if(isMatch) {

        // const user = user;

        const token = jwt.sign({_id: user._id}, secretOrPrivateKey);

        res.cookie("token", token, {
            expires: new Date(Date.now() + 86400 * 1000), // 86400 seconds = 1 day
            // maxAge: 86400,
            httpOnly: true,
        });

        res.redirect('/');
    }
    else return res.render('login', { email, message: "Incorrect Password!"});
});

app.post('/signup', async (req, res) => {

    const { name, email, password } = req.body;

    const prevUser = await User.findOne({email});

    if(prevUser) {
        return res.redirect('/login');
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = await User.create({
        name,
        email,
        password:hashedPassword,
    });

    const token = jwt.sign({_id: newUser._id}, secretOrPrivateKey);

    res.cookie("token", token, {
        expires: new Date(Date.now()+ 86400*1000), // 86400 seconds = 1 day
        // maxAge: 86400,
        httpOnly: true,
    });
    res.redirect('/');
});

app.get('/logout', (req, res) => {
    res.cookie("token", null, {
        expires: new Date(Date.now()),
    })
    res.redirect('/');
});

// app.get('/success', (req, res) => {
//     res.render('success');
// });