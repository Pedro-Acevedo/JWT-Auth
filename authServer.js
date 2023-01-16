if(process.env.NODE_ENV !== 'production'){
    require('dotenv').config()
}
require('dotenv').config()
const express = require('express')
const app = express()
const jwt = require('jsonwebtoken')
const User = require('./model/user')
const Token = require('./model/token')
const bcrypt = require('bcrypt')
const cookieParser = require ('cookie-parser')
app.use(express.json()) 
app.use(cookieParser())
const mongoose = require('mongoose')
mongoose.set('strictQuery', false)
mongoose.connect(process.env.DATABASE_URL, { useNewUrlParser: true } )
const db = mongoose.connection
 
db.on('error', err => {console.log(err)})
db.once('open', () => console.log('DB Connected'))

app.post('/login', validateEmptyFields, validateCredentials, async(req, res) =>{
    // validateEmptyFields(req.body.username, req.body.password, res)
    // try{
    //     let query = User.findOne({})
    //     query = query.regex('userName', new RegExp(req.body.username, 'i'))
    //     const user = await query.exec()

    //     if (user == null){
    //         return res.send('no user')
    //     }
    //     if( req.body.username.toUpperCase() !== user.userName.toUpperCase() ){
    //         return res.send('Username is wrong')
    //     }    
    //     if( await bcrypt.compare( req.body.password, user.password) ){
    //         const username = { name: req.body.username}
    //         const accessToken = generateAccessToken(username)
    //         const refreshToken = generateRefreshToken(username)
    //         const userID = user._id
    //         const searchToken = await Token.findOne({user: userID})
    //         if(searchToken == null){
    //             const newRefreshToken = new Token({
    //                 token: refreshToken,
    //                 user: user._id
    //             })
    //             await newRefreshToken.save()
    //             // Set secure: true in produccion
    //             res.cookie('jwt', newRefreshToken.token, { httpOnly: true, maxAge: 24 * 60 * 60 * 1000
    //                 , secure:process.env.SECURE 
    //             })
    //             res.json({ accessToken : accessToken })
    //         } else {
    //             let updateToken = await Token.findOneAndUpdate(
    //                     {user: user._id}, 
    //                     {token: refreshToken} , 
    //                     {new: true}
    //                 )
    //                 // JWT cookie was created as httpOnly so it can't be modified with Js
    //                 // Set secure: true in produccion
    //                 res.cookie('jwt', updateToken.token, { httpOnly: true, maxAge: 24 * 60 * 60 * 1000,    secure:process.env.SECURE 
    //                 })
    //                 res.json({ user: user ,accessToken : accessToken })       
    //             }   
    //     } else {
    //             res.send('Wrong Password')
    //     }
        
    // } catch (err) {
    //     res.json({ message: err.message })
    // }
})

app.get('/token', async(req, res) =>{
    const cookie = req.cookies
    if (!cookie?.jwt) return res.sendStatus(403)
    try {
        const token = await Token.findOne({token: cookie.jwt})
        const users = await User.findById({ _id: token.user })
        if(!token){
            return res.sendStatus(403)
        } 
        jwt.verify(cookie.jwt, process.env.REFRESH_TOKEN, async(err, user) =>{
            if(err || users.userName !== user.name) return res.sendStatus(403)
            const accessToken = generateAccessToken({name: user.name})   
            res.json({"accessToken" : accessToken})
        })  
    } catch ( err ) {
        res.json({ "message": err.message})
    }
})


app.get('/logout', async(req, res) => {

    const cookies = req.cookies
    // console.log(cookies.jwt);
    if(!cookies?.jwt) return res.sendStatus(204) //204 means no content
    try{
    const userJWT = await Token.find({ token: cookies.jwt })
    if ( !userJWT ){
        res.clearCookie('jwt', { httpOnly: true, maxAge: 24 * 60 * 60 * 1000
            //, secure:process.env.SECURE 
        }) //Set secure: true when in produccion
        return res.sendStatus(204)
    }
    // console.log(userJWT);
    const deletedToken = await Token.findOne({token: cookies.jwt})
            // return res.send( jwt)
            res.clearCookie('jwt', { httpOnly: true,    maxAge: 24 * 60 * 60 * 1000 
                // secure: process.env.SECURE
            })
        await deletedToken.remove()
        } catch (err) {
            res.json({ "message" : err.message})
        }
   
    // res.sendStatus(204)
})

// Functions
const generateAccessToken = (user) => {
    return jwt.sign(user, process.env.ACCESS_TOKEN, { expiresIn: '30s'})
}
const generateRefreshToken = (user) => {
    return jwt.sign(user, process.env.REFRESH_TOKEN, { expiresIn: '1d'})
}
const generateTokenCookie = (res, token) => {
    res.cookie('jwt', token, { httpOnly: true, maxAge: 24 * 60 * 60 * 1000
        , secure:process.env.SECURE 
    })
}

// MiddleWare
function validateEmptyFields(req, res, next) {
    const { username, password } = req.body
    try{
        if(username == null || username == '') return res.send('User not valid')
        if(password == null || password == '') return res.send('Password not valid')
    } catch{
        res.sendStatus(500)
    }
    next()
}

async function validateCredentials(req, res, next){
    try{
        let query = User.findOne({})
        query = query.regex('userName', new RegExp(req.body.username, 'i'))
        const user = await query.exec()

        if (user == null){
            return res.send('no user')
        }
        if( req.body.username.toUpperCase() !== user.userName.toUpperCase() ){
            return res.send('Incorrect username or password')
        }    
        if( await bcrypt.compare( req.body.password, user.password) ){
            const username = { name: req.body.username}
            const accessToken = generateAccessToken(username)
            const refreshToken = generateRefreshToken(username)
            const userID = user._id
            const searchToken = await Token.findOne({user: userID})
            if(searchToken == null){
                const newRefreshToken = new Token({
                    token: refreshToken,
                    user: user._id
                })
                await newRefreshToken.save()
                // Set secure: true in produccion
                generateTokenCookie(res, newRefreshToken.token)
                res.json({ accessToken : accessToken })
            } else {
                let updateToken = await Token.findOneAndUpdate(
                        {user: user._id}, 
                        {token: refreshToken} , 
                        {new: true}
                    )
                    // JWT cookie was created as httpOnly so it can't be modified with Js
                    // Set secure: true in produccion
                    generateTokenCookie(res, updateToken)
                    res.json({ user: user ,accessToken : accessToken })       
                }   
        } else {
                res.send('Incorrect username or password')
        }
        
    } catch (err) {
        res.json({ message: err.message })
    }
    next()
}

app.listen(4000)