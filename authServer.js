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
app.use(express.json()) 

const mongoose = require('mongoose')
mongoose.set('strictQuery', false)
mongoose.connect(process.env.DATABASE_URL, { useNewUrlParser: true } )
const db = mongoose.connection

db.on('error', err => {console.log(err)})
db.once('open', () => console.log('DB Connected'))

app.post('/token', async(req, res) =>{
    const refreshToken = req.body.refreshToken
    if(refreshToken == null) return res.sendStatus(403)
    const token = await Token.findOne({token: refreshToken})
    if(!token){
        return res.sendStatus(403)
    } 
        jwt.verify(refreshToken, process.env.REFRESH_TOKEN, async(err, user) =>{
            if(err) return res.sendStatus(403)
            const accessToken = generateAccessToken({name: user.name})
            const newRefreshToken = generateRefreshToken({name: user.name})
            const find_token = await Token.findOneAndUpdate({ token: refreshToken}, {token: newRefreshToken}, {new: true})    
            res.json({"accessToken" : accessToken, "Refresh Token": find_token.token})
        })
})

app.post('/login', async(req, res) =>{
    let user = await User.find({userName: req.body.username})
    if (user == null){
         res.send('User not found')
    }
    try{
        if( await bcrypt.compare( req.body.password, user[0].password) ){
            const username = { name: req.body.username}
            const accessToken = generateAccessToken(username)
            const refreshToken = generateRefreshToken(username)
            const userID = user[0]._id
            const searchToken = await Token.findOne({user: userID})
            
            if(searchToken == null){
                const newRefreshToken = new Token({
                    token: refreshToken,
                    user: user[0]._id
                })
                await newRefreshToken.save()
                res.json({ accessToken : accessToken, refreshToken: newRefreshToken.token})
            } else {
                let updateToken = await Token.findOneAndUpdate(
                    {user: user[0]._id}, 
                    {token: refreshToken} , 
                    {new: true}
                )
                // res.send('Token updated')
                res.json({ accessToken : accessToken, refreshToken: updateToken.token})

            }
        } else {
            res.send('Could not login')
        }
    } catch (err) {
        res.json({ message: err.message })
    }
})

const generateAccessToken = (user) => {
    return jwt.sign(user, process.env.ACCESS_TOKEN, { expiresIn: '20s'})
}
const generateRefreshToken = (user) => {
    return jwt.sign(user, process.env.REFRESH_TOKEN)
}

app.listen(4000)