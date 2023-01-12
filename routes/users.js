const express = require('express')
const router = express.Router()
const User = require('../model/user')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
require('dotenv').config()

router.get('/', async(req, res) =>{
    const users = await User.find()
    res.send(users)
})

router.get('/post', authenticateJWT, async (req, res) => {
    const UserVerified = await User.find({userName: req.user.username})
    // res.json({ user: authuser})
    res.send(UserVerified)
})


router.get('/:id', getUserById, (req, res) =>{
    try{
        res.json(res.user)
    } catch (err) {
        res.json({message: err.message})
    }
})


//Register User
router.post('/new', async(req, res)=>{
    const password = await bcrypt.hash( req.body.password, 10 )
    const newUser = new User({ name: req.body.name,
        userName: req.body.username,
        password: password
})
    // res.send(req.body.name)
    try{
        await newUser.save()
        res.status(201).json(newUser)

    } catch (err) {
        res.json({ message: err.message })
    }
})


// Login user

router.post('/login', async (req, res) =>{
    let user = await User.find({userName: req.body.username})
    // const username = user.select("name")
    if (user == null){
         res.send('User not found')
    }
    
    try{
        // const match = await bcrypt.compare( password, user.password)
        if( await bcrypt.compare( req.body.password, user[0].password) ){

            const user = { username: req.body.username}
            const accessToken = jwt.sign( user, process.env.ACCESS_TOKEN)
            res.json({ accessToken : accessToken})
        } else {
            res.send('Could not login')
        }
    } catch (err) {
        res.json({ message: err.message })
        // res.send(  user[0].password)
    }
})

router.patch('/:id', getUserById, async(req, res) =>{
    if( req.body.name != null ){
        res.user.name = req.body.name
    }
    if( req.body.username != null ){
        res.user.userName = req.body.username
    }
    if ( req.body.password != null){
        res.user.password = req.body.password
    }
    try{
        const UpdatedUser = await res.user.save()
        res.json(UpdatedUser)
    } catch (err){
        res.json({ message: err.message})
    }
})

router.delete('/:id', getUserById, async(req, res) =>{
    try{
        await res.user.remove()
        res.json({ message: 'User deleted'})
    } catch {
        res.status(500).json({ message: 'Something went wrong'})
    }
})

async function getUserById(req, res, next){
    let user
    try{
        user = await User.findById(req.params.id)
        if(user == null) {
            return res.status(404).json({message: 'User not found'})
        }
    } catch (err) {
        res.status(500).json({message: err.message})
    }
    res.user = user
    next()
}

function authenticateJWT( req, res, next){
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(' ')[1]
    if(token == null) return res.sendStatus(401)
    
    jwt.verify( token, process.env.ACCESS_TOKEN, (err, user) => {
        if(err) return res.sendStatus(403)
        req.user = user
        next()
    })
}
module.exports = router