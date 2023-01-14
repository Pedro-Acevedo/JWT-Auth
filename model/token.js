const mongoose = require('mongoose')
const tokenSchema = new mongoose.Schema({
    token: String,
    user: {
        type: mongoose.Schema.Types.ObjectId,
        ref:'User'
    } 
})


module.exports = mongoose.model('token', tokenSchema)