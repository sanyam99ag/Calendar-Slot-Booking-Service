const mongoose = require('mongoose')

const userSchema = new mongoose.Schema({
    email: {
        type: String,
        required: true
    },
    username: {
        type: String,
        required: true
    },
    password: {
        type: String,
        required: true
    },
    slots: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: "slot"
    }],
    bookedSlots: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: "slot"
    }],
    api_url: String
});

module.exports = new mongoose.model('user', userSchema )
