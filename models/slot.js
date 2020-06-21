const mongoose = require("mongoose");

const slotSchema = new mongoose.Schema({
    free: {
        type: Boolean,
        default: true
    },
    date: Date.UTC(),
    time: String,
    owner: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "user"
    },
    booked_by: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "user"
    },
    booked_on: Date.UTC(),
    title: String,
    description: String
});

module.exports = mongoose.model("slot", slotSchema);