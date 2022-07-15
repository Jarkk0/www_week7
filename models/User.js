const mongoose = require('mongoose');


const Schema = mongoose.Schema;

let userSchema = new Schema({
    username: {type: 'string'},
    password: {type: 'string'}
});

module.exports =mongoose.model('users', userSchema);