const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
    username: { type: String,  required: true, unique: true,  trim: true},
    email: { type: String, required: true,  unique: true, trim: true,  lowercase: true},
    passwordHash: {type: String,   required: true },
    role: {type: String,  enum: ['user', 'admin'], default: 'user' },
    refreshToken: {type: String}
},
   {
    timestamps: true
});


userSchema.pre('save', async function (next) {
    if(!this.isModified('passwordHash')) return next();
    const salt = await bcrypt.genSalt(10);
    this.passwordHash = await bcrypt.hash(this.passwordHash, salt);
    next();
});

userSchema.methods.toJSON = function(){
    const user = this.toObject();
    delete user.passwordHash; 
    return user; 
};

userSchema.statics.findByEmail = function(email){
    return this.findOne({email});
};
module.exports = mongoose.model('User', userSchema, 'users');
