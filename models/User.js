var mongoose = require('mongoose');
var uniqueValidator = require('mongoose-unique-validator');
var crypto = require('crypto');
var jwt = require('jsonwebtoken');
var secret = require('../config').secret;



// https://mongoosejs.com/docs/validation.html for validations
// Validations: Checks that are run before the model gets saved. This way we ensure that no dirty data is pushed in our db.

// timestamps: true creates a createdAt and updatedAt field automatically
// index: true is added to optimize quieries that use these fields

// https://github.com/blakehaswell/mongoose-unique-validator
// I want the usernames and emails to be unique; mongoose does not support this functionality. We can use the plugin mongoose-unique-validator
var UserSchema = new mongoose.Schema({
  username: {
    type: String,
    lowercase: true,
    unique: true,
    required: [
      true,
      "can't be blank"
    ],
    match: [/^[a-zA-Z0-9]+$/, 'is invalid'],
    index: true
  },
  email: {
    type: String,
    lowercase: true,
    unique: true,
    required: [
      true,
      "can't be blank"
    ],
    match: [/\S+@\S+\.\S+/, 'is invalid'],
    index: true
  },
  bio: String,
  image: String,
  hash: String,
  salt: String
}, {timestamps: true});


UserSchema.plugin(uniqueValidator, {message: 'is already taken.'})


/*
  ** Method to hash passwords. 
  First we generate a random salt for each user
  Then we use crypto.crypto.pbkdf2Sync() to generate the hashes using the salt
  pbkdf2Sync() takes 5 params: the password to hash, thesalt, the number of times to hash the pass,the length of the hash and the algorithm

 */
UserSchema.methods.setPassword = function(password) {
  this.salt = crypto.randomBytes(16).toString('hex');
  this.hash = crypto.pbkdf2Sync(password, this.salt, 10000, 512, 'sha512').toString('hex');
}

/*
  ** Method to check if pass is valid.
  We have to run the pbkdf2 with the same number of iterations and key length as we did in our setPassword function, with the salt of the user.
  Then wecheckif the resulting hash matches the one that's stored in the db.

*/
UserSchema.methods.validPassword = function(password) {
  var hash = crypto.pbkdf2Sync(password, this.salt, 100000, 512, 'sha512').toString('hex');

  return this.hash === hash;
}

/*
  ** Method for generating a JWT. 

  JWT's are the tokens that will be passed to the front-end that will be used for authentication.
  
  The JWT contains a payload(assertions) that is signed by the back-end, so the payload can be read by both the front
  and the back-end BUT can only be validated by the back-end.

  exp is a UNIX  timestamp in seconds that determines when the token will expire. We'll set the token expiration to 60 days in the future.
*/
UserSchema.methods.generateJWT = function() {
  var today = new Date();
  var exp = new Date(today);
  exp.setDate(today.getDate() + 60);

  return jwt.sign({
    id: this._id,
    username: this.username,
    exp: parseInt(exp.getTime() / 1000),
  }, secret);
}

/*
  ** Method to get the JSON representaion of the user that will be passed to the front-end during authentication.

  * This JSON should be returned only to that specific user since it contains sensitive info likethe JWT.
*/

UserSchema.methods.toAuthJSON = function() {
  return {
    username: this.username,
    email: this.email,
    token: this.generateJWT(),
    bio: this.bio,
    image: this.image
  }
}

// Register the schema with mongoose, afou to kanw auto the user model can be accessed from anywhere in the app by calling mongoose.model('User)
mongoose.model('User', UserSchema);