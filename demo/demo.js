var pamlib = require('../build/default/pam.node');
var pam = new pamlib.PAM();
console.log("Username: ditesh, password: mypass, output: " + pam.authenticate("system-auth", "ditesh", 'mypass')); // should output false 
console.log("Username: ditesh, password: mypass, output: " + pam.authenticate("system-auth", "ditesh", 'efg')); // should output true

