var mongoose = require('mongoose'),
	Schema = mongoose.Schema;

var nrModel = new Schema({
	idA: {type: String},
	idB: {type: String},
	publicaA: {
		e:{type:String},
		n:{type:String}
	},
	prueba:{type:String}
});

module.exports = mongoose.model('nrModel', nrModel);