var mongoose = require('mongoose'),
	Schema = mongoose.Schema;

var nrModel = new Schema({
	id1: {type: String},
	id2: {type: String},
	publicaA: [{type:Number}],
	publicaB: [{type:Number}],
	contenido: {type:String},
	prueba:{type:String}
});

module.exports = mongoose.model('nrModel', nrModel);