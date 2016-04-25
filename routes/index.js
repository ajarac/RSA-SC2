var express = require('express');
var router = express.Router();
var bignum = require('bignum');
var rsa = require('./rsa-bignum.js');
var sha256 = require('js-sha256');
var Base64 = require('./base64.js');
var nrModel = require('mongoose').model('nrModel');
function asc2hex(pStr) {
	tempstr = '';
	for (a = 0; a < pStr.length; a = a + 1) {
		tempstr = tempstr + pStr.charCodeAt(a).toString(16);
	}
	return tempstr;
}
function hex2asc(pStr) {
	tempstr = '';
	for (b = 0; b < pStr.length; b = b + 2) {
		tempstr = tempstr + String.fromCharCode(parseInt(pStr.substr(b, 2), 16));
	}
	return tempstr;
}

var usuarioB = 'servidorNode';
// -- NR TTP
router.post('/nrttp', function(req, res) {
	console.log("---------- FASE 2 ----------")
	var proofA = bignum(req.body['proof'],16);
	var publicAn = bignum(req.body['publicKey[n]'], 16);
	var publicAe = bignum(req.body['publicKey[e]'], 16);

	proof = proofA.powm(publicAe, publicAn);
	
	console.log("proof en bignum: ", proof.toString(16));
	pr = hex2asc(proof.toString(16));
	
	//pr = proof.toBuffer().toString('base64');

	console.log("proof en texto plano: ", pr);
	
	p = pr.split('-');
	console.log("proof separados", p);

	if(p[0] == usuarioB && req.body.user != undefined){
		
		proof = req.body.user + '-2-' + p[2];

		var bytes = asc2hex(proof);
		console.log("bytes", bytes);

		var b = bignum(bytes, 16);

		console.log("b", b.toString());

		console.log("Generando key...");
		var keyB = rsa.generateKeys(1024);

		console.log("Encriptando proof..");
		var x = keyB.privateKey.encrypt(b);

		console.log("Encriptado", x.toString());
		var norepModel = new nrModel({
			idA:req.body.user,
			idB:usuarioB,
			publicaA:{
				e:publicAe.toString(),
				n:publicAn.toString()
			},
			prueba:pr
		})
		norepModel.save(function (err){		
			res.status(200).send({
				proof:x.toString(16),
				publicKey:{
					n:keyB.publicKey.n.toString(16),
					e:keyB.publicKey.e.toString(16)
				},
				user:usuarioB
			});
		});
	} else{
		res.status(400).send('Destino incorrecto!');
	}
	
});

router.post('/ttp', function (req, res){
	console.log("---------- FASE 4 ----------")
	console.log("BODY", req.body);
	if( req.body.user != undefined){
		nrModel.find({
			idA:req.body.user,
			idB:usuarioB
		}, function (err, result){
			if(err) throw err;	
			var proofA = bignum(req.body['proof'],16);
			var publicAn = bignum(req.body['publicKey[n]'], 16);
			var publicAe = bignum(req.body['publicKey[e]'], 16);
			
			proof = proofA.powm(publicAe, publicAn);
			console.log("proof en bignum: ", proof.toString(16));
			pr = hex2asc(proof.toString(16));
			
			//pr = proof.toBuffer().toString('base64');

			console.log("proof en texto plano: ", pr);
			
			p = pr.split('-');
			console.log("proof separados", p);
			result.remove();

			res.status(200).send();
		})
	} else{
		res.status(400).send("Usuario incorrecto");
	}

});



module.exports = router;
