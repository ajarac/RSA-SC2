var express = require('express');
var router = express.Router();
var bignum = require('bignum');
var rsa = require('./rsa-bignum.js');
var sha256 = require('js-sha256');


router.post('/nrttp', function(req, res) {
	console.log("---------- FASE 2 ----------")
	console.log("BODY", req.body);
	var destino = req.body.destino;
	if(destino == 'servidorNode'){
		//todo bien
		var user = req.body.user;
		//var proof = req.body.proof;
		var msg = req.body.msg;
		var hash = sha256(msg);
		var proof2 = (user+'-'+hash);
		var publicaA = req.body.publicKey;
		var bytes = "";
		for(i=0;i<proof2.length;i++){
			bytes+= proof2.charCodeAt(i);
		}
		var keyB = rsa.generateKeys(1024);

		var b = bignum(bytes);
		console.log("Original: ", b);

		var x = keyB.privateKey.encrypt(b);
		console.log("Encriptado: " + x);

		var y = keyB.publicKey.decrypt(x);
		console.log("Desencriptado: " + y);

		var out = {
			user:user,
			proof:x,
			publicKey:keyB.publicKey.e
		}
		console.log("out", out);
		res.status(200).send(out);
	} else{
		res.status(403).send("403 Forbiden");
	}
});

router.post('/ttp', function (req, res){
	console.log("---------- FASE 4 ----------")
	console.log("BODY", req.body);
	var B = req.body.destino;
	var k = req.body.k;
	var user = req.body.user;
	var proof = (user +'-'+B+'-'+k);

	var bytes = "";
	for(i=0;i<proof.length;i++){
		bytes+=proof.charCodeAt(i);
	}
	console.log("Bytes", bytes);
	var keyTTP = rsa.generateKeys(1024);

	var b = bignum(bytes);
	console.log("Original:", b);

	var x = keyTTP.privateKey.encrypt(b);
	console.log("Encriptado", x);

	var y = keyTTP.publicKey.decrypt(x);
	console.log("Desencriptado", y);


	var out = {
		a:user,
		b:B,
		k:k,
		proof:x
	}
	res.status(200).send(out);
});



module.exports = router;
