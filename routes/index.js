var express = require('express');
var router = express.Router();
var bignum = require('bignum');
var rsa = require('./rsa-bignum.js');
var sha256 = require('js-sha256');
var Base64 = require('./base64.js');

function convertFromHex(hex) {
    var hex = hex.toString();//force conversion
    var str = '';
    for (var i = 0; i < hex.length; i += 2)
        str += String.fromCharCode(parseInt(hex.substr(i, 2)));
    return str;
}
// -- NR TTP
router.post('/nrttp', function(req, res) {
	console.log("---------- FASE 2 ----------")
	console.log(req.body);
	var proofA = bignum(req.body['proof'],16);
	console.log("proofA", proofA.toString());
	//var publicKeyA = bignum(req.body['publicKey[]']);
	var publicAn = bignum(req.body['publicKey[n]'], 16);
	var publicAe = bignum(req.body['publicKey[e]'], 16);
	var publicAbytes = req.body['publicKey[bytes]'];
	console.log("n", publicAn);
	console.log("e", publicAe);

	proof = proofA.powm(publicAe, publicAn);
	console.log("proof 1", proof.toString());

	pr = proof.toString();

	console.log("proof 2", pr);
	
	pr = atob(pr);
	console.log("proof 3", pr);
	

	p = convertFromHex(proof.toString('base64'));

	console.log("p", p);

	res.status(200).send();
	/*
	if(destino == 'servidorNode'){
		//var proof = req.body.proof;
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
			proof:x,
			publicKey:keyB.publicKey.e
		}
		console.log("out", out);
		res.status(200).send(out);
	} else{
		res.status(403).send("403 Forbiden");
	}
	*/
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
