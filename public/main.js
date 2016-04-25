var destino = 'servidorNode';
rsa = {
    publicKey: function (bits, n, e) {
        this.bits = bits;
        this.n = n;
        this.e = e;
    },
    privateKey: function (p, q, d, publicKey) {
        this.p = p;
        this.q = q;
        this.d = d;
        this.publicKey = publicKey;
    },
    generateKeys: function(bitlength) {
        var p, q, n, phi, e, d, keys = {};
        this.bitlength = bitlength || 2048;
        console.log("Generating RSA keys of", this.bitlength, "bits");
        p = bigInt.prime(this.bitlength / 2);
        do {
            q = bigInt.prime(this.bitlength / 2);
        } while (q.compare(p) === 0);
        n = p.multiply(q);

        phi = p.subtract(1).multiply(q.subtract(1));

        e = bigInt(65537);
        d = bigInt.modInv(e, phi);
        keys.publicKey = new rsa.publicKey(this.bitlength, n, e);
        keys.privateKey = new rsa.privateKey(p, q, d, keys.publicKey);
        return keys;
    }
};


rsa.publicKey.prototype = {
	encrypt: function(m) {
		return m.modPow(this.e, this.n);
	},
	decrypt: function(c) {
		return c.modPow(this.e, this.n);
	}
};

rsa.privateKey.prototype = {
	encrypt: function(m) {
		return m.modPow(this.d, this.publicKey.n);
	},
	decrypt: function(c) {
		return c.modPow(this.d, this.publicKey.n);
	}
};

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
function nrttp(){
	var texto = $('#text').val();
	var user = $('#user').val();
	if(texto == '' || user == ''){
		alert("Escribe usuario y texto!");
	} else{
		console.log("---------- FASE 1 ----------")
		console.log("texto", texto);

		console.log("Creando proof...");
		var proof = destino + '-1-' + sha256(texto);
		console.log("proof", proof);

		bytes = asc2hex(proof);

		console.log("bytes", bytes);
		var b = bigInt(bytes, 16);
		console.log("b", b.toString());

		console.log("Generando key...");
		var keyA = rsa.generateKeys(1024);

		console.log("Encriptando proof... ");
		var x = keyA.privateKey.encrypt(b);
		
		console.log("Encriptado: " + x.toString());
		
		var y = keyA.publicKey.decrypt(x);
		console.log("Desencriptado: " + hex2asc(y.toString(16)));
		
		var clavePublica = keyA.publicKey.n.value;
		console.log("Enviando proof..");
		$.ajax({
			url:"/nrttp",
			method:"POST",
			data:{
				proof:x.toString(16),
				publicKey:{
					n:keyA.publicKey.n.toString(16),
					e:keyA.publicKey.e.toString(16)
				},
				user:user
			},
			success: function(data){
				console.log("------------FASE 3-----------");
				console.log("data", data);
				var proof = bigInt(data['proof'], 16);
				console.log("proof", proof.toString());

				var publicKeyBn = bigInt(data['publicKey']['n'], 16);
				var publicKeyBe = bigInt(data['publicKey']['e'], 16);

				proof = proof.modPow(publicKeyBe, publicKeyBn);
				console.log("proof en bigint", proof.toString(16));

				pr = hex2asc(proof.toString(16));

				console.log("proof en texto plano", pr);
				pr = pr.split('-');

				if(pr[0] != user || parseInt(pr[1]) != 2){
					alert("Error en fase 3");
				} else{
					proof = destino+ '-3-' + texto;
					console.log("Proof a enviar", proof);
					bytes = asc2hex(proof);
					console.log("bytes", bytes);
					var b = bigInt(bytes, 16);
					console.log("b", b.toString());
					console.log("Encriptando proof... ");
					var x = keyA.privateKey.encrypt(b);
					console.log("Encriptado: " + x.toString());
					
					$.ajax({
						url:"/ttp",
						method:"POST",
						data:{
							proof:x.toString(16),
							publicKey:{
								n:keyA.publicKey.n.toString(16),
								e:keyA.publicKey.e.toString(16)
							},
							user:user
						},
						success: function(data){
							alert("Entregao correctamente!");
						}
					})
				}
			}
			/*
			success:function (data){
				console.log("---------- FASE 3 ----------")
				console.log("RESPUESTA", data);
				var k = Math.round(Math.random()*10000);
				proof = (destino+'-'+k);
				bytes = "";
				for(i=0;i<proof.length;i++){
					bytes+= proof.charCodeAt(i);
				}
				console.log("Bytes", bytes);
				b = bigInt(bytes);
				console.log("Original: "+b);
				x = keyA.privateKey.encrypt(b);
				console.log("Encriptado: ", x);
				$.ajax({
					url:"/ttp",
					method:"POST",
					data:{
						destino:destino,
						k:k,
						proof:x.value,
						user:user
					},
					success:function (data){
						alert("FIN nrttp");
						console.log("FIN", data);
					}
				})
			}
			*/
		})
	}
}