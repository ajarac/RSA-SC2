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

function nrttp(){
	if(texto == '' || user == ''){
		alert("Escribe algo!");
	} else{
		console.log("---------- FASE 1 ----------")
		var texto = $('#text').val();
		var user = $('#user').val();
		console.log("texto", texto);
		console.log("user", user);
		var hash = sha256(texto);
		var proof = (destino + '-' + hash);
		console.log("proof", proof);
		var bytes = "";
		for(i=0;i<proof.length;i++){
			bytes+= proof.charCodeAt(i);
		}
		console.log("Bytes", bytes);
		var keyA = rsa.generateKeys(1024);


		var b = bigInt(bytes);
		console.log("Original: " + b);

		var x = keyA.privateKey.encrypt(b);
		console.log(x);
		console.log("Encriptado: " + x);

		var y = keyA.publicKey.decrypt(x);
		console.log("Desencriptado: " + y);

		var clavePublica = keyA.publicKey.n.value;
		console.log("KEY PUBLIC", clavePublica);
		$.ajax({
			url:"/nrttp",
			method:"POST",
			data:{
				destino:destino,
				msg:texto,
				user:user,
				proof:x.value,
				publicKey:clavePublica
			},
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
		})
	}
}