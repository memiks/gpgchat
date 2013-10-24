var pub_key = new Array();
var priv_key;

function encrypt() {
  if (window.crypto.getRandomValues) {
    require("./js/openpgp.js");
    require("./js/rawdeflate.js");
    require("./js/rawinflate.js");
    require("./js/base64.js");
    openpgp.init();
    pub_key["moi"] = openpgp.read_publicKey($('#pubkey').text());
    priv_key = openpgp.read_privateKey($('#privkey').text());
    
	if (priv_key.length < 1) {
		util.print_error("No private key found!")
		return;
	}
	
	
	$('#messageEnc').val(eval('('+createJsonMessage("moi", $('#message').val())+')').message);

    $('#messageDec').text(decryptMessage($('#messageEnc').val(),$('#decpassword').text()));

	//var msg = openpgp.read_message($('#messageEnc').val());

    
    return false;
  } else {
    $("#mybutton").val("browser not supported");
    window.alert("Error: Browser not supported\nReason: We need a cryptographically secure PRNG to be implemented (i.e. the window.crypto method)\nSolution: Use Chrome >= 11, Safari >= 3.1 or Firefox >= 21");   
    return false;
  }
}

function receptNewUser(jSonUser, password) {
    if( jsonUser !== null) {
        var jsonUser = eval('('+jSonUser+')');
        if(jsonUser.user !== null && jsonUser.key !== null) {
            pub_key[jsonUser.user] = decryptMessage(jsonUser.key, password);
        }
    }
}


function createJsonMessage(user, message) {
    var JObjectMessage = { "user" : user,
                     "message" : encryptMessageForUser(user,message) ,
                     };
    return JSON.stringify(JObjectMessage, replacer);
    //return JObjectMessage;
}

function encryptMessageForUser(user,message) {
    return openpgp.write_encrypted_message(pub_key[user],message);
}

function decryptMessage(message, password) {
	var msg = openpgp.read_message(message);
	var keymat = null;
	var sesskey = null;
	// Find the private (sub)key for the session key of the message
	for (var i = 0; i< msg[0].sessionKeys.length; i++) {
		if (priv_key[0].privateKeyPacket.publicKey.getKeyId() == msg[0].sessionKeys[i].keyId.bytes) {
			keymat = { key: priv_key[0], keymaterial: priv_key[0].privateKeyPacket};
			sesskey = msg[0].sessionKeys[i];
			break;
		}
		for (var j = 0; j < priv_key[0].subKeys.length; j++) {
			if (priv_key[0].subKeys[j].publicKey.getKeyId() == msg[0].sessionKeys[i].keyId.bytes) {
				keymat = { key: priv_key[0], keymaterial: priv_key[0].subKeys[j]};
				sesskey = msg[0].sessionKeys[i];
				break;
			}
		}
	}
	if (keymat !== null) {
		if (!keymat.keymaterial.decryptSecretMPIs(password)) {
			util.print_error("Password for secret key was incorrect!");
			return;
		}
		return msg[0].decrypt(keymat, sesskey);
	} else {
		util.print_error("No private key found!");
	}
	return null;
}



function replacer(key, value) {
    if (typeof value === 'number' && !isFinite(value)) {
        return String(value);
    }
    return value;
}

function require(script) {
    $.ajax({
        url: script,
        dataType: "script",
        async: false,           // <-- this is the key
        success: function () {
            // all good...
        },
        error: function () {
            throw new Error("Could not load script " + script);
        }
    });
}

function showMessages(str) {
	$('#debug').append(str);
}

