
var API = {
	errorsMethods: [],
    pathChangeMethods: []
};

API.listenErrorsMethods = function(addErrorCallback, clearErrorsCallback) {
    API.errorsMethods.push({
        addError: addErrorCallback,
        clearErrors: clearErrorsCallback
    })
}

API.addError = function(err) {
    for (i = 0; i < API.errorsMethods.length ; i++) {
        if (API.errorsMethods[i].addError !== undefined) {
            API.errorsMethods[i].addError(err);
        }
    }
}
API.clearErrors = function() {
    for (i = 0; i < API.errorsMethods.length ; i++) {
        if (API.errorsMethods[i].clearErrors !== undefined) {
            API.errorsMethods[i].clearErrors();
        }
    }
}

API.generateRandomString = function(len, charSet) {
    charSet = charSet || 'abcdef0123456789';
    var randomString = '';
    for (var i = 0; i < len; i++) {
        var randomPoz = Math.floor(Math.random() * charSet.length);
        randomString += charSet.substring(randomPoz, randomPoz + 1);
    }
    return randomString;
}

API.generateUUID = function() {
    return API.generateRandomString(8) + "-" + 
        API.generateRandomString(4) + "-" +
        API.generateRandomString(4) + "-" +
        API.generateRandomString(4) + "-" +
        API.generateRandomString(12);
}

API.doRequestPutFile = function(fileData, url, callback) {
    var xhr = new XMLHttpRequest();
    xhr.open("PUT", url, true);
    xhr.onreadystatechange = function() {
        if (xhr.readyState == 4) {
            var res;
            try {
                res = JSON.parse(xhr.responseText)
            } catch (e) {
            }
            if (xhr.status == 200) {
                callback(null, res);
            } else {
                API.addError(xhr.statusText);
                callback(xhr.statusText, res);
            }
        }   
    }
    xhr.send(fileData);
}

API.getUserName = function(userId) {
    if (userId === undefined) return;
    var pair = userId.split("/", 1);
    return pair[0];
}

API.getWebAPIRoot = function() {
    return (window.location.protocol + "//" + window.location.host + projectPath + "/api");
}

API.escapeHTML = function(unsafe) {
    return unsafe.replace(/[&<"']/g, function(m) {
        switch (m) {
            case '&':
                return '&amp;';
            case '<':
                return '&lt;';
            case '"':
                return '&quot;';
            default:
                return '&#039;';
        }
    });
}
