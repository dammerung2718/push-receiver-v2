const crypto = require("crypto");
const ece = require("http_ece");

module.exports = decrypt;

// https://tools.ietf.org/html/draft-ietf-webpush-encryption-03
function decrypt(object, keys) {
  const cryptoKey = object.appData.find((item) => item.key === "crypto-key");

  // treat as unencrypted
  if (!cryptoKey) {
    const newObject = { fcmMessageId: object.id, data: {} };

    for (var i = 0; i < object.appData.length; i++) {
      var key1 = object.appData[i].key;
      if (key1 == "google.c.sender.id") {
        newObject["senderId"] = object.appData[i].value;
        continue;
      }
      var value1 = object.appData[i].value;
      newObject["data"][key1] = value1;
    }

    return newObject;
  }

  // expected encryption
  const salt = object.appData.find((item) => item.key === "encryption");
  if (!salt) throw new Error("salt is missing");
  const dh = crypto.createECDH("prime256v1");
  dh.setPrivateKey(keys.privateKey, "base64");
  const params = {
    version: "aesgcm",
    authSecret: keys.authSecret,
    dh: cryptoKey.value.slice(3),
    privateKey: dh,
    salt: salt.value.slice(5),
  };
  const decrypted = ece.decrypt(object.rawData, params);
  return JSON.parse(decrypted);
}
