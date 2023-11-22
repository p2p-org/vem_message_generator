const crypto = require('crypto');

const args = process.argv.slice(2);
function getOptionValue(optionName) {
    const index = args.indexOf(optionName);
    return index !== -1 && args[index + 1] !== undefined ? args[index + 1] : null;
}

const ecdhPrivateKey = getOptionValue('--ecdhPrivateKey');
const encryptedMessage = getOptionValue('--encryptedMessage');
if (!ecdhPrivateKey || !encryptedMessage) {
    console.error('Error: Required options are missing.');
    process.exit(1); // Exit with an error code
}

const concatKDF = (secret, s1, keyLen) => {
    let hashSum = Buffer.from('')
    for (let ctr = 1; hashSum.length < keyLen; ctr++) {
        const ctrs = Buffer.from([ctr >> 24, ctr >> 16, ctr >> 8, ctr]) // Buffer.from([ctr >> 24, ctr >> 16, ctr >> 8, ctr])
        const tmp = [hashSum, crypto.createHash('sha256').update(Buffer.concat([ctrs, secret, s1])).digest()];
        console.log(tmp);
        hashSum = Buffer.concat(tmp);
    }
    return hashSum.slice(0, keyLen)
};

const deriveKeys = (secret, s1, keyLen) => {
    const keys = concatKDF(secret, s1, keyLen * 2)
    const encKey = keys.slice(0, keyLen)
    const macKey = crypto.createHash('sha256').update(keys.slice(keyLen, keyLen * 2)).digest()
    return {encKey, macKey}
};

const messageTag = (macKey, message, s2) => {
    return crypto.createHmac('sha256', macKey).update(message).update(s2).digest()
}

const symDecrypt = (key, ct) => {
    const c = crypto.createCipheriv('aes-128-ctr', key, ct.slice(0, 16))
    const m = Buffer.alloc(ct.length - 16)
    c.update(ct.slice(16)).copy(m)
    return m
}

const decrypt = (privateKey, msg) => {
    const ecdh = crypto.createECDH('prime256v1');
    ecdh.setPrivateKey(privateKey);
    const epk = msg.slice(0, 65)
    const message = msg.slice(65, msg.length - 32)
    const sharedSecret = ecdh.computeSecret(epk);
    const {encKey, macKey} = deriveKeys(sharedSecret, Buffer.alloc(0), 16)
    const tag = messageTag(macKey, message, Buffer.alloc(0))
    if (tag.toString('hex') !== msg.slice(msg.length - 32).toString('hex')) {
        throw new Error('tag mismatch')
    }
    return symDecrypt(encKey, message)
}

const client = crypto.createECDH('prime256v1');
client.setPrivateKey(ecdhPrivateKey, 'hex')
const decryptedMessage = decrypt(client.getPrivateKey(), Buffer.from(encryptedMessage, 'base64'));

console.log(decryptedMessage.toString('utf8'));