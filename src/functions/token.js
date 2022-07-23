import util from 'node:util';
import { generateKeyPair } from 'crypto';
const generateKeyPairAsync = util.promisify(generateKeyPair)

const PASS_PHRASE = process.env.PASS_PHRASE ?? 'some secret';

// privateKey: '-----BEGIN ENCRYPTED PRIVATE KEY-----\n' + ... + '-----END ENCRYPTED PRIVATE KEY-----\n'
// publicKey: '-----BEGIN PUBLIC KEY-----\n' + ... + '-----END PUBLIC KEY-----\n',
/**
 * @returns Promise<{ publicKey, privateKey }>
 */
function generateRSA256KeyPair() {
    return generateKeyPairAsync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: {
            type: 'spki',
            format: 'pem'
        },
        privateKeyEncoding: {
            type: 'pkcs8',
            format: 'pem',
            cipher: 'aes-256-cbc',
            passphrase: PASS_PHRASE
        }
    })
}

export {
    generateRSA256KeyPair,
    PASS_PHRASE
}
