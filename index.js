import bodyParser from 'body-parser';
import util from 'node:util';
import { generateKeyPair } from 'crypto';
const generateKeyPairAsync = util.promisify(generateKeyPair)
import { MongoMemoryServer } from 'mongodb-memory-server';
import { MongoClient } from 'mongodb';
import jwt from 'jsonwebtoken';
import express from 'express';
import fs from 'fs';


(async () => {
    const app = express()
    const port = 3000
    
    const mongoServer = await MongoMemoryServer.create();
    const connection = await MongoClient.connect(mongoServer.getUri(), {});
    const database = connection.db('auth-db');
    const collection = database.collection("user")
 
    // publicKey = fs.readFileSync('publicKey.txt');

    app.use(bodyParser.json());

    app.get('/refresh-key', (req, res) => {
        res.send('Hello World!')
    })

    app.post('/authenticate', async (req, res) => {
        console.log(req.body.id)


        const result = await collection.findOne({ id: req.body.id }, { projection: { _id: 0, publicKey: 1 } })
        console.log(result)
        const validated = jwt.verify(req.body.token, result.publicKey)

        res.send(validated)
    })

    app.get('/get-public-key', async (req, res) => {
        const result = await collection.findOne({ id: req.query.id }, { projection: { _id: 0, publicKey: 1 } })
        res.send({ data: { publicKey: result.publicKey } })
    })

    app.get('/add-new-user', async (req, res) => {
        if (req.query?.id) {
            const { publicKey, privateKey } = await generateKeyPairAsync('rsa', {
                modulusLength: 2048,
                publicKeyEncoding: {
                    type: 'spki',
                    format: 'pem'
                },
                privateKeyEncoding: {
                    type: 'pkcs8',
                    format: 'pem',
                    cipher: 'aes-256-cbc',
                    passphrase: 'top secret'
                }
            })
            
            // privateKey: '-----BEGIN ENCRYPTED PRIVATE KEY-----\n' + ... + '-----END ENCRYPTED PRIVATE KEY-----\n'
            // publicKey: '-----BEGIN PUBLIC KEY-----\n' + ... + '-----END PUBLIC KEY-----\n',

            const token = jwt.sign({id: req.query.id }, { key: privateKey, passphrase: 'top secret' } , { algorithm: "RS256", expiresIn: "12h" })
            await collection.updateOne({ id: req.query?.id }, { $set: { publicKey, privateKey, token } }, { upsert: true })
        }
        const result = await collection.findOne({ id: req.query?.id }, { projection: { _id: 0, token: 1 } })

        res.send({ data: { token: result.token } })
    })

    app.listen(port, () => {
    console.log(`Example app listening on port ${port}`)
    })
})();

