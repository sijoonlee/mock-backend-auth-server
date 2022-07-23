import bcrypt from 'bcrypt';
import util from 'node:util';
import { generateKeyPair } from 'crypto';
const generateKeyPairAsync = util.promisify(generateKeyPair)
import { MongoMemoryServer } from 'mongodb-memory-server';
import { MongoClient } from 'mongodb';
import jwt from 'jsonwebtoken';
import express from 'express';
import fs from 'fs';
import { v4 as uuidV4 } from 'uuid';
import cookieParser from 'cookie-parser';

import authTokenChecker from './src/middleware/authTokenChecker.js';
import errorHandler from './src/middleware/errorHandler.js';

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

/**
 * 
 * @param {string} password 
 * @returns Promise<string>
 */
async function encryptPassword(password) {
    return bcrypt.hash(password, await bcrypt.genSalt(10))
}

/**
 * 
 * @param {string} password 
 * @param {string} encryptedPassword 
 * @returns Promise<boolean>
 */
function comparePassword(password, encryptedPassword) {
    return bcrypt.compare(password, encryptedPassword)
}


(async () => {
    const app = express()
    const port = 3000
    
    const mongoServer = await MongoMemoryServer.create();
    const connection = await MongoClient.connect(mongoServer.getUri(), {});
    const database = connection.db('auth-db');
    const collection = database.collection("user")
 
    // publicKey = fs.readFileSync('publicKey.txt');

    app.use(express.json());
    app.use(cookieParser());

    app.post('/verify-auth-token', async (req, res) => {
        const result = await collection.findOne({ id: req.body.id }, { projection: { _id: 0, uuid: 1, publicKey: 1 } })

        let isAuthTokenValid;
        try {
            const validated = jwt.verify(req.body.authToken, result.publicKey)
            isAuthTokenValid = validated.id === req.body.id && validated.id === result.uuid
        } catch (error) {
            isAuthTokenValid = false
        }
        
        res.send({ data: { isAuthTokenValid }})
    })

    app.get('/get-public-key', async (req, res) => {
        const result = await collection.findOne({ id: req.query.id }, { projection: { _id: 0, publicKey: 1 } })
        res.send({ data: { publicKey: result.publicKey } })
    })

    // renew auth token without checking password - only possible when auth token has not been expired
    app.post('/refresh-auth-token', async (req, res) => {
        const result = await collection.findOne({ id: req.body.id }, { projection: { _id: 0, uuid: 1, publicKey: 1,  privateKey:1, password: 1} })
        
        // TODO: put authToken to cookie or header and use middleware for authToken
        const validated = jwt.verify(req.body.authToken, result.publicKey)
        if (validated.id === req.body.id && validated.uuid === result.uuid) {
            const authToken = jwt.sign({id: req.body.id }, { key: result.privateKey, passphrase: PASS_PHRASE } , { algorithm: "RS256", expiresIn: "12h" })
            res.send({ data: { authToken }})
        } else {
            throw new Error('failed to sign in')
        }  
    })

    // check password and make new auth token
    app.post('/sign-in', async (req, res) => {
        const result = await collection.findOne({ id: req.body.id }, { projection: { _id: 0, uuid: 1, publicKey: 1,  privateKey:1, password: 1} })
        if (result && await comparePassword(req.body.password, result.password)) {
            const uuid = uuidV4()
            const updateOneResult = await collection.updateOne({ id: req.body.id, uuid: result.uuid }, {$set: { uuid } }) // update uuid
            const authToken = jwt.sign({id: req.query.id, uuid }, { key: result.privateKey, passphrase: PASS_PHRASE } , { algorithm: "RS256", expiresIn: "12h" })
            res.send({ data: { authToken }})
        } else {
            throw new Error('user does not exist or wrong password')
        }
    })

    app.post('/sign-up', 
    authTokenChecker,
    async (req, res, next) => {
        try {
            const foundUser = await collection.findOne({ id: req.body.id })
            if (foundUser) {
                next(new Error('id is already taken'))
            }
    
            const encryptedPassword = await encryptPassword(req.body.password)
            const { publicKey, privateKey } = await generateRSA256KeyPair()
    
            const uuid = uuidV4()
            const authToken = jwt.sign({ id: req.body.id, uuid }, { key: privateKey, passphrase: PASS_PHRASE } , { algorithm: "RS256", expiresIn: "12h" })
    
            const now = new Date()
    
            const updateOneResult = await collection.updateOne(
                { id: req.body.id, createdAt: { $exists: false } },
                { $set: { 
                    id: req.body.id,
                    uuid,
                    publicKey, 
                    privateKey, 
                    password: encryptedPassword, 
                    createdAt: now,
                    updatedAt: now
                }},
                { upsert: true }
            )
    
            if (updateOneResult.matchedCount !== 0 || updateOneResult.upsertedCount !== 1) {
                throw new Error("Sorry! Critial DB error") // logically should not happen
            }
    
            const cursor = collection.find({ id: req.body.id });
            if (await cursor.next() && await cursor.hasNext()) { // checking if there're two is enough
                await collection.deleteOne({ _id: updateOneResult.upsertedId })
                throw new Error('Sorry, id is already taken')
            }
            
            res.send({ data: { authToken } })
        } catch (error) {
            next(error)
        }
        
    }, errorHandler)

    app.listen(port, () => {
        console.log(`Example app listening on port ${port}`)
    })
})();

