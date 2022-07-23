
import { MongoMemoryServer } from 'mongodb-memory-server';
import { MongoClient } from 'mongodb';
import express from 'express';
import fs from 'fs';
import cookieParser from 'cookie-parser';

import createAuthTokenChecker from './src/middleware/createAuthTokenChecker.js';
import errorHandler from './src/middleware/errorHandler.js';

import createRouterSignUp from './src/router/createRouterSignUp.js';
import createRouterSignIn from './src/router/createRouterSignIn.js';
import createRouterRefreshAuthToken from './src/router/createRouterRefreshAuthToken.js';
import createRouterVerifyAuthToken from './src/router/createRouterVerifyAuthToken.js';
import createRouterGetPublicKey from './src/router/createRouterGetPublicKey.js';

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
    const authTokenChecker = createAuthTokenChecker(collection)

    app.post('/verify-auth-token', authTokenChecker, createRouterVerifyAuthToken(collection), errorHandler)

    app.get('/get-public-key', authTokenChecker, createRouterGetPublicKey(collection), errorHandler);

    // renew auth token without checking password - only possible when auth token has not been expired
    app.post('/refresh-auth-token', authTokenChecker, createRouterRefreshAuthToken(collection), errorHandler)

    // check password and make new auth token
    app.post('/sign-in', authTokenChecker, createRouterSignIn(collection), errorHandler)

    app.post('/sign-up', authTokenChecker, createRouterSignUp(collection), errorHandler)

    app.listen(port, () => {
        console.log(`Example app listening on port ${port}`)
    })
})();

