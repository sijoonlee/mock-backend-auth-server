import jwt from 'jsonwebtoken';
import { v4 as uuidV4 } from 'uuid';

import { comparePassword } from '../functions/password.js'
import { generateRSA256KeyPair, PASS_PHRASE } from '../functions/token.js'


function createRouterSignIn(collection) {
    return async function signIn(req, res, next) {
        const result = await collection.findOne({ id: req.body.id }, { projection: { _id: 0, uuid: 1, publicKey: 1,  privateKey: 1, password: 1} })

        if (result && await comparePassword(req.body.password, result.password)) {
            const sessionID = uuidV4()
            const { publicKey, privateKey } = await generateRSA256KeyPair()

            const updateOneResult = await collection.updateOne({ id: req.body.id, sessionID: result.sessionID }, { $set: { sessionID, publicKey, privateKey } }) // update uuid
            const authToken = jwt.sign({id: req.query.id, sessionID }, { key: privateKey, passphrase: PASS_PHRASE } , { algorithm: "RS256", expiresIn: "12h" })
            res.cookie('x-authToken', authToken)
            res.send({ data: { isSignedIn: true }})
        } else {
            next(new Error('user does not exist or wrong password'))
        }
    }
}

export default createRouterSignIn;
