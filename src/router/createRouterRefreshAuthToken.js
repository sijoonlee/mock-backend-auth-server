import jwt from 'jsonwebtoken';
import { PASS_PHRASE } from '../functions/token.js';
import { v4 as uuidV4 } from 'uuid';


function createRouterRefreshAuthToken(collection) {
    return async function refreshAuthToken (req, res, next) {
        const result = await collection.findOne({ id: req.body.id }, { projection: { _id: 0, sessionID: 1, publicKey: 1,  privateKey:1, password: 1} })
        
        // TODO: put authToken to cookie or header and use middleware for authToken
        const validated = jwt.verify(res.locals.userAuthToken, result.publicKey)
        if (validated.id === req.body.id && validated.sessionID === result.sessionID) {
            const sessionID = uuidV4();
            const authToken = jwt.sign({id: req.body.id, sessionID }, { key: result.privateKey, passphrase: PASS_PHRASE } , { algorithm: "RS256", expiresIn: "12h" })
            const updateOneResult = await collection.updateOne({ id: req.body.id, sessionID: validated.sessionID }, { $set: { sessionID } }) // update uuid
            res.cookie('x-authToken', authToken);
            res.send({ data: { isAuthTokenRefreshed: true }});
        } else {
            next(new Error('failed to sign in'))
        }  
    }
}

export default createRouterRefreshAuthToken;
