import jwt from 'jsonwebtoken';
import { PASS_PHRASE } from '../functions/token.js';
import { v4 as uuidV4 } from 'uuid';


function createRouterRefreshAuthToken(collection) {
    return async function refreshAuthToken (req, res, next) {
        const result = await collection.findOne({ id: req.body.id }, { projection: { _id: 0, sessionID: 1, publicKey: 1,  privateKey:1, password: 1} })
        
        let validated = null;
        // TODO: put authToken to cookie or header and use middleware for authToken
        if (result) {
            try {
                validated = jwt.verify(res.locals.userAuthToken, result.publicKey)
            } catch (error) {
                next(error)
            }
        } else {
            next(new Error('user does not exist, please sign up'))
        }
        
        if (validated && validated.id === req.body.id && validated.sessionID === result.sessionID) {
            const sessionID = uuidV4();
            const authToken = jwt.sign({id: req.body.id, sessionID }, { key: result.privateKey, passphrase: PASS_PHRASE } , { algorithm: "RS256", expiresIn: "12h" })
            const updateOneResult = await collection.updateOne({ id: req.body.id, sessionID: validated.sessionID }, { $set: { sessionID } }) // update uuid
            res.cookie('x-authToken', authToken);
            res.send({ data: { isAuthTokenRefreshed: true }});
        } else {
            next(new Error('failed to refresh auth token - please sign in again'))
        }  
    }
}

export default createRouterRefreshAuthToken;
