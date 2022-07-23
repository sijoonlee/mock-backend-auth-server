import jwt from 'jsonwebtoken';

function createRouterVerifyAuthToken(collection) {
    return async function verifyAuthToken (req, res, next) {
        const result = await collection.findOne({ id: req.body.id }, { projection: { _id: 0, uuid: 1, publicKey: 1 } })
    
        let isAuthTokenValid;
        try {
            const validated = jwt.verify(res.locals.userAuthToken, result.publicKey)
            isAuthTokenValid = validated.id === req.body.id && validated.id === result.uuid
        } catch (error) {
            isAuthTokenValid = false
        }
        
        res.send({ data: { isAuthTokenValid }})
    }
}

export default createRouterVerifyAuthToken;
