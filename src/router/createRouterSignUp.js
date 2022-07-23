import jwt from 'jsonwebtoken';
import { v4 as uuidV4 } from 'uuid';
import { encryptPassword } from '../functions/password.js'
import { generateRSA256KeyPair, PASS_PHRASE } from '../functions/token.js'


function createRouterSignUp(collection) {
    return async function signUp (req, res, next) {
        try {
            const foundUser = await collection.findOne({ id: req.body.id })
            if (foundUser) {
                throw new Error('id is already taken')
            }
    
            const encryptedPassword = await encryptPassword(req.body.password)
            const { publicKey, privateKey } = await generateRSA256KeyPair()
    
            const sessionID = uuidV4()
            const authToken = jwt.sign({ id: req.body.id, sessionID }, { key: privateKey, passphrase: PASS_PHRASE } , { algorithm: "RS256", expiresIn: "12h" })
    
            const now = new Date()
    
            const updateOneResult = await collection.updateOne(
                { id: req.body.id, createdAt: { $exists: false } },
                { $set: { 
                    id: req.body.id,
                    sessionID,
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
            
            res.cookie('x-authToken', authToken)
            res.send({ data: { isSignedUp: true } })
        } catch (error) {
            next(error)
        }
    }
}

export default createRouterSignUp;
