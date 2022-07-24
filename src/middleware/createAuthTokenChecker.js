import jwt from 'jsonwebtoken';


function createAuthTokenChecker(collection) {
    return async function authTokenChecker(req, res, next) {
        res.locals.userAuthToken = req.cookies['x-authToken']

        // should sign in (or sign up) again
        let isAuthTokenValid = true
        let userInfo = null

        if (req.cookies['x-authToken']) {
            const { id, sessionID } = jwt.decode(req.cookies['x-authToken'])

            userInfo = await collection.findOne({ id, sessionID })

            if (userInfo) {
                try {
                    jwt.verify(req.cookies['x-authToken'], userInfo.publicKey)
                    res.locals.userInfo = userInfo
                } catch (error) {
                    // invalid or expired
                    console.log('error', error)
                    isAuthTokenValid = false;
                    res.cookie('x-authToken', '')
                }
            } else {
                // Non-existing session, clear cookie
                isAuthTokenValid = false;
                res.cookie('x-authToken', '')
            }
        }

        res.locals.isAuthTokenValid = isAuthTokenValid
        res.locals.userInfo = userInfo

        next()
    }
}

export default createAuthTokenChecker;
