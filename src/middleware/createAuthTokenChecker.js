function createAuthTokenChecker() {
    return function authTokenChecker(req, res, next) {
        res.locals.userAuthToken = req.cookies['x-authToken']

        next()
    }
}

export default createAuthTokenChecker;
