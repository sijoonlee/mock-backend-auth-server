function authTokenChecker(req, res, next) {
    console.log("auth token", JSON.stringify(req.headers))
    console.log(req.cookies)
    next()
}

export default authTokenChecker;
