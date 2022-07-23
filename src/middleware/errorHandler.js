function errorHandler(err, req, res, next) {
    res.status(500).send({ errors: [ `something wrong: ${err.message}` ]})
}

export default errorHandler;
