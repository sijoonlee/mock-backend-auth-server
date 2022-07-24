function createRouterGetPublicKey(collection) {
    return async function getPublicKey (req, res, next) {
        // const result = await collection.findOne({ id: req.query.id }, { projection: { _id: 0, publicKey: 1 } })
        // res.send({ data: { publicKey: result.publicKey } })
        res.send({})
    }
}

export default createRouterGetPublicKey;
