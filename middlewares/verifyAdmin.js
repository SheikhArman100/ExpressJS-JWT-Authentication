const verifyAdmin =(req, res, next) => {
        if (!req?.role) return res.sendStatus(401);
        if (req.role!=="ADMIN") return res.sendStatus(401);
        next();
    }


module.exports = verifyAdmin