const jwt = require("jsonwebtoken");
require("dotenv").config();

module.exports.checkAuth = (req, res, next) => {
    try {
        const authHeader = req.headers["authorization"];
        const token = authHeader && authHeader.split(" ")[1];

        if (!token) return res.sendStatus(401);

        jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (error, payload) => {
            if (error) {
                return res.sendStatus(401);
            }

            req.user = payload;
            next();
        });
    } catch (error) {
        console.log(error);
        return res.sendStatus(500);
    }
};

module.exports.checkAdminAuth = (req, res, next) => {
    try {
        const authHeader = req.headers["authorization"];
        const token = authHeader && authHeader.split(" ")[1];

        if (!token) return res.sendStatus(401);

        jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (error, payload) => {
            if (error) {
                return res.sendStatus(401);
            }

            if (payload.role !== 'admin') {
                return res.sendStatus(403);
            }

            req.user = payload;
            next();
        });
    } catch (error) {
        console.log(error);
        return res.sendStatus(500);
    }
};

