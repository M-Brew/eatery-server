const router = require("express").Router();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const User = require("../models/User.model");
const RefreshToken = require("../models/RefreshToken.model");
const {
    signUpValidation,
    signInValidation,
} = require("../validation/authValidation");
const { ACCESS_TOKEN_SECRET, REFRESH_TOKEN_SECRET, SECRET_EXPIRY } = process.env;

const generateAccessToken = (payload) => {
    return jwt.sign(payload, ACCESS_TOKEN_SECRET, {
        expiresIn: SECRET_EXPIRY,
    });
};

const generateRefreshToken = (payload) => {
    return jwt.sign(payload, REFRESH_TOKEN_SECRET);
};

router.post("/sign-up", async (req, res) => {
    try {
        const { firstName, lastName, email, password } = req.body;

        const { valid, errors } = signUpValidation({
            firstName,
            lastName,
            email,
            password,
        });
        if (!valid) {
            return res.status(400).json(errors);
        }

        const existingEmail = await User.findOne({ email });
        if (existingEmail) {
            return res.status(401).json({ error: "User with email exists" });
        }

        const hashedPassword = await bcrypt.hash(password, 12);

        const newUser = new User({
            firstName,
            lastName,
            email,
            password: hashedPassword,
        });
        await newUser.save();

        const payload = {
            id: newUser._id,
            firstName: newUser.firstName,
            role: newUser.role,
        };
        const accessToken = generateAccessToken(payload);
        const refreshToken = generateRefreshToken(payload);

        await RefreshToken({ token: refreshToken }).save();

        return res.status(201).json({
            accessToken,
            refreshToken,
        });
    } catch (error) {
        console.log(error);
        return res.sendStatus(500);
    }
});

router.post("/sign-in", async (req, res) => {
    try {
        const { email, password } = req.body;

        const { valid, errors } = signInValidation({ email, password });
        if (!valid) {
            return res.status(400).json({ errors });
        }

        const user = await User.findOne({ email });
        if (!user) {
            return res.status(401).json({ error: "Invalid email or password" });
        }

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(401).json({ error: "Invalid email or password" });
        }

        const payload = {
            id: user._id,
            firstName: user.firstName,
            role: user.role,
        };
        const accessToken = generateAccessToken(payload);
        const refreshToken = generateRefreshToken(payload);

        await RefreshToken({ token: refreshToken }).save();

        return res.status(200).json({
            accessToken,
            refreshToken,
        });
    } catch (error) {
        console.log(error);
        return res.sendStatus(500);
    }
});

router.post("/admin-sign-in", async (req, res) => {
    try {
        const { email, password } = req.body;

        const { valid, errors } = signInValidation({ email, password });
        if (!valid) {
            return res.status(400).json({ errors });
        }

        const user = await User.findOne({ email });
        if (!user) {
            return res.status(401).json({ error: "Invalid email or password" });
        }

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(401).json({ error: "Invalid email or password" });
        }

        if (user.role !== "admin") {
            return res.status(403).json({ error: "Unauthorized" });
        }

        const payload = {
            id: user._id,
            firstName: user.firstName,
            role: user.role,
        };
        const accessToken = generateAccessToken(payload);
        const refreshToken = generateRefreshToken(payload);

        await RefreshToken({ token: refreshToken }).save();

        return res.status(200).json({
            accessToken,
            refreshToken,
        });
    } catch (error) {
        console.log(error);
        return res.sendStatus(500);
    }
});

router.post("/token", async (req, res) => {
    try {
        const { token } = req.body;
        if (!token) {
            return res.sendStatus(401);
        }

        const refreshToken = await RefreshToken.findOne({ token });
        if (!refreshToken) {
            return res.sendStatus(403);
        }

        const payload = jwt.verify(
            refreshToken.token,
            process.env.REFRESH_TOKEN_SECRET
        );
        const accessToken = generateAccessToken({
            id: payload.id,
            userName: payload.userName,
            role: payload.role,
        });

        return res.status(200).json({ accessToken });
    } catch (error) {
        console.log(error);
        return res.sendStatus(500);
    }
});

router.post("/sign-out", async (req, res) => {
    try {
        const { token } = req.body;

        if (!token) {
            return res.sendStatus(401);
        }

        const refreshToken = await RefreshToken.findOne({ token });
        if (!refreshToken) {
            return res.sendStatus(401);
        }

        await RefreshToken.findByIdAndDelete(refreshToken._id);

        return res.status(204).json({ message: "Signed out successfully" });
    } catch (error) {
        console.log(error);
        return res.sendStatus(500);
    }
});

module.exports = router;
