const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
require('dotenv').config();

const app = express();
const { PORT, MONGO_URI } = process.env;

app.use(cors());
app.use(express.json());

// routes
app.use("/api/auth", require("./routes/authRoutes"));

mongoose.connect(MONGO_URI);
mongoose.connection.once('open', () => console.log('Connected to database successfully'));

app.listen(PORT, () => console.log(`http://localhost:${PORT}`));
