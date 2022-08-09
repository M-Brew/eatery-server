const { Schema, model } = require("mongoose");

const refreshTokenSchema = new Schema(
    {
        token: {
            type: String,
            required: true,
        },
    },
    {
        timestamps: {
            createdAt: true,
            updatedAt: true,
        },
    }
);

module.exports = model("RefreshToken", refreshTokenSchema);
