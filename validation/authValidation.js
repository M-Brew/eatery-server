const signUpValidation = ({
    firstName,
    lastName,
    email,
    password,
}) => {
    const errors = {};

    if (!firstName || firstName.trim() === "") {
        errors.firstName = "First name is required";
    }

    if (!lastName || lastName.trim() === "") {
        errors.lastName = "Last name is required";
    }

    if (!email || email.trim() === "") {
        errors.email = "Email is required";
    } else {
        const emailRegex =
            /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
        if (!email.match(emailRegex)) {
            errors.email = "Email must be a valid email address";
        }
    }

    if (!password || password.trim() === "") {
        errors.password = "Password is required";
    } else {
        if (password.length < 8) {
            errors.password = "Password should be a minimum of 8 digits";
        }
    }

    return {
        valid: Object.keys(errors).length < 1,
        errors,
    };
};

const signInValidation = ({ email, password }) => {
    const errors = {};

    if (!email || email.trim() === "") {
        errors.email = "Email is required";
    }

    if (!password || password.trim() === "") {
        errors.password = "Password is required";
    }

    return {
        valid: Object.keys(errors).length < 1,
        errors,
    };
};

module.exports = { signUpValidation, signInValidation };
