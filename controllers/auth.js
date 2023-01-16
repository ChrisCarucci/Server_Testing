import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import User from "../models/User.js";


// Register the User - essentially like an API call

export const register = async (req, res) => {
try {
    const {
        firstName,
        lastName,
        email,
        password,
        picturePath,
        friends,
        location,
        occupation
    } = req.body;

    // Encrypt the password from the req.body then hash it.

    const salt = await bcrypt.genSalt();
    const passwordHash = await bcrypt.hash(password, salt);

    const newUser = new User({
        firstName,
        lastName,
        email,
        password: passwordHash,
        picturePath,
        friends,
        location,
        occupation,
        viewedProfile: Math.floor(Math.random() * 10000),
        impressions: Math.floor(Math.random() * 10000)
    })

    const savedUser = await newUser.save();

    // If correct info send the user a status code.
    res.status(201).json(savedUser)

} catch (error) {
    res.status(500).json( { error: error.message })
}
};


// Login the User + check password

export const login = async (req, res) => {
    try {
        // Take email from req.body
        const {email, password } = req.body;
        // Search Mongoose for user via above email
        const user = await User.findOne({ email: email})

        if (!user) return res.status(500).json({ msg: "User does not exist."})

        // Check if the password matches with the stored password.
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json( { msg: "Invalid credentials.." } )
        
        const token = jwt.sign( { id: user.id }, process.env.JWT_SECRET);
        // Make sure to not accidentally display user pass on frontend..!
        delete user.password;

        // COnfirm Creation
        res.status(200).json({ token, user })

    } catch (error) {
        res.status(500).json({ error: error.message})
    }
}