const express = require("express");
const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');
var jwt = require('jsonwebtoken');

const PORT = 3000;
const SALTROUNDS = 10;
const JWT_SECRET = "JWT_SECRET";

const app = express();

app.use(express.json());

const userList = [];
var database = [];

app.get("/", (req, res) => {
    res.json({ "message": "Welcome, let's get started" });
})

app.post("/api/register", async (req, res) => {
    var { username, password, email, full_name, age, gender } = req.body;

    if (username && password && email) {
        if (!userExist(email)) {
            var user_id = await createUser(username, password, email, full_name, age, gender);
            var token = "";
            await jwt.sign({ payload: { username, password: await bcrypt.hash(password, SALTROUNDS) } }, 'JWT_SECRET', { expiresIn: 60 * 60 }, (err, asyncToken) => {
                if (err) throw err;
                token = asyncToken;
            });
            res.status(200);
            res.json({
                "status": "success",
                "message": "User successfully registered!",
                "data": {
                    "user_id": user_id,
                    "username": username,
                    "email": email,
                    "full_name": full_name,
                    "age": age,
                    "gender": gender
                }
            });
        }
        else {
            res.status(403);
            res.json({
                "status": "EMAIL_EXISTS",
            });
        }
    }
    else {
        res.status(400);
        res.json({
            "status": "error",
            "code": "INVALID_REQUEST",
            "message": "Invalid request. Please provide all required fields: username, email, password, full_name."
        });
    }

})

app.post("/api/token", async (req, res) => {
    try {
        var token = "";
        await jwt.sign({ payload: req.body }, JWT_SECRET, { expiresIn: 60 * 60 }, (err, asyncToken) => {
            if (err) throw err;
            token = asyncToken;
        });
        res.status(200);
        res.json({
            "status": "success",
            "message": "Access token generated successfully.",
            "data": {
                "access_token": token,
                "expires_in": 3600
            }
        });
    }
    catch (err) {
        res.status(500);
        res.json({
            "status": "INVALID_CREDENTIALS",
            "message": "Invalid credentials. The provided username or password is incorrect."
        })
    }
})

app.post("/api/data", async (req, res) => {
    try {
        const token = req.headers['authorization'].split(" ")[1];
        const user = await verifyToken(token, res);
        const data = req.body;
        data.user = user;
        database.push(data);
        res.json({
            "status": "success",
            "message": "Data stored successfully."
        })
    } catch (err) {
        res.sendStatus(401);
    }
})

app.get("/api/data/:key", async (req, res) => {
    try {
        const token = req.headers['authorization'].split(" ")[1];
        const user = await verifyToken(token, res);
        const key = req.params.key;
        const data = database.find(userData => userData.user == user && userData.key == key);
        if (data && data.key && data.value) {
            res.json({
                "status": "success",
                "data": {
                    "key": data.key,
                    "value": data.value
                }
            });
        }
        else {
            res.status(401);
            res.json({ "status": "KEY_NOT_FOUND", "message": "The provided key does not exist in the database." })
        }
    }
    catch (err) {
        console.log(err);
    }

})

app.put("/api/data/:key", async (req, res) => {
    try {
        const token = req.headers['authorization'].split(" ")[1];
        const user = await verifyToken(token, res);
        const key = req.params.key;
        if (user && key) {
            var userData = database.filter(data => data.user == user);
            if (userData.length > 0) {
                var updatedData = database.map(data => {
                    if (data.user == user && data.key == key) {
                        data.value = req.body.value || "";
                    }
                    return data;
                })
                database = updatedData;
                res.json({
                    "status": "success",
                    "message": "Data updated successfully."
                });
            }
            else {
                res.status(404);
                res.json({ "status": "USER_HAS_NO_DATA", "message": "User doesn't have any data in the database." });
            }
        }
        else {
            res.status(401);
            res.json({ "status": "KEY_NOT_FOUND", "message": "The provided key does not exist in the database." })
        }
    }
    catch (err) {
        console.log(err);
    }
})

app.delete("/api/data/:key", async (req, res) => {
    try {
        const token = req.headers['authorization'].split(" ")[1];
        const user = await verifyToken(token, res);
        const key = req.params.key;
        const data = database.find(userData => userData.user == user && userData.key == key);
        if (data && data.key && data.value) {
            var updatedData = database.filter(data => data.key !== key);
            database = updatedData;
            res.json({
                "status": "success",
                "message": "Data deleted successfully."
            });
        }
        else {
            res.status(401);
            res.json({ "status": "KEY_NOT_FOUND", "message": "The provided key does not exist in the database." })
        }
    }
    catch (err) {
        console.log(err);
    }

})

const userExist = (email) => {
    return userList.some(user => user.email === email);
}

const createUser = async (username, password, email, full_name, age, gender) => {
    var user_id = uuidv4();
    userList.push({
        user_id,
        username,
        password: await bcrypt.hash(password, SALTROUNDS),
        email,
        full_name,
        age,
        gender
    });
    return user_id;
}

const verifyToken = async (token, res) => {
    var user = "";
    await jwt.verify(token, JWT_SECRET, function (err, decoded) {
        if (err) {
            res.status(403);
            res.json({ "status": "INVALID_TOKEN", "message": "Invalid access token provided" });
            throw err;
        }
        else {
            user = decoded.payload.username;
        }
    });
    return user;
}

app.listen(PORT, () => console.log(`Example app listening on port ${PORT}`))