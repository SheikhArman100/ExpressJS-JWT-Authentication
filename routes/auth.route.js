const express = require('express');
const router = express.Router();
const { schemaValidation} =require("../middlewares/zodSchemaValidation");
const { registerSchema, loginSchema } = require('../zod_schema/auth.schema');
const { handleRegistration, handleLogin, handleLogout, handleRefreshToken } = require('../controllers/auth.controller');



//register user
router.post("/register",schemaValidation(registerSchema),handleRegistration)

//login user
router.post("/login",schemaValidation(loginSchema),handleLogin)

//logout
router.get("/logout",handleLogout)

//refresh token handler
router.get("/refreshToken",handleRefreshToken)








//export
module.exports = router;