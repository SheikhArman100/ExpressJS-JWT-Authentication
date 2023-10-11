const jwt = require("jsonwebtoken");
const prisma = require("../prisma/client");
const bcrypt = require("bcrypt");

// -----------------------------------------------Registration--------------------------------------------------------------------------------------

const handleRegistration = async (req, res) => {
  try {
    //take the values from req body
    const { username, email, password } = req.body;

    //check for duplicate username and email
    const duplicateUserByUsername = await prisma.user.findUnique({
      where: {
        username,
      },
    });
    const duplicateUserByEmail = await prisma.user.findUnique({
      where: {
        email,
      },
    });
    if (duplicateUserByUsername || duplicateUserByEmail)
      return res.status(409).json({
        message: "Username or email is already used",
      });

    //encrypt password
    const hashPassword = await bcrypt.hash(password, 10);

    //create user in database
    const user = await prisma.user.create({
      data: {
        username,
        email,
        password: hashPassword,
      },
    });

    return res.json({
      message: `${user.username} is created successfully`,
    });
  } catch (error) {
    res.send({
      message: "Registration failed",
    });
  }
};

// ------------------------------------------------------------------Log in-------------------------------------------------------------------------------

const handleLogin = async (req, res) => {
  //extract email and password from the body of req
  const { email, password } = req.body;

  //find the user in db using email
  const findUser = await prisma.user.findUnique({
    where: {
      email,
    },
    include: {
      tokens: true,
    },
  });
  console.log(findUser);
  if (!findUser)
    return res
      .status(401)
      .send({ message: "Email or Password doesn't match with any account" }); //Unauthorized

  // compare password
  const isPasswordMatched = await bcrypt.compare(password, findUser.password);
  if (isPasswordMatched) {
    //create access token
    const newAccessToken = jwt.sign(
      {
        id: findUser.id,
        username: findUser.username,
        email: findUser.email,
        role: findUser.role,
      },
      process.env.ACCESS_TOKEN_SECRET,
      { expiresIn: "10s" }
    );

    //create refresh token
    const newRefreshToken = jwt.sign(
      {
        id: findUser.id,
        username: findUser.username,
        email: findUser.email,
        role: findUser.role,
      },
      process.env.REFRESH_TOKEN_SECRET,
      { expiresIn: "1d" }
    );

    //extract the cookie value from req
    const cookies = req.cookies;

    if (cookies?.jwt) {
      /* 
            Scenario added here: 
                1) User logs in but never uses RT and does not logout 
                2) RT is stolen
                3) If 1 & 2, reuse detection is needed to clear all RTs when user logs in
            */

      //search that refresh token in db
      const refreshToken = cookies.jwt;
      const foundToken = await prisma.token.findUnique({
        where: {
          userId: findUser.id,
          refreshToken: refreshToken,
        },
      });

      if (!foundToken) {
        //could be hacker..
        console.log("attempted refresh token reuse at login!");
        // clear out ALL previous refresh tokens
        await prisma.token.deleteMany({
          where: {
            userId: findUser.id,
          },
        });
      }
      res.clearCookie("jwt", {
        httpOnly: true,
        sameSite: "None",
        secure: true,
      });
    }
    // updating refresh token ith new refresh token
    await prisma.token.create({
      data: {
        userId: findUser.id,
        refreshToken: newRefreshToken,
      },
    });

    // Creates Secure Cookie with refresh token
    res.cookie("jwt", newRefreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: "None",
      maxAge: 24 * 60 * 60 * 1000,
    });

    // Send authorization roles and access token to user
    res.json({ newAccessToken, message: "Logged in  successfully" });
  } else {
    return res
      .status(401)
      .send({ message: "Email or Password doesn't match with any account" }); //Unauthorized
  }
};

//-----------------------------------------------------------------logout-------------------------------------------------------------------------------------
const handleLogout = async (req, res) => {
  const cookies = req.cookies;
  if (!cookies?.jwt) return res.sendStatus(204); //No content
  const refreshToken = cookies.jwt;

  // Is refreshToken in db?
  const findUser = await prisma.token.findUnique({
    where: {
      refreshToken: refreshToken,
    },
  });
  if (!findUser) {
    res.clearCookie("jwt", { httpOnly: true, sameSite: "None", secure: true });
    return res.sendStatus(204);
  }

  // Delete refreshToken in db
  // foundUser.refreshToken = foundUser.refreshToken.filter(rt => rt !== refreshToken);
  // const result = await foundUser.save();
  // console.log(result);
  await prisma.token.delete({
    where: {
      userId: findUser.userId,
      refreshToken: refreshToken,
    },
  });

  res.clearCookie("jwt", { httpOnly: true, sameSite: "None", secure: true });
  res.status(204).json({ message: "Logged out successfully" });
};

// ---------------------------------------------------------------refresh token handler-------------------------------------------------------------------
const handleRefreshToken = async (req, res) => {
  const cookies = req.cookies;
  if (!cookies.jwt) return res.sendStatus(401); //Unauthorized
  const refreshToken = cookies.jwt;
  res.clearCookie("jwt", { httpOnly: true, sameSite: "None", secure: true });

  const findUser = await prisma.user.findUnique({
    where: {
      tokens: [
        {
          refreshToken: refreshToken,
        },
      ],
    },
  });

  // Detected refresh token reuse!
  if (!findUser) {
    jwt.verify(
      refreshToken,
      process.env.REFRESH_TOKEN_SECRET,
      async (err, decoded) => {
        if (err) return res.sendStatus(403); //Forbidden
        console.log("attempted refresh token reuse!");
        const hackedUser = await prisma.user.findUnique({
          where: {
            email: decoded.email,
          },
        });

        const result = await prisma.token.deleteMany({
          where: {
            userId: hackedUser.id,
          },
        });
        console.log(result);
      }
    );
    return res.sendStatus(403); //Forbidden
  }

  // evaluate jwt
  jwt.verify(
    refreshToken,
    process.env.REFRESH_TOKEN_SECRET,
    async (err, decoded) => {
      if (err) {
        console.log("expired refresh token");
        const result = await prisma.token.delete({
          where: {
            refreshToken: refreshToken,
          },
        });
        console.log(result);
      }
      if (err || findUser.email !== decoded.email) return res.sendStatus(403);

      // Refresh token was still valid
      const accessToken = jwt.sign(
        {
          id: decoded.id,
          username: decoded.username,
          email: decoded.email,
          role: decoded.role,
        },
        process.env.ACCESS_TOKEN_SECRET,
        { expiresIn: "10s" }
      );

      const newRefreshToken = jwt.sign(
        {
          id: decoded.id,
          username: decoded.username,
          email: decoded.email,
          role: decoded.role,
        },
        process.env.REFRESH_TOKEN_SECRET,
        { expiresIn: "1d" }
      );
      // Saving refreshToken with current user
      await prisma.token.create({
        data:{
          userId:decoded.id,
          refreshToken:newRefreshToken
        }
      })

      // Creates Secure Cookie with refresh token
      res.cookie("jwt", newRefreshToken, {
        httpOnly: true,
        secure: true,
        sameSite: "None",
        maxAge: 24 * 60 * 60 * 1000,
      });

      res.json({accessToken});
    }
  );
};

module.exports = { handleRegistration, handleLogin, handleLogout,handleRefreshToken };
