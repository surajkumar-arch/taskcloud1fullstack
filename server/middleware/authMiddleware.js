import asyncHandler from "express-async-handler";
import jwt from "jsonwebtoken";
import User from "../models/userModel.js";

const protectRoute = asyncHandler(async (req, res, next) => {
  let token;

  console.log("Authorization Header:", req.headers?.authorization);
  console.log("Cookies:", req.cookies);

  // 1. Try to get token from cookies
  if (req.cookies && typeof req.cookies.token === "string") {
    token = req.cookies.token;
    console.log("Token found in cookies");
  }
  // 2. Else try to get token from Authorization header
  else if (
    req.headers &&
    typeof req.headers.authorization === "string" &&
    req.headers.authorization.startsWith("Bearer ")
  ) {
    token = req.headers.authorization.split(" ")[1];
    console.log("Token found in Authorization header");
  }

  // If no token found, respond with 401
  if (!token) {
    return res.status(401).json({
      status: false,
      message: "Not authorized. Try login again.",
    });
  }

  try {
    // Verify JWT token
    const decodedToken = jwt.verify(token, process.env.JWT_SECRET);

    // Find user by ID from token payload
    const user = await User.findById(decodedToken.userId).select("isAdmin email");

    if (!user) {
      return res.status(401).json({
        status: false,
        message: "User  not found. Not authorized.",
      });
    }

    // Attach user info to request object
    req.user = {
      email: user.email,
      isAdmin: user.isAdmin,
      userId: decodedToken.userId,
    };

    next();
  } catch (error) {
    console.error("JWT Verify Error:", error.message);
    return res.status(401).json({
      status: false,
      message: "Not authorized. Try login again.",
    });
  }
});

const isAdminRoute = (req, res, next) => {
  if (req.user && req.user.isAdmin) {
    next();
  } else {
    return res.status(401).json({
      status: false,
      message: "Not authorized as admin. Try login as admin.",
    });
  }
};

export { isAdminRoute, protectRoute };
