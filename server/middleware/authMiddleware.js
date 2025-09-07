import asyncHandler from "express-async-handler";
import jwt from "jsonwebtoken";
import User from "../models/userModel.js";

const protectRoute = asyncHandler(async (req, res, next) => {
  let token;

  console.log("Authorization Header:", req.headers?.authorization);
  console.log("Cookies:", req.cookies);

  // 1. Token from cookie (check if req.cookies exists and has token)
  if (req.cookies && typeof req.cookies.token === "string") {
    token = req.cookies.token;
  } 
  // 2. Token from Authorization header (safe check)
  else if (
    req.headers &&
    typeof req.headers.authorization === "string" &&
    req.headers.authorization.startsWith("Bearer ")
  ) {
    // Now safe to split
    token = req.headers.authorization.split(" ")[1];
  }

  // Token not found
  if (!token) {
    return res.status(401).json({
      status: false,
      message: "Not authorized. Try login again.",
    });
  }

  try {
    // Verify token
    const decodedToken = jwt.verify(token, process.env.JWT_SECRET);

    // Find user by ID from token payload
    const resp = await User.findById(decodedToken.userId).select("isAdmin email");

    if (!resp) {
      return res.status(401).json({
        status: false,
        message: "User  not found. Not authorized.",
      });
    }

    // Attach user info to request object
    req.user = {
      email: resp.email,
      isAdmin: resp.isAdmin,
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
