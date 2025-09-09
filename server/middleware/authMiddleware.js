import asyncHandler from "express-async-handler";
import jwt from "jsonwebtoken";
import User from "../models/userModel.js";

const protectRoute = asyncHandler(async (req, res, next) => {
  let token;

  console.log("Authorization header from client:", req.headers.authorization);  // Debug log

  // Only check the Authorization header
  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith("Bearer ")
  ) {
    token = req.headers.authorization.split(" ")[1];
  }

  if (!token) {
    return res.status(401).json({
      status: false,
      message: "Not authorized. Try login again.",
    });
  }

  try {
    const decodedToken = jwt.verify(token, process.env.JWT_SECRET);

    const resp = await User.findById(decodedToken.userId).select("isAdmin email");

    if (!resp) {
      return res.status(401).json({
        status: false,
        message: "User not found.",
      });
    }

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
    res.status(403).json({
      status: false,
      message: "Admin access required.",
    });
  }
};

export { isAdminRoute, protectRoute };
