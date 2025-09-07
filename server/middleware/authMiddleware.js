import asyncHandler from "express-async-handler";
import jwt from "jsonwebtoken";
import User from "../models/userModel.js";

const protectRoute = asyncHandler(async (req, res, next) => {
  let token;

  console.log("Authorization Header:", req.headers.authorization);
  console.log("Cookies:", req.cookies);

  // 1. Token from cookie
  if (req.cookies.token) {
    token = req.cookies.token;
  }
  // 2. Token from Authorization header
  else if (
    typeof req.headers.authorization === "string" &&
    req.headers.authorization.startsWith("Bearer ")
  ) {
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
    const decodedToken = jwt.verify(token, process.env.JWT_SECRET);

    const resp = await User.findById(decodedToken.userId).select("isAdmin email");

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

export { protectRoute };
