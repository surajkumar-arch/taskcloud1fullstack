
import jwt from "jsonwebtoken";

const createJWT = (res, userId) => {
  const token = jwt.sign({ userId }, process.env.JWT_SECRET, {
    expiresIn: "1d",
  });

  // 🛠 Cookie setup (works on localhost too)
  res.cookie("token", token, {
    httpOnly: true,
    secure: true,     // force false in dev, change to true in prod (with HTTPS)
    sameSite: "none",   // use "none" only if frontend is on different domain
    maxAge: 1 * 24 * 60 * 60 * 1000, // 1 day
  });

  return token; // 👈 return so controller can send it in JSON too
};

export default createJWT;
