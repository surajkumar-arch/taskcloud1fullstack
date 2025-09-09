const createJWT = (res, userId) => {
  const token = jwt.sign({ userId }, process.env.JWT_SECRET, {
    expiresIn: "1d",
  });

  const isProduction = process.env.NODE_ENV === 'production';

  res.cookie("token", token, {
    httpOnly: true,
    secure: isProduction, // true only in production (HTTPS)
    sameSite: isProduction ? "None" : "Lax", // "None" for cross-site in prod, "Lax" for dev
    maxAge: 1 * 24 * 60 * 60 * 1000, // 1 day
  });

  return token;
};
