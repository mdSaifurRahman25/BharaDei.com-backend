import jwt from "jsonwebtoken";
import { COLLECTIONS, getCollection } from "../config/db.js";

export function getJwtSecret() {
  if (process.env.JWT_SECRET) {
    return process.env.JWT_SECRET;
  }
  if (process.env.NODE_ENV === "production") {
    throw new Error("JWT_SECRET environment variable is required in production.");
  }
  return "bharadei_dev_fallback_jwt_secret_change_me";
}

export function signAccessToken(user) {
  return jwt.sign(
    {
      id: String(user._id || user.id || ""),
      email: user.email,
      name: user.name,
      role: user.role || "Customer",
    },
    getJwtSecret(),
    { expiresIn: "7d" }
  );
}

/**
 * Verifies Bearer JWT token and loads the latest user record from MongoDB.
 */
export async function verifyToken(req, res, next) {
  try {
    const authHeader = req.headers.authorization || "";
    if (!authHeader.startsWith("Bearer ")) {
      return res.status(401).json({
        success: false,
        message: "Unauthorized: Missing Bearer access token.",
      });
    }

    const token = authHeader.slice(7).trim();
    if (!token) {
      return res.status(401).json({
        success: false,
        message: "Unauthorized: Empty access token.",
      });
    }

    const decoded = jwt.verify(token, getJwtSecret());
    const users = await getCollection(COLLECTIONS.USERS);
    const dbUser = await users.findOne(
      { email: decoded.email.toLowerCase() },
      { projection: { password: 0 } }
    );

    if (!dbUser) {
      return res.status(401).json({
        success: false,
        message: "Unauthorized: User account no longer exists.",
      });
    }

    req.user = {
      id: String(dbUser._id),
      name: dbUser.name,
      email: dbUser.email,
      image: dbUser.image || "",
      role: dbUser.role || "Customer",
      phone: dbUser.phone || "",
      address: dbUser.address || "",
      createdAt: dbUser.createdAt,
    };

    return next();
  } catch (err) {
    return res.status(401).json({
      success: false,
      message:
        err.name === "TokenExpiredError"
          ? "Session expired. Please login again."
          : "Unauthorized: Invalid access token.",
    });
  }
}

/**
 * Restricts route access strictly to Customer (Renter) accounts.
 */
export function verifyRenter(req, res, next) {
  if (req.user?.role !== "Customer") {
    return res.status(403).json({
      success: false,
      message: "Forbidden: Customer (Renter) access required.",
    });
  }
  return next();
}

/**
 * Restricts route access strictly to Owner accounts.
 */
export function verifyOwner(req, res, next) {
  if (req.user?.role !== "Owner") {
    return res.status(403).json({
      success: false,
      message: "Forbidden: Equipment Owner access required.",
    });
  }
  return next();
}

/**
 * Restricts route access strictly to Admin accounts.
 */
export function verifyAdmin(req, res, next) {
  if (req.user?.role !== "Admin") {
    return res.status(403).json({
      success: false,
      message: "Forbidden: Admin access required.",
    });
  }
  return next();
}

/**
 * Allows access to any of the listed roles.
 */
export function verifyRoles(...roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({
        success: false,
        message: `Forbidden: Requires one of [${roles.join(", ")}].`,
      });
    }
    return next();
  };
}
