import bcrypt from "bcryptjs";
import { COLLECTIONS, getCollection } from "../config/db.js";
import { signAccessToken } from "../middleware/auth.js";

function validatePassword(password) {
  if (typeof password !== "string" || password.length < 6) {
    return "Password must be at least 6 characters long.";
  }
  if (!/[A-Z]/.test(password)) {
    return "Password must include at least one uppercase letter.";
  }
  if (!/[a-z]/.test(password)) {
    return "Password must include at least one lowercase letter.";
  }
  return null;
}

function sanitizeUser(doc) {
  return {
    id: String(doc._id),
    name: doc.name,
    email: doc.email,
    image: doc.image || "",
    role: doc.role || "Customer",
    phone: doc.phone || "",
    address: doc.address || "",
    createdAt: doc.createdAt,
  };
}

export async function registerUser(req, res) {
  const { name, email, image = "", password } = req.body || {};

  if (!name?.trim() || !email?.trim() || !password) {
    return res.status(400).json({
      success: false,
      message: "Name, email, and password are required.",
    });
  }

  const passwordError = validatePassword(password);
  if (passwordError) {
    return res.status(400).json({
      success: false,
      message: passwordError,
    });
  }

  const normalizedEmail = email.trim().toLowerCase();
  const users = await getCollection(COLLECTIONS.USERS);

  const existing = await users.findOne({ email: normalizedEmail });
  if (existing) {
    return res.status(409).json({
      success: false,
      message: "An account with this email already exists.",
    });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const now = new Date();

  const newUserDoc = {
    name: name.trim(),
    email: normalizedEmail,
    image: typeof image === "string" ? image.trim() : "",
    password: hashedPassword,
    role: "Customer",
    phone: "",
    address: "",
    provider: "credentials",
    createdAt: now,
    updatedAt: now,
  };

  const result = await users.insertOne(newUserDoc);
  const createdUser = sanitizeUser({ ...newUserDoc, _id: result.insertedId });
  const token = signAccessToken(createdUser);

  return res.status(201).json({
    success: true,
    message: "Account registered successfully.",
    user: createdUser,
    token,
  });
}

export async function loginUser(req, res) {
  const { email, password } = req.body || {};

  if (!email?.trim() || !password) {
    return res.status(400).json({
      success: false,
      message: "Email and password are required.",
    });
  }

  const normalizedEmail = email.trim().toLowerCase();
  const users = await getCollection(COLLECTIONS.USERS);
  const userDoc = await users.findOne({ email: normalizedEmail });

  if (!userDoc || !userDoc.password) {
    return res.status(401).json({
      success: false,
      message: "Invalid email or password.",
    });
  }

  const isMatch = await bcrypt.compare(password, userDoc.password);
  if (!isMatch) {
    return res.status(401).json({
      success: false,
      message: "Invalid email or password.",
    });
  }

  const user = sanitizeUser(userDoc);
  const token = signAccessToken(user);

  return res.status(200).json({
    success: true,
    message: "Login successful.",
    user,
    token,
  });
}

/**
 * Upserts a social/BetterAuth user (default role Customer on first sign-in)
 * and issues a role-aware Express JWT token.
 */
export async function syncOAuthUser(req, res) {
  const { name, email, image = "", provider = "google" } = req.body || {};

  if (!email?.trim()) {
    return res.status(400).json({
      success: false,
      message: "Email is required to sync account.",
    });
  }

  const normalizedEmail = email.trim().toLowerCase();
  const users = await getCollection(COLLECTIONS.USERS);
  const now = new Date();

  const updatedDoc = await users.findOneAndUpdate(
    { email: normalizedEmail },
    {
      $setOnInsert: {
        email: normalizedEmail,
        role: "Customer",
        phone: "",
        address: "",
        createdAt: now,
      },
      $set: {
        name: (name || normalizedEmail.split("@")[0]).trim(),
        ...(image ? { image: image.trim() } : {}),
        provider,
        updatedAt: now,
      },
    },
    { upsert: true, returnDocument: "after", projection: { password: 0 } }
  );

  const user = sanitizeUser(updatedDoc);
  const token = signAccessToken(user);

  return res.status(200).json({
    success: true,
    message: "Session synchronized.",
    user,
    token,
  });
}

export async function getCurrentProfile(req, res) {
  return res.status(200).json({
    success: true,
    user: req.user,
  });
}

export async function updateCurrentProfile(req, res) {
  const { name, image, phone, address } = req.body || {};
  const users = await getCollection(COLLECTIONS.USERS);

  const updates = { updatedAt: new Date() };
  if (typeof name === "string" && name.trim()) updates.name = name.trim();
  if (typeof image === "string") updates.image = image.trim();
  if (typeof phone === "string") updates.phone = phone.trim();
  if (typeof address === "string") updates.address = address.trim();

  const updated = await users.findOneAndUpdate(
    { email: req.user.email },
    { $set: updates },
    { returnDocument: "after", projection: { password: 0 } }
  );

  if (!updated) {
    return res.status(404).json({
      success: false,
      message: "User profile not found.",
    });
  }

  return res.status(200).json({
    success: true,
    message: "Profile updated successfully.",
    user: sanitizeUser(updated),
  });
}
