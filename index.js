import express from "express";
import cors from "cors";
import "dotenv/config";
import { MongoClient, ServerApiVersion } from "mongodb";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";

const app = express();
const port = process.env.PORT || 5000;

// ---------------------------------------------------------------------------
// 1. CORS & Core Middleware
// ---------------------------------------------------------------------------
const allowedOrigins = new Set(
  [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    process.env.CLIENT_URL,
    ...(process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(",") : []),
  ]
    .map((origin) => origin?.trim())
    .filter(Boolean)
);

const corsOptions = {
  origin(origin, callback) {
    if (!origin || allowedOrigins.has(origin)) {
      return callback(null, true);
    }
    const err = new Error(`CORS blocked for origin: ${origin}`);
    err.statusCode = 403;
    return callback(err);
  },
  credentials: true,
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
};

app.use(cors(corsOptions));
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));

// ---------------------------------------------------------------------------
// 2. MongoDB Connection & Collections
// ---------------------------------------------------------------------------
const COLLECTIONS = {
  USERS: "users",
  EQUIPMENT: "equipment",
  BOOKINGS: "bookings",
  PAYMENTS: "payments",
  FAVORITES: "favorites",
  REVIEWS: "reviews",
};

let mongoClient = null;
let database = null;
let connectionPromise = null;

async function connectDB() {
  if (database) return database;

  const uri = process.env.MONGODB_URI;
  if (!uri) {
    console.warn(
      "[DB] MONGODB_URI is not set in backend/.env — running in limited mode until configured."
    );
    return null;
  }

  if (!connectionPromise) {
    connectionPromise = (async () => {
      mongoClient = new MongoClient(uri, {
        serverApi: {
          version: ServerApiVersion.v1,
          strict: true,
          deprecationErrors: true,
        },
      });
      await mongoClient.connect();
      const dbName = process.env.DB_NAME || "bharadei";
      database = mongoClient.db(dbName);

      await Promise.all([
        database.collection(COLLECTIONS.USERS).createIndex({ email: 1 }, { unique: true }),
        database
          .collection(COLLECTIONS.EQUIPMENT)
          .createIndex({ status: 1, category: 1, createdAt: -1 }),
        database.collection(COLLECTIONS.EQUIPMENT).createIndex({ ownerEmail: 1 }),
        database
          .collection(COLLECTIONS.BOOKINGS)
          .createIndex({ customerEmail: 1, createdAt: -1 }),
        database
          .collection(COLLECTIONS.BOOKINGS)
          .createIndex({ ownerEmail: 1, createdAt: -1 }),
        database.collection(COLLECTIONS.BOOKINGS).createIndex({ equipmentId: 1 }),
        database
          .collection(COLLECTIONS.FAVORITES)
          .createIndex({ userEmail: 1, equipmentId: 1 }, { unique: true }),
        database
          .collection(COLLECTIONS.PAYMENTS)
          .createIndex({ sessionId: 1 }, { unique: true, sparse: true }),
      ]);

      console.log(`[DB] Connected to MongoDB database: ${dbName}`);
      return database;
    })().catch((err) => {
      connectionPromise = null;
      database = null;
      throw err;
    });
  }

  return connectionPromise;
}

async function getCollection(name) {
  const db = database || (await connectDB());
  if (!db) {
    const err = new Error("Database connection is not configured.");
    err.statusCode = 503;
    throw err;
  }
  return db.collection(name);
}

// ---------------------------------------------------------------------------
// 3. JWT Helpers & Role-Based Middlewares (Challenge 2)
// ---------------------------------------------------------------------------
function getJwtSecret() {
  if (process.env.JWT_SECRET) {
    return process.env.JWT_SECRET;
  }
  if (process.env.NODE_ENV === "production") {
    throw new Error("JWT_SECRET environment variable is required in production.");
  }
  return "bharadei_dev_fallback_jwt_secret_change_me";
}

function signAccessToken(user) {
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

async function verifyToken(req, res, next) {
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

    req.user = sanitizeUser(dbUser);
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

function verifyRenter(req, res, next) {
  if (req.user?.role !== "Customer") {
    return res.status(403).json({
      success: false,
      message: "Forbidden: Customer (Renter) access required.",
    });
  }
  return next();
}

function verifyOwner(req, res, next) {
  if (req.user?.role !== "Owner") {
    return res.status(403).json({
      success: false,
      message: "Forbidden: Equipment Owner access required.",
    });
  }
  return next();
}

function verifyAdmin(req, res, next) {
  if (req.user?.role !== "Admin") {
    return res.status(403).json({
      success: false,
      message: "Forbidden: Admin access required.",
    });
  }
  return next();
}

function asyncHandler(fn) {
  return (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}

// ---------------------------------------------------------------------------
// 4. Health & Auth Routes
// ---------------------------------------------------------------------------
app.get("/", (_req, res) => {
  res.status(200).json({
    success: true,
    name: "BharaDei.com API",
    message: "BharaDei.com Equipment Rental API is running.",
    dbConnected: Boolean(database),
  });
});

app.get("/api/health", async (_req, res) => {
  let dbConnected = Boolean(database);
  if (!dbConnected && process.env.MONGODB_URI) {
    try {
      const db = await connectDB();
      dbConnected = Boolean(db);
    } catch {
      dbConnected = false;
    }
  }

  res.status(200).json({
    success: true,
    service: "BharaDei.com API",
    tagline: "Everything You Need, Ready to Rent.",
    dbConnected,
    timestamp: new Date().toISOString(),
  });
});

app.post(
  "/api/auth/register",
  asyncHandler(async (req, res) => {
    const { name, email, image = "", password } = req.body || {};

    if (!name?.trim() || !email?.trim() || !password) {
      return res.status(400).json({
        success: false,
        message: "Name, email, and password are required.",
      });
    }

    const passwordError = validatePassword(password);
    if (passwordError) {
      return res.status(400).json({ success: false, message: passwordError });
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
  })
);

app.post(
  "/api/auth/login",
  asyncHandler(async (req, res) => {
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
  })
);

app.post(
  "/api/auth/oauth-sync",
  asyncHandler(async (req, res) => {
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
  })
);

app.get(
  "/api/auth/me",
  verifyToken,
  asyncHandler(async (req, res) => {
    return res.status(200).json({
      success: true,
      user: req.user,
    });
  })
);

app.put(
  "/api/auth/profile",
  verifyToken,
  asyncHandler(async (req, res) => {
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
  })
);

// ---------------------------------------------------------------------------
// 5. 404 & Global Error Handlers
// ---------------------------------------------------------------------------
app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: `Route not found: ${req.method} ${req.originalUrl}`,
  });
});

app.use((err, req, res, _next) => {
  const statusCode = err.statusCode || err.status || 500;
  const message =
    statusCode >= 500 && process.env.NODE_ENV === "production"
      ? "Internal server error"
      : err.message || "Something went wrong";

  if (statusCode >= 500) {
    console.error(`[API Error] ${req.method} ${req.originalUrl}:`, err);
  }

  res.status(statusCode).json({
    success: false,
    message,
  });
});

async function startServer() {
  try {
    await connectDB();
  } catch (err) {
    console.error("[DB] Initial MongoDB connection failed:", err.message);
  }

  app.listen(port, () => {
    console.log(`BharaDei.com server running at http://localhost:${port}`);
  });
}

startServer();

export default app;
