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
        serverSelectionTimeoutMS: 10000,
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
      await seedInitialMarketplaceData(database);
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

const DEFAULT_SEED_EQUIPMENT = [
  {
    name: "Sony Alpha A7 IV Mirrorless Cinema Kit",
    description:
      "Full-frame 33MP hybrid camera with 24-70mm f/2.8 GM II lens, dual batteries, and carbon tripod for commercial shoots.",
    category: "Photography Equipment",
    location: "Banani, Dhaka",
    rentalPrice: 3500,
    rentalType: "Daily",
    availableQuantity: 4,
    condition: "Like New",
    brand: "Sony",
    model: "ILCE-7M4",
    image:
      "https://images.unsplash.com/photo-1516035069371-29a1b244cc32?auto=format&fit=crop&w=900&q=80",
    rentalTerms:
      "Valid NID copy required upon pickup. Late return incurs 20% daily fee. Handle lens optics with care.",
    status: "Approved",
    ownerName: "Dhaka Lens Hub",
    ownerEmail: "owner@bharadei.com",
    ownerPhone: "+8801711000101",
    rentalCount: 28,
  },
  {
    name: "Bosch GBH 2-26 Heavy Rotary Hammer Drill",
    description:
      "800W SDS-plus rotary hammer drill with chisel set and hard carrying case for concrete & renovation tasks.",
    category: "Construction Equipment",
    location: "Mirpur 10, Dhaka",
    rentalPrice: 950,
    rentalType: "Daily",
    availableQuantity: 7,
    condition: "Excellent",
    brand: "Bosch",
    model: "GBH 2-26 DRE",
    image:
      "https://images.unsplash.com/photo-1504148455328-c376907d081c?auto=format&fit=crop&w=900&q=80",
    rentalTerms:
      "Inspect chuck and bits before use. Return clean without concrete residue.",
    status: "Approved",
    ownerName: "BuildPro Rentals BD",
    ownerEmail: "owner@bharadei.com",
    ownerPhone: "+8801711000102",
    rentalCount: 41,
  },
  {
    name: "Toyota HiAce 14-Seater Commercial Van",
    description:
      "Air-conditioned high-roof commuter van suitable for corporate travel, production crews, and inter-district logistics.",
    category: "Vehicles & Transportation",
    location: "Uttara Sector 7, Dhaka",
    rentalPrice: 28000,
    rentalType: "Weekly",
    availableQuantity: 2,
    condition: "Good",
    brand: "Toyota",
    model: "HiAce GL 2022",
    image:
      "https://images.unsplash.com/photo-1549317661-bd82c8e0f8e9?auto=format&fit=crop&w=900&q=80",
    rentalTerms:
      "Fuel excluded. Valid driving license required for self-drive or driver package available.",
    status: "Approved",
    ownerName: "MetroFleet Logistics",
    ownerEmail: "owner@bharadei.com",
    ownerPhone: "+8801711000103",
    rentalCount: 19,
  },
  {
    name: "Kubota L4508 Agricultural Power Tractor",
    description:
      "45HP 4WD agricultural tractor with rotary tiller attachment for field preparation and seasonal harvesting.",
    category: "Agriculture Equipment",
    location: "Bogura Sadar, Bogura",
    rentalPrice: 6500,
    rentalType: "Daily",
    availableQuantity: 3,
    condition: "Good",
    brand: "Kubota",
    model: "L4508 4WD",
    image:
      "https://images.unsplash.com/photo-1530267981375-f0de937f5f13?auto=format&fit=crop&w=900&q=80",
    rentalTerms:
      "Diesel supplied by renter. Operator briefing provided at handover.",
    status: "Approved",
    ownerName: "AgroMach Bangladesh",
    ownerEmail: "owner@bharadei.com",
    ownerPhone: "+8801711000104",
    rentalCount: 14,
  },
  {
    name: "JBL EON715 Event PA Sound & Mixer Rig",
    description:
      "Dual 15-inch powered PA speakers, 12-channel digital mixer, tripod stands, and 2 wireless UHF microphones.",
    category: "Event Equipment",
    location: "Dhanmondi 27, Dhaka",
    rentalPrice: 4800,
    rentalType: "Daily",
    availableQuantity: 5,
    condition: "Like New",
    brand: "JBL Professional",
    model: "EON715 Bundle",
    image:
      "https://images.unsplash.com/photo-1470225620780-dba8ba36b745?auto=format&fit=crop&w=900&q=80",
    rentalTerms:
      "Indoor or covered stage use only. Protect from rain and voltage spikes.",
    status: "Approved",
    ownerName: "Dhaka StageCraft",
    ownerEmail: "owner@bharadei.com",
    ownerPhone: "+8801711000105",
    rentalCount: 33,
  },
  {
    name: "DJI Mavic 3 Pro Cine Enterprise Drone",
    description:
      "Triple-camera Hasselblad aerial cinema drone with RC Pro controller, ND filters, and 3 intelligent flight batteries.",
    category: "Electronics",
    location: "Gulshan 2, Dhaka",
    rentalPrice: 5500,
    rentalType: "Daily",
    availableQuantity: 3,
    condition: "Like New",
    brand: "DJI",
    model: "Mavic 3 Pro Cine",
    image:
      "https://images.unsplash.com/photo-1507582020474-9a35b7d455d9?auto=format&fit=crop&w=900&q=80",
    rentalTerms:
      "CAAB flight compliance is renter responsibility. MicroSD card included.",
    status: "Approved",
    ownerName: "SkyView Media BD",
    ownerEmail: "owner@bharadei.com",
    ownerPhone: "+8801711000106",
    rentalCount: 25,
  },
  {
    name: "Honda EU22i Silent Inverter Generator",
    description:
      "2200W ultra-quiet portable inverter generator ideal for outdoor film sets, pop-up booths, and backup power.",
    category: "Construction Equipment",
    location: "Chattogram GEC",
    rentalPrice: 14500,
    rentalType: "Weekly",
    availableQuantity: 4,
    condition: "Excellent",
    brand: "Honda",
    model: "EU22i",
    image:
      "https://images.unsplash.com/photo-1581092160607-ee22621dd758?auto=format&fit=crop&w=900&q=80",
    rentalTerms:
      "Use unleaded petrol only. Check oil indicator before every start.",
    status: "Approved",
    ownerName: "PortCity Power",
    ownerEmail: "owner@bharadei.com",
    ownerPhone: "+8801711000107",
    rentalCount: 16,
  },
  {
    name: "Epson EB-L530U 5200-Lumen Laser Projector",
    description:
      "Full HD WUXGA laser projector with 120-inch tripod screen and HDMI wireless presenter for conferences.",
    category: "Electronics",
    location: "Sylhet Zindabazar",
    rentalPrice: 24000,
    rentalType: "Monthly",
    availableQuantity: 6,
    condition: "Excellent",
    brand: "Epson",
    model: "EB-L530U",
    image:
      "https://images.unsplash.com/photo-1517457373958-b7bdd4587205?auto=format&fit=crop&w=900&q=80",
    rentalTerms:
      "Do not unplug during cool-down fan cycle. Carry in padded flight case.",
    status: "Approved",
    ownerName: "Sylhet AV Solutions",
    ownerEmail: "owner@bharadei.com",
    ownerPhone: "+8801711000108",
    rentalCount: 12,
  },
];

const DEFAULT_SEED_REVIEWS = [
  {
    customerName: "Tanvir Ahmed",
    role: "Commercial Filmmaker, Dhaka",
    rating: 5,
    equipmentName: "Sony Alpha A7 IV Mirrorless Cinema Kit",
    comment:
      "Booked a Sony A7 IV kit for a 3-day agency shoot in Banani. Gear was spotless, batteries fully charged, and Stripe checkout took under a minute.",
    createdAt: new Date("2026-10-15T10:00:00Z"),
  },
  {
    customerName: "Nusrat Jahan",
    role: "Event Coordinator, Dhanmondi",
    rating: 5,
    equipmentName: "JBL EON715 Event PA Sound & Mixer Rig",
    comment:
      "Instead of buying pricey PA speakers for one seminar, we rented the JBL bundle at a fraction of the cost. Crystal clear audio and punctual handover.",
    createdAt: new Date("2026-10-22T14:30:00Z"),
  },
  {
    customerName: "Rafiqul Islam",
    role: "Civil Contractor, Mirpur",
    rating: 4,
    equipmentName: "Bosch GBH 2-26 Heavy Rotary Hammer Drill",
    comment:
      "Transparent daily pricing and verified owners saved our renovation team from buying extra heavy tools. Booking tracking in the dashboard is super clean.",
    createdAt: new Date("2026-11-02T09:15:00Z"),
  },
  {
    customerName: "Farhana Chowdhury",
    role: "Agri-Tech Lead, Bogura",
    rating: 5,
    equipmentName: "Kubota L4508 Agricultural Power Tractor",
    comment:
      "Finding reliable farm machinery with clear rental terms used to take days of phone calls. BharaDei.com made availability and booking effortless.",
    createdAt: new Date("2026-11-10T11:45:00Z"),
  },
];

const CORE_CATEGORIES = [
  "Construction Equipment",
  "Photography Equipment",
  "Vehicles & Transportation",
  "Agriculture Equipment",
  "Electronics",
  "Event Equipment",
];

async function seedInitialMarketplaceData(db) {
  try {
    const equipmentCol = db.collection(COLLECTIONS.EQUIPMENT);
    const reviewsCol = db.collection(COLLECTIONS.REVIEWS);

    const equipCount = await equipmentCol.countDocuments();
    if (equipCount === 0) {
      const now = Date.now();
      const docs = DEFAULT_SEED_EQUIPMENT.map((item, idx) => ({
        ...item,
        createdAt: new Date(now - idx * 86400000),
        updatedAt: new Date(now - idx * 86400000),
      }));
      await equipmentCol.insertMany(docs);
      console.log(`[Seed] Inserted ${docs.length} initial equipment listings.`);
    }

    const reviewCount = await reviewsCol.countDocuments();
    if (reviewCount === 0) {
      await reviewsCol.insertMany(DEFAULT_SEED_REVIEWS);
      console.log(`[Seed] Inserted ${DEFAULT_SEED_REVIEWS.length} initial reviews.`);
    }
  } catch (err) {
    console.warn("[Seed] Skipped seeding:", err.message);
  }
}

function serializeEquipment(doc) {
  return {
    id: String(doc._id || doc.id || ""),
    name: doc.name,
    description: doc.description,
    category: doc.category,
    location: doc.location,
    rentalPrice: Number(doc.rentalPrice || 0),
    rentalType: doc.rentalType || "Daily",
    availableQuantity: Number(doc.availableQuantity ?? 0),
    condition: doc.condition || "Good",
    brand: doc.brand || "",
    model: doc.model || "",
    image: doc.image || "",
    rentalTerms: doc.rentalTerms || "",
    status: doc.status || "Pending",
    ownerName: doc.ownerName || "Verified Owner",
    ownerEmail: doc.ownerEmail || "",
    ownerPhone: doc.ownerPhone || "",
    rentalCount: Number(doc.rentalCount || 0),
    createdAt: doc.createdAt || new Date(),
  };
}

// ---------------------------------------------------------------------------
// 5. Public Home & Discovery Routes
// ---------------------------------------------------------------------------
app.get(
  "/api/equipment/featured",
  asyncHandler(async (_req, res) => {
    try {
      const equipmentCol = await getCollection(COLLECTIONS.EQUIPMENT);
      const docs = await equipmentCol
        .find({ status: "Approved" })
        .sort({ rentalCount: -1, createdAt: -1 })
        .limit(6)
        .toArray();

      return res.status(200).json({
        success: true,
        items: docs.map(serializeEquipment),
      });
    } catch {
      return res.status(200).json({
        success: true,
        fallback: true,
        items: DEFAULT_SEED_EQUIPMENT.slice(0, 6).map((item, idx) =>
          serializeEquipment({ ...item, id: `seed-${idx + 1}` })
        ),
      });
    }
  })
);

app.get(
  "/api/equipment/categories",
  asyncHandler(async (_req, res) => {
    try {
      const equipmentCol = await getCollection(COLLECTIONS.EQUIPMENT);
      const counts = await equipmentCol
        .aggregate([
          { $match: { status: "Approved" } },
          { $group: { _id: "$category", count: { $sum: 1 } } },
        ])
        .toArray();

      const countMap = new Map(counts.map((c) => [c._id, c.count]));
      const categories = CORE_CATEGORIES.map((name) => ({
        name,
        count: countMap.get(name) || 0,
      }));

      return res.status(200).json({ success: true, categories });
    } catch {
      const categories = CORE_CATEGORIES.map((name) => ({
        name,
        count: DEFAULT_SEED_EQUIPMENT.filter((e) => e.category === name).length,
      }));
      return res.status(200).json({ success: true, fallback: true, categories });
    }
  })
);

app.get(
  "/api/equipment/highlights",
  asyncHandler(async (_req, res) => {
    try {
      const equipmentCol = await getCollection(COLLECTIONS.EQUIPMENT);
      const [popularDocs, recentDocs] = await Promise.all([
        equipmentCol
          .find({ status: "Approved" })
          .sort({ rentalCount: -1 })
          .limit(4)
          .toArray(),
        equipmentCol
          .find({ status: "Approved" })
          .sort({ createdAt: -1 })
          .limit(4)
          .toArray(),
      ]);

      return res.status(200).json({
        success: true,
        popular: popularDocs.map(serializeEquipment),
        recent: recentDocs.map(serializeEquipment),
      });
    } catch {
      const mapped = DEFAULT_SEED_EQUIPMENT.map((item, idx) =>
        serializeEquipment({ ...item, id: `seed-${idx + 1}` })
      );
      return res.status(200).json({
        success: true,
        fallback: true,
        popular: [...mapped]
          .sort((a, b) => b.rentalCount - a.rentalCount)
          .slice(0, 4),
        recent: mapped.slice(0, 4),
      });
    }
  })
);

app.get(
  "/api/reviews",
  asyncHandler(async (_req, res) => {
    try {
      const reviewsCol = await getCollection(COLLECTIONS.REVIEWS);
      const docs = await reviewsCol
        .find({})
        .sort({ createdAt: -1 })
        .limit(6)
        .toArray();

      return res.status(200).json({
        success: true,
        reviews: docs.map((r) => ({
          id: String(r._id),
          customerName: r.customerName,
          role: r.role || "Verified Renter",
          rating: Number(r.rating || 5),
          equipmentName: r.equipmentName || "",
          comment: r.comment,
        })),
      });
    } catch {
      return res.status(200).json({
        success: true,
        fallback: true,
        reviews: DEFAULT_SEED_REVIEWS.map((r, idx) => ({
          id: `review-${idx + 1}`,
          ...r,
        })),
      });
    }
  })
);

// ---------------------------------------------------------------------------
// 6. 404 & Global Error Handlers
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
  app.listen(port, () => {
    console.log(`BharaDei.com server running at http://localhost:${port}`);
  });

  connectDB().catch((err) => {
    console.error("[DB] Initial MongoDB connection failed:", err.message);
  });
}

startServer();

export default app;
