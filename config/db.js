import { MongoClient, ServerApiVersion } from "mongodb";

export const COLLECTIONS = {
  USERS: "users",
  EQUIPMENT: "equipment",
  BOOKINGS: "bookings",
  PAYMENTS: "payments",
  FAVORITES: "favorites",
  REVIEWS: "reviews",
};

let client = null;
let database = null;
let connectionPromise = null;

/**
 * Establishes and caches a singleton MongoDB connection and initializes indexes.
 */
export async function connectDB() {
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
      client = new MongoClient(uri, {
        serverApi: {
          version: ServerApiVersion.v1,
          strict: true,
          deprecationErrors: true,
        },
      });
      await client.connect();
      const dbName = process.env.DB_NAME || "bharadei";
      database = client.db(dbName);
      await ensureIndexes(database);
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

/**
 * Creates core indexes idempotently to keep search, auth, and analytics fast.
 */
async function ensureIndexes(db) {
  await Promise.all([
    db.collection(COLLECTIONS.USERS).createIndex({ email: 1 }, { unique: true }),
    db.collection(COLLECTIONS.EQUIPMENT).createIndex({ status: 1, category: 1, createdAt: -1 }),
    db.collection(COLLECTIONS.EQUIPMENT).createIndex({ ownerEmail: 1 }),
    db.collection(COLLECTIONS.BOOKINGS).createIndex({ customerEmail: 1, createdAt: -1 }),
    db.collection(COLLECTIONS.BOOKINGS).createIndex({ ownerEmail: 1, createdAt: -1 }),
    db.collection(COLLECTIONS.BOOKINGS).createIndex({ equipmentId: 1 }),
    db
      .collection(COLLECTIONS.FAVORITES)
      .createIndex({ userEmail: 1, equipmentId: 1 }, { unique: true }),
    db.collection(COLLECTIONS.PAYMENTS).createIndex({ sessionId: 1 }, { unique: true, sparse: true }),
  ]);
}

/**
 * Returns the active MongoDB database instance, connecting lazily if needed.
 */
export async function getDB() {
  if (database) return database;
  return connectDB();
}

/**
 * Returns a named MongoDB collection or throws a 503 error if the DB is unavailable.
 */
export async function getCollection(name) {
  const db = await getDB();
  if (!db) {
    const err = new Error("Database connection is not configured.");
    err.statusCode = 503;
    throw err;
  }
  return db.collection(name);
}

/**
 * Reports whether MongoDB is currently connected.
 */
export function isDBConnected() {
  return Boolean(database);
}
