import postgres from "postgres";
import dotenv from "dotenv";
import path from "path";

dotenv.config({ path: path.join(__dirname, "../.env") });

const DATABASE_URL = process.env.DATABASE_URL;

if (!DATABASE_URL) {
  console.error("DATABASE_URL is not defined in .env");
  process.exit(1);
}

const sql = postgres(DATABASE_URL, { ssl: "require" });

async function initDb() {
  console.log("Initializing database...");
  try {
    await sql`
      CREATE TABLE IF NOT EXISTS hub_users (
        uid TEXT PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        display_name TEXT,
        role TEXT NOT NULL,
        phone_number TEXT,
        business_name TEXT,
        service_governorate TEXT,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      )
    `;

    await sql`
      CREATE TABLE IF NOT EXISTS hub_deliveries (
        id TEXT PRIMARY KEY,
        business_id TEXT REFERENCES hub_users(uid),
        business_name TEXT,
        delivery_guy_id TEXT REFERENCES hub_users(uid),
        delivery_guy_name TEXT,
        delivery_guy_phone TEXT,
        status TEXT NOT NULL,
        payment_status TEXT NOT NULL,
        receipt_url TEXT,
        governorate TEXT NOT NULL,
        pickup_address TEXT,
        pickup_lat DOUBLE PRECISION,
        pickup_lng DOUBLE PRECISION,
        dropoff_address TEXT,
        dropoff_lat DOUBLE PRECISION,
        dropoff_lng DOUBLE PRECISION,
        customer_name TEXT,
        customer_phone TEXT,
        item_description TEXT,
        price DOUBLE PRECISION,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      )
    `;
    await sql`
      CREATE TABLE IF NOT EXISTS hub_otps (
        id SERIAL PRIMARY KEY,
        email TEXT NOT NULL,
        otp TEXT NOT NULL,
        expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      )
    `;
    console.log("Database initialized successfully");
  } catch (error) {
    console.error("Database initialization failed:", error);
  } finally {
    await sql.end();
  }
}

initDb();
