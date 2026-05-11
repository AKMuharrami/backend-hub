import { put } from "@vercel/blob";
import express from "express";
import postgres from "postgres";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import cors from "cors";
import dotenv from "dotenv";
import multer from "multer";

dotenv.config();

const DATABASE_URL = process.env.DATABASE_URL!;
const JWT_SECRET = process.env.JWT_SECRET || "supersecretkey";

const sql = postgres(DATABASE_URL, { ssl: "require" });

const app = express();
const upload = multer({ storage: multer.memoryStorage() });

app.use(cors());
app.use(express.json());

// Logging middleware
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.url}`);
  next();
});

// Middleware to authenticate JWT
const authenticateToken = (req: any, res: any, next: any) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, JWT_SECRET, (err: any, user: any) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

app.get("/api/health", (req, res) => {
  res.json({ status: "ok", time: new Date().toISOString() });
});

app.post("/api/upload", authenticateToken, upload.single('file'), async (req: any, res) => {
  if (!req.file) {
    return res.status(400).json({ error: "No file uploaded" });
  }

  try {
    const blob = await put(`receipts/${Date.now()}-${req.file.originalname}`, req.file.buffer, {
      access: 'public',
      token: process.env.BLOB_READ_WRITE_TOKEN
    });

    res.json(blob);
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// Auth Routes
app.post("/api/auth/register", async (req, res) => {
  const { email, password, displayName, role, phoneNumber, businessName, serviceGovernorate } = req.body;
  console.log(`Registration attempt for: ${email}`);
  try {
    const hashedPassword = bcrypt.hashSync(password, 10);
    const uid = Math.random().toString(36).substring(2, 15);
    
    const [user] = await sql`
      INSERT INTO hub_users (uid, email, password, display_name, role, phone_number, business_name, service_governorate)
      VALUES (${uid}, ${email}, ${hashedPassword}, ${displayName}, ${role}, ${phoneNumber}, ${businessName}, ${serviceGovernorate})
      RETURNING uid, email, display_name, role, phone_number, business_name, service_governorate
    `;

    const token = jwt.sign({ uid: user.uid, email: user.email }, JWT_SECRET);
    res.json({ token, user });
  } catch (error: any) {
    res.status(400).json({ error: error.message });
  }
});

app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;
  console.log(`Login attempt for: ${email}`);
  try {
    const [user] = await sql`
      SELECT * FROM hub_users WHERE email = ${email}
    `;
    if (!user) return res.status(400).json({ error: "User not found" });

    const validPassword = bcrypt.compareSync(password, user.password);
    if (!validPassword) return res.status(400).json({ error: "Invalid password" });

    const token = jwt.sign({ uid: user.uid, email: user.email }, JWT_SECRET);
    
    const { password: _, ...userWithoutPassword } = user;
    res.json({ token, user: userWithoutPassword });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.get("/api/auth/me", authenticateToken, async (req: any, res) => {
  try {
    const [user] = await sql`
      SELECT uid, email, display_name as "displayName", role, phone_number as "phoneNumber", 
             business_name as "businessName", service_governorate as "serviceGovernorate"
      FROM hub_users WHERE uid = ${req.user.uid}
    `;
    res.json(user);
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// Users Routes
app.get("/api/users", authenticateToken, async (req: any, res) => {
  try {
    const [admin] = await sql`SELECT role FROM hub_users WHERE uid = ${req.user.uid}`;
    if (admin.role !== 'admin') return res.sendStatus(403);

    const users = await sql`
      SELECT uid, email, display_name as "displayName", role, phone_number as "phoneNumber", 
             business_name as "businessName", service_governorate as "serviceGovernorate", created_at as "createdAt"
      FROM hub_users ORDER BY created_at DESC
    `;
    res.json(users);
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.get("/api/users/:uid", authenticateToken, async (req, res) => {
  try {
    const [user] = await sql`
      SELECT uid, email, display_name as "displayName", role, phone_number as "phoneNumber", 
             business_name as "businessName", service_governorate as "serviceGovernorate"
      FROM hub_users WHERE uid = ${req.params.uid}
    `;
    res.json(user);
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.patch("/api/users/:uid", authenticateToken, async (req: any, res) => {
  const data = req.body;
  try {
    const [requester] = await sql`SELECT role FROM hub_users WHERE uid = ${req.user.uid}`;
    if (req.user.uid !== req.params.uid && requester.role !== 'admin') {
      return res.sendStatus(403);
    }

    const updates: any = {};
    if (data.role) updates.role = data.role;
    if (data.phoneNumber) updates.phone_number = data.phoneNumber;
    if (data.serviceGovernorate !== undefined) updates.service_governorate = data.serviceGovernorate;
    if (data.displayName) updates.display_name = data.displayName;

    await sql`
      UPDATE hub_users SET ${sql(updates)} WHERE uid = ${req.params.uid}
    `;
    res.json({ success: true });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// Deliveries Routes
app.get("/api/deliveries", authenticateToken, async (req: any, res) => {
  try {
    const { uid } = req.user;
    const [user] = await sql`SELECT role FROM hub_users WHERE uid = ${uid}`;
    
    let deliveries;
    if (user.role === 'admin') {
      deliveries = await sql`SELECT * FROM hub_deliveries ORDER BY created_at DESC`;
    } else if (user.role === 'business') {
      deliveries = await sql`SELECT * FROM hub_deliveries WHERE business_id = ${uid} ORDER BY created_at DESC`;
    } else {
      deliveries = await sql`SELECT * FROM hub_deliveries ORDER BY created_at DESC`;
    }
    
    const transformed = deliveries.map(d => ({
      id: d.id,
      businessId: d.business_id,
      businessName: d.business_name,
      deliveryGuyId: d.delivery_guy_id,
      deliveryGuyName: d.delivery_guy_name,
      deliveryGuyPhone: d.delivery_guy_phone,
      status: d.status,
      paymentStatus: d.payment_status,
      receiptUrl: d.receipt_url,
      governorate: d.governorate,
      pickupAddress: d.pickup_address,
      pickupCoords: { lat: d.pickup_lat, lng: d.pickup_lng },
      dropoffAddress: d.dropoff_address,
      dropoffCoords: { lat: d.dropoff_lat, lng: d.dropoff_lng },
      customerName: d.customer_name,
      customerPhone: d.customer_phone,
      itemDescription: d.item_description,
      price: d.price,
      createdAt: d.created_at,
      updatedAt: d.updated_at
    }));

    res.json(transformed);
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.post("/api/deliveries", authenticateToken, async (req: any, res) => {
  const data = req.body;
  const id = Math.random().toString(36).substring(2, 15);
  try {
    await sql`
      INSERT INTO hub_deliveries (
        id, business_id, business_name, status, payment_status, receipt_url, governorate, 
        pickup_address, pickup_lat, pickup_lng, dropoff_address, dropoff_lat, dropoff_lng,
        customer_name, customer_phone, item_description, price
      ) VALUES (
        ${id}, ${req.user.uid}, ${data.businessName}, ${data.status}, ${data.paymentStatus}, ${data.receiptUrl}, ${data.governorate},
        ${data.pickupAddress}, ${data.pickupCoords?.lat}, ${data.pickupCoords?.lng}, 
        ${data.dropoffAddress}, ${data.dropoffCoords?.lat}, ${data.dropoffCoords?.lng},
        ${data.customerName}, ${data.customerPhone}, ${data.item_description || data.itemDescription}, ${data.price}
      )
    `;
    res.json({ id });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.patch("/api/deliveries/:id", authenticateToken, async (req, res) => {
  const data = req.body;
  try {
    const updates: any = {};
    if (data.status) updates.status = data.status;
    if (data.paymentStatus) updates.payment_status = data.paymentStatus;
    if (data.deliveryGuyId) updates.delivery_guy_id = data.deliveryGuyId;
    if (data.deliveryGuyName) updates.delivery_guy_name = data.deliveryGuyName;
    if (data.deliveryGuyPhone) updates.delivery_guy_phone = data.deliveryGuyPhone;
    
    updates.updated_at = new Date();

    await sql`
      UPDATE hub_deliveries SET ${sql(updates)} WHERE id = ${req.params.id}
    `;
    res.json({ success: true });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// Catch-all for undefined API routes
app.all("/api/*", (req, res) => {
  res.status(404).json({ error: `API route not found: ${req.method} ${req.url}` });
});

// For Vercel, we export the app
export default app;
