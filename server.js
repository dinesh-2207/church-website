// ---------- FGM ADMIN BACKEND (with Auth, Event Details, About, Ministries) ----------
const express = require("express");
const mysql = require("mysql2");
const bcrypt = require("bcryptjs"); // ✅ Correct: Using bcryptjs
const cors = require("cors");
const path = require("path");
const bodyParser = require("body-parser");
const multer = require("multer"); // For file uploads
const fs = require("fs"); // For file system operations
const jwt = require("jsonwebtoken"); // 🌟 For authentication
const nodemailer = require("nodemailer"); // --- 🌟 NEW: For sending emails 🌟 ---
const stripe = require("stripe"); // --- 🌟 NEW: For payments 🌟 ---
require("dotenv").config();

const app = express();
app.use(cors());
app.use(express.json());
app.use(bodyParser.urlencoded({ extended: true }));

// --- Serve frontend files AND the uploads folder ---
app.use(express.static(path.join(__dirname, "public")));
app.use("/uploads", express.static(path.join(__dirname, "public/uploads")));

// --- 🌟 NEW: Stripe Initialization 🌟 ---
let stripeInstance;
if (process.env.STRIPE_SECRET_KEY) {
  stripeInstance = stripe(process.env.STRIPE_SECRET_KEY);
  console.log("✅ Stripe payment gateway configured.");
} else {
  console.warn("❌ Stripe (STRIPE_SECRET_KEY) is NOT configured in .env file. Payment API will not work.");
}


// --- 🌟 NEW: Nodemailer Transporter 🌟 ---
let transporter;
if (process.env.EMAIL_USER && process.env.EMAIL_PASS) {
  transporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST,
    port: parseInt(process.env.EMAIL_PORT || "587"),
    secure: process.env.EMAIL_PORT === '465', // true for 465, false for other ports
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
  });
  
  transporter.verify((error, success) => {
    if (error) {
      console.warn("❌ Nodemailer config error:", error.message);
      console.warn("Email sending might fail. Check .env variables (EMAIL_USER, EMAIL_PASS, etc.)");
    } else {
      console.log("✅ Nodemailer is ready to send emails");
    }
  });

} else {
  console.warn("❌ Email (Nodemailer) is NOT configured. Skipping email setup.");
  console.warn("Add EMAIL_USER, EMAIL_PASS, EMAIL_HOST, etc. to .env to enable email features.");
}


// --- Database Connection ---
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

db.connect((err) => {
  if (err) {
    console.error("❌ DB Connection Failed:", err);
  } else {
    console.log("✅ Connected to Clever Cloud MySQL!");
  }
});

// --- Multer Configuration (File Uploads) ---
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = 'public/uploads/';
    if (!fs.existsSync(uploadDir)){
        fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + "-" + file.originalname);
  },
});
const upload = multer({ storage: storage });

// --- Helper Function to Get a Record (for deleting/editing images) ---
const getRecordById = (table, id) => {
  return new Promise((resolve, reject) => {
    db.query(`SELECT * FROM ${table} WHERE id = ?`, [id], (err, results) => {
      if (err) return reject(err);
      resolve(results[0]);
    });
  });
};

// --- Helper Function to Delete a File ---
const deleteFile = (filePath) => {
  if (!filePath) return;
  if (!filePath.startsWith("uploads/")) {
    console.warn(
      `Skipping delete: File path '${filePath}' is not in uploads folder.`
    );
    return;
  }
  const actualPath = path.join(__dirname, "public", filePath);
  fs.unlink(actualPath, (err) => {
    if (err) {
      console.warn(`Could not delete file ${actualPath}:`, err.message);
    } else {
      console.log(`Deleted file ${actualPath}`);
    }
  });
};

// --- 🌟 JWT Secret & Auth Middleware 🌟 ---
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
    console.error("FATAL ERROR: JWT_SECRET is not defined in .env file.");
    process.exit(1);
}

const verifyToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1]; // Bearer TOKEN

  if (token == null) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      console.warn("JWT Verification failed:", err.message);
      return res.status(403).json({ error: "Invalid token." });
    }
    req.user = user; // Add user payload to request
    next(); // Proceed to the protected route
  });
};

// --- 🌟 Login (Updated to generate JWT) 🌟 ---
app.post("/api/login", (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required." });
  }
  db.query("SELECT * FROM admin WHERE email = ?", [email], async (err, results) => {
    if (err) return res.status(500).json({ error: "Database error" });
    if (results.length === 0)
      return res.status(401).json({ error: "Invalid email or password" });

    const user = results[0];
    const match = await bcrypt.compare(password, user.password);

    if (!match)
      return res.status(401).json({ error: "Invalid email or password" });

    const tokenPayload = { id: user.id, email: user.email };
    const token = jwt.sign(tokenPayload, JWT_SECRET, { expiresIn: "1d" });
    res.json({ success: true, message: "Login successful", token: token });
  });
});

// --- 🌟 NEW: HELPER FUNCTION FOR SENDING EMAILS 🌟 ---
const sendEmailNotification = async (subject, htmlContent, res) => {
  if (!transporter) {
    console.warn("Email not sent: Nodemailer is not configured.");
    return res.json({ success: true, message: "Form submitted (email admin not configured)." });
  }
  if (!process.env.CHURCH_EMAIL) {
     console.warn("Email not sent: CHURCH_EMAIL is not set in .env");
     return res.json({ success: true, message: "Form submitted (church contact email not set)." });
  }
  const mailOptions = {
    from: `"FGM Website" <${process.env.EMAIL_USER}>`,
    to: process.env.CHURCH_EMAIL,
    subject: subject,
    html: htmlContent,
  };
  try {
    await transporter.sendMail(mailOptions);
    res.json({ success: true, message: "Form submitted successfully!" });
  } catch (error) {
    console.error("❌ Failed to send email:", error);
    res.status(500).json({ error: "Failed to send notification email." });
  }
};

// --- 🌟 NEW: 'CONNECT' FORM API (PUBLIC) 🌟 ---
app.post("/api/connect", (req, res) => {
  const { name, email, phonenumber, message } = req.body;
  if (!name || !email || !phonenumber) {
    return res.status(400).json({ error: "Name, email and phone number are required." });
  }
  const subject = "New 'Connect' Form Submission";
  const htmlContent = `
    <h2>New Connect Form Submission</h2>
    <p><strong>Name:</strong> ${name}</p>
    <p><strong>Email:</strong> ${email}</p>
    <p><strong>Phone Number:</strong> ${phonenumber}</p>
    <p><strong>Message:</strong></p>
    <p>${message.replace(/\n/g, "<br>") || "No message provided."}</p>
  `;
  sendEmailNotification(subject, htmlContent, res);
});

// --- 🌟 NEW: 'PLAN VISIT' FORM API (PUBLIC) 🌟 ---
app.post("/api/plan-visit", (req, res) => {
  const { name, email, phonenumber, service } = req.body;
  if (!name || !email || !phonenumber || !service) {
    return res.status(400).json({ error: "All fields are required." });
  }
  const subject = "New 'Plan Your Visit' Submission";
  const htmlContent = `
    <h2>New 'Plan Your Visit' Submission</h2>
    <p><strong>Name:</strong> ${name}</p>
    <p><strong>Email:</strong> ${email}</p>
    <p><strong>Phone Number:</strong> ${phonenumber}</p>
    <p><strong>Attending Service:</strong> ${service}</p>
  `;
  sendEmailNotification(subject, htmlContent, res);
});

// --- 🌟 NEW: 'EVENT REGISTRATION' FORM API (PUBLIC) 🌟 ---
app.post("/api/event-registration", (req, res) => {
  const { name, email, phonenumber, guests, eventName } = req.body; 
  if (!name || !email || !phonenumber || !guests || !eventName) {
    return res.status(400).json({ error: "All fields are required." });
  }
  const subject = `New Registration for '${eventName}'`;
  const htmlContent = `
    <h2>New Event Registration</h2>
    <p><strong>Event:</strong> ${eventName}</p>
    <p><strong>Name:</strong> ${name}</p>
    <p><strong>Email:</strong> ${email}</p>
    <p><strong>Phone Number:</strong> ${phonenumber}</p>
    <p><strong>Number of Guests:</strong> ${guests}</p>
  `;
  sendEmailNotification(subject, htmlContent, res);
});

// --- 🌟 NEW: 'GIVING' PAYMENT API (PUBLIC) 🌟 ---
app.post("/api/create-payment-intent", async (req, res) => {
  const { amount, frequency, name, email } = req.body;
  if (!amount || isNaN(Number(amount)) || Number(amount) < 1) {
     return res.status(400).json({ error: "A valid amount is required." });
  }
  if (!stripeInstance) {
      console.error("❌ Payment failed: STRIPE_SECRET_KEY is not set.");
      return res.status(500).json({ error: "Payment processing is not configured."});
  }
  const amountInCents = Math.round(Number(amount) * 100);

  if (frequency === "one-time") {
    try {
      const paymentIntent = await stripeInstance.paymentIntents.create({
        amount: amountInCents,
        currency: "usd",
        description: "One-Time Donation to FGM",
        receipt_email: email,
        metadata: {
            name: name,
            donation_type: "One-Time"
        }
      });
      res.json({ clientSecret: paymentIntent.client_secret });
    } catch (error) {
      console.error("❌ Stripe PaymentIntent error:", error.message);
      res.status(500).json({ error: "Failed to create payment." });
    }
  } 
  else {
    console.warn(`Subscription logic for '${frequency}' not yet implemented.`);
    res.status(501).json({ error: "Recurring payments (Monthly/Weekly) are not yet implemented. Please select 'One-Time'." });
  }
});


// --- 🌟 EVENTS API (CRUD - UPDATED FOR DETAILS) 🌟 ---
// (No changes here, indha section appadiye irukku)
app.get("/api/events", (req, res) => {
  db.query(
    "SELECT id, title, subtitle, description, imageUrl FROM events ORDER BY id DESC",
    (err, rows) => {
      if (err) return res.status(500).json({ error: "Failed to fetch events" });
      res.json(rows);
    }
  );
});
app.get("/api/events/:id", (req, res) => {
  const { id } = req.params;
  db.query("SELECT * FROM events WHERE id = ?", [id], (err, results) => {
    if (err) {
      console.error("❌ SQL Error (GET Event ID):", err);
      return res.status(500).json({ error: "Failed to fetch event details" });
    }
    if (results.length === 0) {
      return res.status(404).json({ error: "Event not found" });
    }
    res.json(results[0]);
  });
});
app.post(
  "/api/events",
  verifyToken, 
  upload.fields([
    { name: "image", maxCount: 1 }, 
    { name: "detailImage", maxCount: 1 },
  ]),
  (req, res) => {
    const { title, subtitle, description, fullDescription, registrationNote } =
      req.body;
    const imageUrl = req.files["image"]
      ? `uploads/${req.files["image"][0].filename}`
      : null;
    const detailImageUrl = req.files["detailImage"]
      ? `uploads/${req.files["detailImage"][0].filename}`
      : null;
    const sql = `INSERT INTO events (title, subtitle, description, imageUrl, fullDescription, registrationNote, detailImageUrl) VALUES (?, ?, ?, ?, ?, ?, ?)`;
    const params = [
      title,
      subtitle,
      description,
      imageUrl,
      fullDescription,
      registrationNote,
      detailImageUrl,
    ];
    db.query(sql, params, (err, result) => {
      if (err) {
        console.error("❌ SQL INSERT Error (Events):", err);
        return res.status(500).json({ error: "Failed to add event" });
      }
      res.json({ success: true, id: result.insertId });
    });
  }
);
app.put(
  "/api/events/:id",
  verifyToken, 
  upload.fields([
    { name: "image", maxCount: 1 },
    { name: "detailImage", maxCount: 1 },
  ]),
  async (req, res) => {
    const { id } = req.params;
    const {
      title,
      subtitle,
      description,
      fullDescription,
      registrationNote,
      existingImageUrl,
      existingDetailImageUrl,
    } = req.body;
    let imageUrl = existingImageUrl || null;
    let detailImageUrl = existingDetailImageUrl || null;

    try {
      const oldRecord = await getRecordById("events", id);
      if (req.files["image"]) {
        if (oldRecord && oldRecord.imageUrl) {
          deleteFile(oldRecord.imageUrl);
        }
        imageUrl = `uploads/${req.files["image"][0].filename}`;
      }
      if (req.files["detailImage"]) {
        if (oldRecord && oldRecord.detailImageUrl) {
          deleteFile(oldRecord.detailImageUrl);
        }
        detailImageUrl = `uploads/${req.files["detailImage"][0].filename}`;
      }
      const sql = `UPDATE events SET title = ?, subtitle = ?, description = ?, imageUrl = ?, fullDescription = ?, registrationNote = ?, detailImageUrl = ? WHERE id = ?`;
      const params = [
        title,
        subtitle,
        description,
        imageUrl,
        fullDescription,
        registrationNote,
        detailImageUrl,
        id,
      ];
      db.query(sql, params, (err, result) => {
        if (err) {
          console.error("❌ SQL UPDATE Error (Events):", err);
          return res.status(500).json({ error: "Failed to update event" });
        }
        res.json({ success: true, message: "Event updated" });
      });
    } catch (err) {
      console.error("❌ Server Error (PUT Event):", err);
      res.status(500).json({ error: "Server error during update." });
    }
  }
);
app.delete("/api/events/:id", verifyToken, async (req, res) => {
  const { id } = req.params;
  try {
    const record = await getRecordById("events", id);
    if (record) {
      if (record.imageUrl) deleteFile(record.imageUrl);
      if (record.detailImageUrl) deleteFile(record.detailImageUrl);
    }
    db.query("DELETE FROM events WHERE id = ?", [id], (err, result) => {
      if (err) {
        console.error("❌ SQL DELETE Error (Events):", err);
        return res.status(500).json({ error: "Failed to delete event" });
      }
      res.json({ success: true, message: "Event deleted" });
    });
  } catch (err) {
    console.error("❌ Server Error (DELETE Event):", err);
    res.status(500).json({ error: "Server error during delete." });
  }
});


// --- 🌟 NEW: MINISTRIES API (CRUD) 🌟 ---
// (No changes here, indha section appadiye irukku)
app.get("/api/ministries", (req, res) => {
  db.query(
    "SELECT id, title, subtitle, description, imageUrl FROM ministries ORDER BY id DESC",
    (err, rows) => {
      if (err) return res.status(500).json({ error: "Failed to fetch ministries" });
      res.json(rows);
    }
  );
});
app.get("/api/ministries/:id", (req, res) => {
  const { id } = req.params;
  db.query("SELECT * FROM ministries WHERE id = ?", [id], (err, results) => {
    if (err) {
      console.error("❌ SQL Error (GET Ministry ID):", err);
      return res.status(500).json({ error: "Failed to fetch ministry details" });
    }
    if (results.length === 0) {
      return res.status(404).json({ error: "Ministry not found" });
    }
    res.json(results[0]);
  });
});
app.post(
  "/api/ministries",
  verifyToken, 
  upload.fields([
    { name: "image", maxCount: 1 }, 
    { name: "detailImage", maxCount: 1 },
  ]),
  (req, res) => {
    const { title, subtitle, description, fullDescription } = req.body;
    const imageUrl = req.files["image"]
      ? `uploads/${req.files["image"][0].filename}`
      : null;
    const detailImageUrl = req.files["detailImage"]
      ? `uploads/${req.files["detailImage"][0].filename}`
      : null;
    const sql = `INSERT INTO ministries (title, subtitle, description, imageUrl, fullDescription, detailImageUrl) VALUES (?, ?, ?, ?, ?, ?)`;
    const params = [
      title,
      subtitle,
      description,
      imageUrl,
      fullDescription,
      detailImageUrl,
    ];
    db.query(sql, params, (err, result) => {
      if (err) {
        console.error("❌ SQL INSERT Error (Ministries):", err);
        return res.status(500).json({ error: "Failed to add ministry" });
      }
      res.json({ success: true, id: result.insertId });
    });
  }
);
app.put(
  "/api/ministries/:id",
  verifyToken, 
  upload.fields([
    { name: "image", maxCount: 1 },
    { name: "detailImage", maxCount: 1 },
  ]),
  async (req, res) => {
    const { id } = req.params;
    const {
      title,
      subtitle,
      description,
      fullDescription,
      existingImageUrl,
      existingDetailImageUrl,
    } = req.body;
    let imageUrl = existingImageUrl || null;
    let detailImageUrl = existingDetailImageUrl || null;
    try {
      const oldRecord = await getRecordById("ministries", id);
      if (req.files["image"]) {
        if (oldRecord && oldRecord.imageUrl) {
          deleteFile(oldRecord.imageUrl);
        }
        imageUrl = `uploads/${req.files["image"][0].filename}`;
      }
      if (req.files["detailImage"]) {
        if (oldRecord && oldRecord.detailImageUrl) {
          deleteFile(oldRecord.detailImageUrl);
        }
        detailImageUrl = `uploads/${req.files["detailImage"][0].filename}`;
      }
      const sql = `UPDATE ministries SET title = ?, subtitle = ?, description = ?, imageUrl = ?, fullDescription = ?, detailImageUrl = ? WHERE id = ?`;
      const params = [
        title,
        subtitle,
        description,
        imageUrl,
        fullDescription,
        detailImageUrl,
        id,
      ];
      db.query(sql, params, (err, result) => {
        if (err) {
          console.error("❌ SQL UPDATE Error (Ministries):", err);
          return res.status(500).json({ error: "Failed to update ministry" });
        }
        res.json({ success: true, message: "Ministry updated" });
TA     });
    } catch (err) {
      console.error("❌ Server Error (PUT Ministry):", err);
      res.status(500).json({ error: "Server error during update." });
    }
  }
);
app.delete("/api/ministries/:id", verifyToken, async (req, res) => {
  const { id } = req.params;
  try {
    const record = await getRecordById("ministries", id);
    if (record) {
      if (record.imageUrl) deleteFile(record.imageUrl);
      if (record.detailImageUrl) deleteFile(record.detailImageUrl);
    }
    db.query("DELETE FROM ministries WHERE id = ?", [id], (err, result) => {
      if (err) {
        console.error("❌ SQL DELETE Error (Ministries):", err);
        return res.status(500).json({ error: "Failed to delete ministry" });
      }
      res.json({ success: true, message: "Ministry deleted" });
    });
  } catch (err) {
    console.error("❌ Server Error (DELETE Ministry):", err);
    res.status(500).json({ error: "Server error during delete." });
  }
});

// --- 🌟 LOCATIONS API (CRUD - NOW SECURED) 🌟 ---
// (No changes here, indha section appadiye irukku)
app.get("/api/locations", (req, res) => {
  db.query(
    "SELECT id, title, subtitle, description, imageUrl FROM locations ORDER BY id DESC",
    (err, rows) => {
      if (err)
        return res.status(500).json({ error: "Failed to fetch locations" });
      res.json(rows);
    }
  );
});
app.get("/api/locations/:id", (req, res) => {
  const { id } = req.params;
  db.query("SELECT * FROM locations WHERE id = ?", [id], (err, results) => {
    if (err) {
      console.error("❌ SQL Error (GET Location ID):", err);
      return res.status(500).json({ error: "Failed to fetch location details" });
    }
    if (results.length === 0) {
      return res.status(404).json({ error: "Location not found" });
    }
    res.json(results[0]);
  });
});
app.post(
  "/api/locations",
  verifyToken, 
  upload.fields([
    { name: "image", maxCount: 1 },
    { name: "detailImage", maxCount: 1 },
  ]),
  (req, res) => {
    const {
      title,
      subtitle,
      description,
      pastorName,
      phone,
      email,
      address,
      mailingAddress,
     googleMapEmbed,
    } = req.body;
    const imageUrl = req.files["image"]
      ? `uploads/${req.files["image"][0].filename}`
      : null;
    const detailImageUrl = req.files["detailImage"]
      ? `uploads/${req.files["detailImage"][0].filename}`
      : null;
    const sql = `INSERT INTO locations (title, subtitle, description, imageUrl, pastorName, phone, email, address, mailingAddress, googleMapEmbed, detailImageUrl) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;
    const params = [
      title,
      subtitle,
      description,
      imageUrl,
      pastorName,
      phone,
      email,
      address,
      mailingAddress,
     googleMapEmbed,
      detailImageUrl,
    ];
    db.query(sql, params, (err, result) => {
      if (err) {
        console.error("❌ SQL INSERT Error (Locations):", err);
        return res.status(500).json({ error: "Failed to add location" });
      }
      res.json({ success: true, id: result.insertId });
    });
  }
);
app.put(
  "/api/locations/:id",
  verifyToken, 
  upload.fields([
    { name: "image", maxCount: 1 },
    { name: "detailImage", maxCount: 1 },
  ]),
  async (req, res) => {
    const { id } = req.params;
    const {
      title,
      subtitle,
      description,
      pastorName,
      phone,
      email,
      address,
      mailingAddress,
      googleMapEmbed,
      existingImageUrl,
      existingDetailImageUrl,
    } = req.body;
    let imageUrl = existingImageUrl || null;
    let detailImageUrl = existingDetailImageUrl || null;
    
    try {
      const oldRecord = await getRecordById("locations", id);
      if (req.files["image"]) {
        if (oldRecord && oldRecord.imageUrl) {
          deleteFile(oldRecord.imageUrl);
        }
        imageUrl = `uploads/${req.files["image"][0].filename}`;
      }
      if (req.files["detailImage"]) {
        if (oldRecord && oldRecord.detailImageUrl) {
          deleteFile(oldRecord.detailImageUrl);
        }
        detailImageUrl = `uploads/${req.files["detailImage"][0].filename}`;
      }
      const sql = `UPDATE locations SET title = ?, subtitle = ?, description = ?, imageUrl = ?, pastorName = ?, phone = ?, email = ?, address = ?, mailingAddress = ?, googleMapEmbed = ?, detailImageUrl = ? WHERE id = ?`;
      const params = [
        title,
        subtitle,
        description,
        imageUrl,
        pastorName,
        phone,
        email,
        address,
        mailingAddress,
        googleMapEmbed,
        detailImageUrl,
        id,
      ];
      db.query(sql, params, (err, result) => {
        if (err) {
          console.error("❌ SQL UPDATE Error (Locations):", err);
          return res.status(500).json({ error: "Failed to update location" });
        }
        res.json({ success: true, message: "Location updated" });
      });
    } catch (err) {
      console.error("❌ Server Error (PUT Location):", err);
      res.status(500).json({ error: "Server error during update." });
    }
  }
);
app.delete("/api/locations/:id", verifyToken, async (req, res) => {
  const { id } = req.params;
  try {
    const record = await getRecordById("locations", id);
    if (record) {
      if (record.imageUrl) deleteFile(record.imageUrl);
      if (record.detailImageUrl) deleteFile(record.detailImageUrl);
    }
    db.query("DELETE FROM locations WHERE id = ?", [id], (err, result) => {
      if (err) {
        console.error("❌ SQL DELETE Error (Locations):", err);
        return res.status(500).json({ error: "Failed to delete location" });
      }
      res.json({ success: true, message: "Location deleted" });
    });
  } catch (err) {
    console.error("❌ Server Error (DELETE Location):", err);
    res.status(500).json({ error: "Server error during delete." });
  }
});

// --- 🌟 GALLERY API (CRUD - NOW SECURED) 🌟 ---
// (No changes here, indha section appadiye irukku)
app.get("/api/gallery", (req, res) => {
  db.query("SELECT * FROM gallery ORDER BY id DESC", (err, rows) => {
    if (err) return res.status(500).json({ error: "Failed to fetch gallery" });
    res.json(rows);
  });
});
app.post("/api/gallery", verifyToken, upload.single("image"), (req, res) => {
  const { category } = req.body;
  const imageUrl = req.file ? `uploads/${req.file.filename}` : null;
  if (!imageUrl) {
    return res.status(400).json({ error: "Image file is required." });
  }
  db.query(
    "INSERT INTO gallery (imageUrl, category) VALUES (?, ?)",
    [imageUrl, category],
    (err, result) => {
      if (err) {
        console.error("❌ SQL INSERT Error (Gallery):", err);
        return res.status(500).json({ error: "Failed to add photo" });
      }
      res.json({ success: true, id: result.insertId });
    }
  );
});
app.delete("/api/gallery/:id", verifyToken, async (req, res) => {
  const { id } = req.params;
  try {
    const record = await getRecordById("gallery", id);
    if (record && record.imageUrl) {
      deleteFile(record.imageUrl);
    }
    db.query("DELETE FROM gallery WHERE id = ?", [id], (err, result) => {
      if (err) {
        console.error("❌ SQL DELETE Error (Gallery):", err);
        return res.status(500).json({ error: "Failed to delete photo" });
      }
      res.json({ success: true, message: "Photo deleted" });
    });
  } catch (err) {
    console.error("❌ Server Error (DELETE Gallery):", err);
    res.status(500).json({ error: "Server error during delete." });
  }
});

// --- 🌟🌟🌟 ABOUT PAGE API (UPDATED FOR IMAGE) 🌟🌟🌟 ---

// GET About Content - 🌟 UPDATED 🌟
app.get("/api/about", (req, res) => {
    // Select all fields, including the new imageUrl
    db.query("SELECT * FROM about_content WHERE id = 1", (err, results) => {
        if (err)
            return res.status(500).json({ error: "Failed to fetch about content" });
        
        if (results.length === 0) {
            // If no content, create a default one
            // 🌟 Updated to include imageUrl as NULL
            db.query("INSERT INTO about_content (id, ourMission, ourStory, imageUrl) VALUES (1, 'Our mission...', 'Our story...', NULL)", (insertErr) => {
                if (insertErr) return res.status(500).json({ error: "Failed to init about content" });
                res.json({ ourMission: 'Our mission...', ourStory: 'Our story...', imageUrl: null });
            });
        } else {
            res.json(results[0]); // This will now include imageUrl
        }
    });
});

// PUT About Content - 🌟 UPDATED 🌟
app.put("/api/about", verifyToken, upload.single("image"), async (req, res) => { // Added upload.single
    const { ourMission, ourStory, existingImageUrl } = req.body;
    let imageUrl = existingImageUrl || null; // Start with the old URL

    if (ourMission === undefined || ourStory === undefined) {
        return res.status(400).json({ error: "Both ourMission and ourStory fields are required." });
    }

    try {
        // Check if a new file was uploaded
        if (req.file) {
            imageUrl = `uploads/${req.file.filename}`; // Set new image path
            
            // Delete the old image if it exists and is different
            if (existingImageUrl && existingImageUrl !== imageUrl) {
                deleteFile(existingImageUrl);
            }
        }

        // Now, update the database
        const sql = "UPDATE about_content SET ourMission = ?, ourStory = ?, imageUrl = ? WHERE id = 1";
        const params = [ourMission, ourStory, imageUrl];

        db.query(sql, params, (err, result) => {
            if (err) {
                console.error("❌ SQL UPDATE Error (About):", err);
                return res.status(500).json({ error: "Failed to update about content" });
            }
            res.json({ success: true, message: "About page updated", imageUrl: imageUrl }); // Send back the new path
        });

    } catch (err) {
        console.error("❌ Server Error (PUT About):", err);
        res.status(500).json({ error: "Server error during update." });
    }
});

// --- Server ---
const PORT = process.env.PORT || 5000; // Use port from .env or fallback to 5000
app.listen(PORT, () =>
    console.log(`🚀 Server running at http://localhost:${PORT}`)
);