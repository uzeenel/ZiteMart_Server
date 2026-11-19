const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const path = require('path');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
if (require('fs').existsSync('.env.pg')) {
    require('dotenv').config({ path: '.env.pg', override: true });
} else {
    require('dotenv').config();
}
// Set timezone to West Africa Time (UTC+1)
process.env.TZ = 'Africa/Lagos';

const app = express();
const PORT = process.env.PORT || 3000;
// Add multer configuration at the top of your file (after other requires)
const multer = require('multer');

// Middleware
app.use(cors());
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Database connection
// Database connection — credentials come from env only (.env.pg locally,
// Render env vars in cloud). No hardcoded fallbacks for user/password.
const _pgPool = new Pool({
    host:     process.env.DB_HOST,
    user:     process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port:     process.env.DB_PORT ? parseInt(process.env.DB_PORT) : 5432,
    ssl: { rejectUnauthorized: false },
    max: 10,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 10000,
});

function _toPg(sql) {
    let counter = 0;
    return sql.replace(/\?/g, () => `$${++counter}`);
}

const pool = {
    query: async (sql, params) => {
        const result = await _pgPool.query(_toPg(sql), params || []);
        return [result.rows, result.fields];
    },
    connect: async () => {
        const client = await _pgPool.connect();
        return {
            query: async (sql, params) => {
                const result = await client.query(_toPg(sql), params || []);
                return [result.rows, result.fields];
            },
            beginTransaction: () => client.query('BEGIN'),
            commit: () => client.query('COMMIT'),
            rollback: () => client.query('ROLLBACK'),
            release: () => client.release(),
        };
    },
};

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-this';

let requestCounter = 0;

app.post("/api/register", async (req, res) => {
  const { businessName, businessSlug, email, username, password, fullName } =
    req.body;

  if (!businessName || !businessSlug || !username || !password) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  // Basic slug validation (lowercase, no spaces)
  const slug = businessSlug.toLowerCase().replace(/[^a-z0-9-]/g, "");
  if (slug.length < 3) {
    return res
      .status(400)
      .json({ error: "Business code must be at least 3 characters" });
  }

  const client = await _pgPool.connect();
  try {
    await client.query("BEGIN");

    // 1. Check if slug is taken
    const slugCheck = await client.query(
      "SELECT id FROM tenants WHERE slug = $1",
      [slug],
    );
    if (slugCheck.rows.length > 0) {
      await client.query("ROLLBACK");
      return res.status(400).json({ error: "Business code is already taken" });
    }

    // 2. Create the tenant
    const tenantResult = await client.query(
      `INSERT INTO tenants (slug, name, email, status) 
             VALUES ($1, $2, $3, 'active') RETURNING id`,
      [slug, businessName, email || ""],
    );
    const tenantId = tenantResult.rows[0].id;

    // Set RLS context to the new tenant so we can insert their roles and users
    await client.query("SELECT set_config('app.tenant_id', $1, true)", [
      String(tenantId),
    ]);

    // 3. Create the default 'admin' role for this tenant
    const roleResult = await client.query(
      `INSERT INTO roles (name, description, is_system, tenant_id) 
             VALUES ('admin', 'Full access to everything', 1, $1) RETURNING id`,
      [tenantId],
    );
    const roleId = roleResult.rows[0].id;

    // 4. Fetch all global permissions and assign them to the admin role
    // 4. Fetch all global permissions and assign them to the admin role
    const perms = await client.query("SELECT id FROM permissions");
    if (perms.rows.length > 0) {
      // Build placeholders like ($1, $2, $3), ($1, $4, $3), etc.
      const placeholders = perms.rows
        .map((_, i) => `($1, $${i + 2}, $${perms.rows.length + 2})`)
        .join(", ");

      const flatParams = [roleId];
      for (const p of perms.rows) {
        flatParams.push(p.id);
      }
      flatParams.push(tenantId); // This goes at the very end ($29)

      await client.query(
        `INSERT INTO role_permissions (role_id, permission_id, tenant_id) VALUES ${placeholders}`,
        flatParams,
      );
    }

    // 5. Hash password and create the admin user
    const hashedPassword = await bcrypt.hash(password, 10);
    await client.query(
      `INSERT INTO users (username, password, full_name, role, role_id, is_active, tenant_id) 
             VALUES ($1, $2, $3, 'admin', $4, 1, $5)`,
      [username, hashedPassword, fullName || username, roleId, tenantId],
    );

    await client.query("COMMIT");
    res.json({ message: "Registration successful", tenant_slug: slug });
  } catch (error) {
    await client.query("ROLLBACK");
    console.error("Registration error:", error);
    res.status(500).json({ error: "Registration failed" });
  } finally {
    client.release();
  }
});

// ==================== AUTH ENDPOINTS ====================

app.post("/api/login", async (req, res) => {
  try {
    const { username, password, tenant_slug } = req.body;

    // Resolve tenant. Accepts either:
    //   1. tenant_slug from request body (tenant-picker, works today)
    //   2. subdomain from Host header (once wildcard is enabled)
    let tenantId = null;
    let slug = tenant_slug;

    if (!slug) {
      // Fallback: try subdomain from Host header
      const host = (req.headers.host || "").split(":")[0];
      const parts = host.split(".");
      if (parts.length > 2 && parts[0] !== "www") {
        slug = parts[0];
      }
    }

    if (slug) {
      const [tenants] = await pool.query(
        "SELECT id, slug, status FROM tenants WHERE slug = $1",
        [slug],
      );
      if (tenants.length === 0) {
        return res.status(401).json({ error: "Invalid credentials" });
      }
      if (tenants[0].status !== "active") {
        return res
          .status(401)
          .json({ error: "Business account is not active" });
      }
      tenantId = tenants[0].id;
    } else {
      // No tenant provided — reject. SaaS login requires tenant context.
      return res.status(400).json({ error: "Business code required" });
    }

    // Open a dedicated connection, set tenant context, then query users.
    // This works under RLS: app.tenant_id filters users to the resolved tenant.
    const client = await _pgPool.connect();
    try {
      await client.query("BEGIN");
      await client.query("SELECT set_config('app.tenant_id', $1, true)", [
        String(tenantId),
      ]);

      const result = await client.query(
        "SELECT * FROM users WHERE username = $1",
        [username],
      );
      const users = result.rows;

      if (users.length === 0) {
        await client.query("ROLLBACK");
        return res.status(401).json({ error: "Invalid credentials" });
      }

      const user = users[0];

      if (user.is_active !== 1) {
        await client.query("ROLLBACK");
        return res.status(401).json({ error: "Account disabled" });
      }

      const isValid = await bcrypt.compare(password, user.password);
      if (!isValid) {
        await client.query("ROLLBACK");
        return res.status(401).json({ error: "Invalid credentials" });
      }

      await client.query("UPDATE users SET last_login = NOW() WHERE id = $1", [
        user.id,
      ]);

      await client.query("COMMIT");

      const token = jwt.sign(
        {
          id: user.id,
          username: user.username,
          role: user.role,
          tenant_id: user.tenant_id,
        },
        JWT_SECRET,
        { expiresIn: "8h" },
      );

      res.json({
        token,
        user: {
          id: user.id,
          username: user.username,
          fullName: user.full_name,
          role: user.role,
          tenant_id: user.tenant_id,
        },
      });
    } catch (err) {
      await client.query("ROLLBACK");
      throw err;
    } finally {
      client.release();
    }
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ error: "Server error" });
  }
});

// ==================== AUTH MIDDLEWARE ====================

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ error: 'Access denied' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
        return res.status(403).json({ error: "Invalid token" });
        }
        if (!user || !user.tenant_id) {
        return res
            .status(403)
            .json({ error: "Token missing tenant context" });
        }
        req.user = user;
        next();
    });
};

// Tenant context middleware — must run AFTER authenticateToken.
// Acquires a dedicated client, begins a transaction, sets app.tenant_id
// for the duration of this request, and attaches the client as req.db.
// Routes that touch tenant-scoped data should use req.db.query() instead
// of pool.query(). On response finish/close, COMMIT (or ROLLBACK on error)
// and release the client.
const setTenantContext = async (req, res, next) => {
    let client;
    try {
        client = await _pgPool.connect();
        await client.query('BEGIN');
        await client.query("SELECT set_config('app.tenant_id', $1, true)", [String(req.user.tenant_id)]);
        req.db = {
            query: async (sql, params) => {
                const result = await client.query(_toPg(sql), params || []);
                return [result.rows, result.fields];
            },
        };
        let finished = false;
        const cleanup = async (err) => {
            if (finished) return;
            finished = true;
            try {
                if (err) { await client.query('ROLLBACK'); }
                else { await client.query('COMMIT'); }
            } catch (_) { /* swallow */ }
            client.release();
        };
        res.on('finish', () => cleanup(null));
        res.on('close', () => cleanup(new Error('connection closed')));
        next();
    } catch (e) {
        if (client) client.release();
        console.error('setTenantContext error:', e.message);
        res.status(500).json({ error: 'Tenant context failure' });
    }
};

// ==================== TEST ENDPOINT ====================

app.get('/api/test', authenticateToken, (req, res) => {
    res.json({ message: 'API is working!', user: req.user });
});

// ==================== PRODUCT ENDPOINTS ====================

app.get(
  "/api/products",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    try {
      const [companyRows] = await req.db.query(
        "SELECT default_markup_percent FROM company LIMIT 1",
      );
      const globalMarkup =
        parseFloat(companyRows[0]?.default_markup_percent) || 0;

      const [products] = await req.db.query(`
            SELECT 
                p.*, 
                c.name as linked_category_name, 
                c.markup_percent as category_markup,
                u.name as unit_name, 
                u.symbol as unit_symbol
            FROM products p
            LEFT JOIN categories c ON p.category_id = c.id
            LEFT JOIN units u ON p.unit_id = u.id
            WHERE p.is_active = 1
            ORDER BY p.name
        `);

      const enriched = products.map((p) => ({
        ...p,
        effective_markup_percent:
          p.markup_percent != null
            ? parseFloat(p.markup_percent)
            : p.category_markup != null
              ? parseFloat(p.category_markup)
              : globalMarkup,
      }));

      res.json(enriched);
    } catch (error) {
      console.error("Error fetching products:", error);
      res.status(500).json({ error: "Server error" });
    }
  },
);

app.get('/api/products/next-sku', async (req, res) => {
  const { category_id, name } = req.query;

  if (!category_id || isNaN(parseInt(category_id))) {
    return res.status(400).json({ error: 'Valid category_id is required' });
  }
  if (!name || name.trim().length === 0) {
    return res.status(400).json({ error: 'Product name is required' });
  }

  try {
    const [categoryRows] = await pool.query(
      'SELECT name FROM categories WHERE id = ?',
      [category_id]
    );

    if (categoryRows.length === 0) {
      return res.status(404).json({ error: 'Category not found' });
    }

    const categoryName = categoryRows[0].name || '';
    const categoryPrefix = categoryName
      .replace(/[^a-zA-Z]/g, '')
      .toUpperCase()
      .slice(0, 3);

    const productInitials = name
      .trim()
      .split(/\s+/)
      .map(w => w.replace(/[^a-zA-Z]/g, '').charAt(0))
      .join('')
      .toUpperCase()
      .slice(0, 4) || 'X';

    const basePrefix = `${categoryPrefix}-${productInitials}-`;

    const [result] = await pool.query(
      `SELECT MAX(CAST(SUBSTRING(sku, LENGTH(?) + 1) AS INTEGER)) AS maxNum
       FROM products
       WHERE sku LIKE ? || '%'`,
      [basePrefix, basePrefix]
    );

    const nextNum = (result[0].maxNum || 0) + 1;
    const nextSku = `${basePrefix}${nextNum.toString().padStart(3, '0')}`;

    res.json({ nextSku });
  } catch (error) {
    console.error('Error generating next SKU:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});


app.get(
  "/api/products/:id",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    try {
      const [companyRows] = await req.db.query(
        "SELECT default_markup_percent FROM company LIMIT 1",
      );
      const globalMarkup =
        parseFloat(companyRows[0]?.default_markup_percent) || 0;

      const [products] = await req.db.query(
        `
            SELECT 
                p.*, 
                c.name as linked_category_name, 
                c.markup_percent as category_markup,
                u.name as unit_name, 
                u.symbol as unit_symbol
            FROM products p
            LEFT JOIN categories c ON p.category_id = c.id
            LEFT JOIN units u ON p.unit_id = u.id
            WHERE p.id = ? AND p.is_active = 1
        `,
        [req.params.id],
      );

      if (products.length === 0) {
        return res.status(404).json({ error: "Product not found" });
      }

      const p = products[0];
      const enriched = {
        ...p,
        effective_markup_percent:
          p.markup_percent != null
            ? parseFloat(p.markup_percent)
            : p.category_markup != null
              ? parseFloat(p.category_markup)
              : globalMarkup,
      };

      res.json(enriched);
    } catch (error) {
      console.error("Error fetching product:", error);
      res.status(500).json({ error: "Server error" });
    }
  },
);


app.post(
  "/api/products",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    try {
      const {
        name,
        sku,
        categoryId,
        unitId,
        barcode,
        costPrice,
        sellingPrice,
        stockQuantity,
        minStockLevel,
        isVatExempt,
        markupPercent,
        markupIsManual,
        imageUrl,
      } = req.body;

      const [existing] = await req.db.query(
        "SELECT id FROM products WHERE sku = ?",
        [sku],
      );
      if (existing.length > 0) {
        return res.status(400).json({ error: "SKU already exists" });
      }

      // Get category name and markup
      let categoryName = null;
      let categoryMarkup = null;
      if (categoryId) {
        const [cats] = await req.db.query(
          "SELECT name, markup_percent FROM categories WHERE id = ?",
          [categoryId],
        );
        if (cats.length > 0) {
          categoryName = cats[0].name;
          categoryMarkup = cats[0].markup_percent;
        }
      }

      // Get global markup
      const [companyRows] = await req.db.query(
        "SELECT default_markup_percent FROM company LIMIT 1",
      );
      const globalMarkup =
        parseFloat(companyRows[0]?.default_markup_percent) || 0;

      // Resolve effective markup
      const productOverride =
        markupPercent != null && markupPercent !== ""
          ? parseFloat(markupPercent)
          : null;
      const effectiveMarkup =
        productOverride != null
          ? productOverride
          : categoryMarkup != null
            ? parseFloat(categoryMarkup)
            : globalMarkup;

      // Determine if SP is manual
      const isManual =
        markupIsManual === true ||
        markupIsManual === 1 ||
        markupIsManual === "true";

      // Compute final SP
      const cost = parseFloat(costPrice) || 0;
      const finalSP = isManual
        ? parseFloat(sellingPrice) || 0
        : parseFloat((cost * (1 + effectiveMarkup / 100)).toFixed(2));

      const [result] = await req.db.query(
        `INSERT INTO products 
             (name, sku, category_id, category_name, unit_id, barcode, 
              cost_price, selling_price, stock_quantity, min_stock_level, 
              is_vat_exempt, is_active, markup_percent, markup_is_manual, tenant_id) 
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?) RETURNING id`,
        [
          name,
          sku,
          categoryId,
          categoryName,
          unitId,
          barcode,
          cost,
          finalSP,
          stockQuantity,
          minStockLevel,
          isVatExempt ? 1 : 0,
          productOverride,
          isManual ? 1 : 0,
          req.user.tenant_id,
        ],
      );

      res.json({
        id: result[0].id,
        selling_price: finalSP,
        markup_percent: productOverride,
        markup_is_manual: isManual ? 1 : 0,
        message: "Product added successfully",
      });
    } catch (error) {
      console.error("Error adding product:", error);
      res.status(500).json({ error: "Server error" });
    }
  },
);

app.put(
  "/api/products/:id",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    try {
      const {
        name,
        sku,
        category_id,
        unit_id,
        barcode,
        cost_price,
        selling_price,
        stock_quantity,
        min_stock_level,
        is_vat_exempt,
        markup_percent,
        markup_is_manual,
        image_url,
      } = req.body;

      // Get category name and markup
      let categoryName = null;
      let categoryMarkup = null;
      if (category_id) {
        const [cats] = await req.db.query(
          "SELECT name, markup_percent FROM categories WHERE id = ?",
          [category_id],
        );
        if (cats.length > 0) {
          categoryName = cats[0].name;
          categoryMarkup = cats[0].markup_percent;
        }
      }

      // Get global markup
      const [companyRows] = await req.db.query(
        "SELECT default_markup_percent FROM company LIMIT 1",
      );
      const globalMarkup =
        parseFloat(companyRows[0]?.default_markup_percent) || 0;

      // Resolve effective markup
      const productOverride =
        markup_percent != null && markup_percent !== ""
          ? parseFloat(markup_percent)
          : null;
      const effectiveMarkup =
        productOverride != null
          ? productOverride
          : categoryMarkup != null
            ? parseFloat(categoryMarkup)
            : globalMarkup;

      // Determine if SP is manual
      const isManual =
        markup_is_manual === true ||
        markup_is_manual === 1 ||
        markup_is_manual === "true";

      // Compute final SP
      const cost = parseFloat(cost_price) || 0;
      const finalSP = isManual
        ? parseFloat(selling_price) || 0
        : parseFloat((cost * (1 + effectiveMarkup / 100)).toFixed(2));

      await req.db.query(
        `UPDATE products SET 
                name = ?, sku = ?, category_id = ?, category_name = ?, unit_id = ?,barcode = ?,
                cost_price = ?, selling_price = ?, stock_quantity = ?, min_stock_level = ?,
                is_vat_exempt = ?, is_active = 1, markup_percent = ?, markup_is_manual = ?
             WHERE id = ?`,
        [
          name,
          sku,
          category_id || null,
          categoryName,
          unit_id || null,
          barcode || null,
          cost,
          finalSP,
          stock_quantity,
          min_stock_level,
          is_vat_exempt ? 1 : 0,
          productOverride,
          isManual ? 1 : 0,
          req.params.id,
        ],
      );

      res.json({
        message: "Product updated successfully",
        selling_price: finalSP,
        markup_percent: productOverride,
        markup_is_manual: isManual ? 1 : 0,
      });
    } catch (error) {
      console.error("Error updating product:", error);
      res.status(500).json({ error: "Server error" });
    }
  },
);

app.post(
  "/api/products/recalculate-prices",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    if (req.user.role !== "admin" && req.user.role !== "manager") {
      return res.status(403).json({ error: "Access denied" });
    }

    try {
      const [companyRows] = await req.db.query(
        "SELECT default_markup_percent FROM company LIMIT 1",
      );
      const globalMarkup =
        parseFloat(companyRows[0]?.default_markup_percent) || 0;

      // Get all auto products (markup_is_manual = 0)
      const [products] = await req.db.query(`
            SELECT 
                p.id, p.cost_price, p.markup_percent,
                c.markup_percent as category_markup
            FROM products p
            LEFT JOIN categories c ON p.category_id = c.id
            WHERE p.is_active = 1 AND p.markup_is_manual = 0
        `);

      let updated = 0;
      for (const p of products) {
        const effectiveMarkup =
          p.markup_percent != null
            ? parseFloat(p.markup_percent)
            : p.category_markup != null
              ? parseFloat(p.category_markup)
              : globalMarkup;

        const cost = parseFloat(p.cost_price) || 0;
        const newSP = parseFloat(
          (cost * (1 + effectiveMarkup / 100)).toFixed(2),
        );

        await req.db.query(
          "UPDATE products SET selling_price = ? WHERE id = ?",
          [newSP, p.id],
        );
        updated++;
      }

      res.json({
        message: `Recalculated ${updated} products`,
        updated,
      });
    } catch (error) {
      console.error("Error recalculating prices:", error);
      res.status(500).json({ error: "Server error" });
    }
  },
);

app.patch(
  "/api/products/:id/stock",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    console.log("🔴 BACKEND STOCK UPDATE:", req.params.id, req.body);
    try {
      const { quantity, mode } = req.body;

      // Get current stock
      const [current] = await req.db.query(
        "SELECT stock_quantity FROM products WHERE id = ?",
        [req.params.id],
      );
      const currentStock = parseFloat(current[0]?.stock_quantity) || 0;

      let newStock;
      if (mode === "set") {
        // Set to exact quantity
        newStock = quantity;
      } else {
        // Add (default behavior)
        newStock = currentStock + quantity;
      }

      // Update the product
      await req.db.query(
        "UPDATE products SET stock_quantity = ? WHERE id = ?",
        [newStock, req.params.id],
      );

      res.json({
        message: "Stock updated successfully",
        previous: currentStock,
        new: newStock,
      });
    } catch (error) {
      console.error("Error updating stock:", error);
      res.status(500).json({ error: "Server error" });
    }
  },
);

app.delete(
  "/api/products/:id",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    try {
      await req.db.query("UPDATE products SET is_active = 0 WHERE id = ?", [
        req.params.id,
      ]);
      res.json({ message: "Product deleted successfully" });
    } catch (error) {
      console.error("Error deleting product:", error);
      res.status(500).json({ error: "Server error" });
    }
  },
);

// Set stock directly (for opening balances)
app.patch(
  "/api/products/:id/set-stock",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    try {
      const { quantity } = req.body;
      console.log("🔴 SET STOCK START:", req.params.id, "to", quantity);

      // Check current stock before update
      const [before] = await req.db.query(
        "SELECT stock_quantity FROM products WHERE id = ?",
        [req.params.id],
      );
      console.log("🔴 BEFORE:", before[0]?.stock_quantity);

      await req.db.query(
        "UPDATE products SET stock_quantity = ? WHERE id = ?",
        [quantity, req.params.id],
      );

      // Check after update
      const [after] = await req.db.query(
        "SELECT stock_quantity FROM products WHERE id = ?",
        [req.params.id],
      );
      console.log("🔴 AFTER:", after[0]?.stock_quantity);

      res.json({ message: "Stock set successfully", stock: quantity });
    } catch (error) {
      console.error("Error setting stock:", error);
      res.status(500).json({ error: "Server error" });
    }
  },
);
// ==================== DASHBOARD ENDPOINTS ====================

app.get(
  "/api/dashboard",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    try {
      const today = new Date().toISOString().split("T")[0];
      const weekAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000)
        .toISOString()
        .split("T")[0];
      const monthAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000)
        .toISOString()
        .split("T")[0];

      const [todaySales] = await req.db.query(
        "SELECT COALESCE(SUM(total), 0) as total, COUNT(*) as count FROM sales WHERE sale_date::date = ?",
        [today],
      );
      const [weekSales] = await req.db.query(
        "SELECT COALESCE(SUM(total), 0) as total FROM sales WHERE sale_date >= ?",
        [weekAgo],
      );
      const [monthSales] = await req.db.query(
        "SELECT COALESCE(SUM(total), 0) as total FROM sales WHERE sale_date >= ?",
        [monthAgo],
      );
      const [lowStock] = await req.db.query(
        "SELECT COUNT(*) as count FROM products WHERE stock_quantity < min_stock_level AND stock_quantity > 0",
      );
      const [outOfStock] = await req.db.query(
        "SELECT COUNT(*) as count FROM products WHERE stock_quantity <= 0",
      );
      const [totalCustomers] = await req.db.query(
        "SELECT COUNT(*) as count FROM customers WHERE is_active = 1",
      );

      const [categories] = await req.db.query(
        `
            SELECT p.category_name, SUM(si.quantity) as quantity, SUM(si.total) as revenue
            FROM sale_items si
            JOIN products p ON si.product_id = p.id
            JOIN sales s ON si.sale_id = s.id
            WHERE s.sale_date >= ?
            GROUP BY p.category_name
        `,
        [weekAgo],
      );

      const [last7Days] = await req.db.query(`
            SELECT TO_CHAR(dates.date, 'YYYY-MM-DD') as date,
                   COALESCE(SUM(s.total), 0) as total,
                   COUNT(s.id) as transactions
            FROM (SELECT (CURRENT_DATE - (n || ' days')::interval)::date as date
                  FROM (SELECT 0 as n UNION SELECT 1 UNION SELECT 2 UNION SELECT 3 
                        UNION SELECT 4 UNION SELECT 5 UNION SELECT 6) numbers) dates
            LEFT JOIN sales s ON s.sale_date::date = dates.date
            GROUP BY dates.date ORDER BY dates.date
        `);

      const [topProducts] = await req.db.query(
        `
            SELECT p.name, p.sku, SUM(si.quantity) as quantity_sold, SUM(si.total) as revenue
            FROM sale_items si
            JOIN products p ON si.product_id = p.id
            JOIN sales s ON si.sale_id = s.id
            WHERE s.sale_date >= ?
            GROUP BY p.id, p.name, p.sku ORDER BY revenue DESC LIMIT 5
        `,
        [weekAgo],
      );

      res.json({
        totalSalesToday: todaySales[0].total,
        totalTransactionsToday: todaySales[0].count,
        totalSalesThisWeek: weekSales[0].total,
        totalSalesThisMonth: monthSales[0].total,
        averageTicketToday:
          todaySales[0].count > 0
            ? todaySales[0].total / todaySales[0].count
            : 0,
        lowStockCount: lowStock[0].count,
        outOfStockCount: outOfStock[0].count,
        totalCustomers: totalCustomers[0].count,
        salesByCategory: categories,
        last7DaysSales: last7Days,
        topProducts: topProducts,
      });
    } catch (error) {
      console.error("Error fetching dashboard:", error);
      res.status(500).json({ error: "Server error" });
    }
  },
);


// ==================== SALES ENDPOINTS ====================

app.post(
  "/api/sales",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    try {
      const {
        cart,
        subtotal,
        tax,
        total,
        paymentMethod,
        paidAmount,
        cashierId,
        customerId,
        discountType,
        discountValue,
        discountPin,
      } = req.body;

      const invoiceNumber = `INV-${Date.now()}`;

      // ===== DISCOUNT HANDLING =====
      let discountAmount = 0;
      let discountPinId = null;

      const hasDiscount =
        discountType && discountValue && parseFloat(discountValue) > 0;

      if (hasDiscount) {
        if (!discountPin) {
          return res.status(400).json({ error: "Discount PIN required" });
        }

        const [pinRows] = await req.db.query(
          "SELECT * FROM discount_pins WHERE pin = ? FOR UPDATE",
          [discountPin],
        );

        if (pinRows.length === 0) {
          return res.status(400).json({ error: "Invalid discount PIN" });
        }

        const pinRow = pinRows[0];

        if (pinRow.used_at) {
          return res.status(400).json({ error: "Discount PIN already used" });
        }

        const requestedValue = parseFloat(discountValue);
        if (discountType === "percent") {
          discountAmount = parseFloat(
            (subtotal * (requestedValue / 100)).toFixed(2),
          );
        } else {
          discountAmount = parseFloat(requestedValue.toFixed(2));
        }

        const pinMaxValue = parseFloat(pinRow.max_discount_value);
        let pinMaxAmount;
        if (pinRow.max_discount_type === "percent") {
          pinMaxAmount = parseFloat(
            (subtotal * (pinMaxValue / 100)).toFixed(2),
          );
        } else {
          pinMaxAmount = pinMaxValue;
        }

        if (discountAmount > pinMaxAmount) {
          return res.status(400).json({
            error: `Discount exceeds PIN limit`,
          });
        }

        if (discountAmount > subtotal) {
          return res
            .status(400)
            .json({ error: "Discount cannot exceed subtotal" });
        }

        discountPinId = pinRow.id;
      }

      const finalTotal = parseFloat(
        (subtotal - discountAmount + (tax || 0)).toFixed(2),
      );
      const changeAmount = paidAmount - finalTotal;

      // ===== INSERT SALE =====
      const [saleResult] = await req.db.query(
        `INSERT INTO sales 
             (invoice_number, sale_date, customer_id, subtotal, tax, total, 
              payment_method, paid_amount, change_amount, cashier_id, status,
              discount_type, discount_value, discount_amount, discount_pin_id, tenant_id) 
             VALUES (?, NOW(), ?, ?, ?, ?, ?, ?, ?, ?, 'completed', ?, ?, ?, ?, ?) RETURNING id`,
        [
          invoiceNumber,
          customerId || null,
          subtotal,
          tax || 0,
          finalTotal,
          paymentMethod,
          paidAmount,
          changeAmount > 0 ? changeAmount : 0,
          cashierId,
          hasDiscount ? discountType : null,
          hasDiscount ? parseFloat(discountValue) : null,
          discountAmount,
          discountPinId,
          req.user.tenant_id,
        ],
      );

      const saleId = saleResult[0].id;

      // ===== MARK PIN USED =====
      if (discountPinId) {
        await req.db.query(
          `UPDATE discount_pins 
                 SET used_at = NOW(), used_by = ?, sale_id = ?, discount_applied = ? 
                 WHERE id = ?`,
          [cashierId, saleId, discountAmount, discountPinId],
        );
      }

      // ===== PROCESS CART ITEMS =====
      for (const item of cart) {
        await req.db.query(
          `INSERT INTO sale_items (sale_id, product_id, quantity, unit_price,total, is_vat_exempt, tenant_id) 
                 VALUES (?, ?, ?, ?, ?, ?, ?)`,
          [
            saleId,
            item.product.id,
            item.quantity,
            item.product.sellingPrice,
            item.subtotal,
            item.product.isVatExempt ? 1 : 0,
            req.user.tenant_id,
          ],
        );

        const [currentStock] = await req.db.query(
          "SELECT stock_quantity FROM products WHERE id = ?",
          [item.product.id],
        );
        const balanceBefore = parseFloat(currentStock[0]?.stock_quantity) || 0;

        if (paymentMethod !== "Layaway") {
          await req.db.query(
            "UPDATE products SET stock_quantity = stock_quantity - ? WHERE id = ?",
            [item.quantity, item.product.id],
          );
        }

        const balanceAfter = balanceBefore - item.quantity;

        const [product] = await req.db.query(
          "SELECT name, sku, unit_id FROM products WHERE id = ?",
          [item.product.id],
        );

        let unitSymbol = "";
        if (product[0]?.unit_id) {
          const [unit] = await req.db.query(
            "SELECT symbol FROM units WHERE id = ?",
            [product[0].unit_id],
          );
          unitSymbol = unit[0]?.symbol || "";
        }

        await req.db.query(
          `INSERT INTO stock_movements 
                 (product_id, product_name, sku, date, reference, movement_type, 
                  quantity, balance_before, balance_after, notes, user_id, unit_symbol, invoice_number, tenant_id)
                 VALUES (?, ?, ?, NOW(), ?, 'OUT', ?, ?, ?, ?, ?, ?, ?, ?)`,
          [
            item.product.id,
            product[0]?.name || "",
            product[0]?.sku || "",
            `SALE-${saleId}`,
            item.quantity,
            balanceBefore,
            balanceAfter,
            `Sale #${invoiceNumber}${discountAmount > 0 ? ` (discount: ${discountAmount})` : ""}`,
            cashierId,
            unitSymbol,
            invoiceNumber,
            req.user.tenant_id,
          ],
        );
      }

      // ===== CASH / BANK TRANSACTIONS =====
      const dateStr = new Date().toISOString().slice(0, 19).replace("T", " ");

      if (paymentMethod === "Cash") {
        await req.db.query(
          `INSERT INTO cash_transactions (date, type, amount, category, description, reference, user_id, tenant_id) 
                 VALUES (?, 'cash_in', ?, 'Sales Income', ?, ?, ?, ?)`,
          [
            dateStr,
            finalTotal,
            `Cash sale #${invoiceNumber}`,
            invoiceNumber,
            cashierId,
            req.user.tenant_id,
          ],
        );
      } else if (paymentMethod === "Card" || paymentMethod === "Transfer") {
        const [accounts] = await req.db.query(
          "SELECT id FROM bank_accounts WHERE is_active = 1 LIMIT 1",
        );
        const bankAccountId = accounts.length > 0 ? accounts[0].id : null;

        await req.db.query(
          `INSERT INTO bank_transactions (date, type, amount, account_name, bank_name, description, reference, user_id, bank_account_id, tenant_id) 
                 VALUES (?, 'deposit', ?, 'Sales Account', ?, ?, ?, ?, ?, ?)`,
          [
            dateStr,
            finalTotal,
            paymentMethod === "Card" ? "Card Payments" : "Transfer Payments",
            `${paymentMethod} sale #${invoiceNumber}`,
            invoiceNumber,
            cashierId,
            bankAccountId,
            req.user.tenant_id,
          ],
        );

        if (bankAccountId) {
          await req.db.query(
            "UPDATE bank_accounts SET current_balance = current_balance + ? WHERE id = ?",
            [finalTotal, bankAccountId],
          );
        }
      }

      res.json({
        invoiceNumber,
        change: changeAmount > 0 ? changeAmount : 0,
        saleId,
        discountAmount,
        finalTotal,
      });
    } catch (error) {
      console.error("ERROR SAVING SALE:", error);
      res.status(500).json({ error: error.message });
    }
  },
);


app.get(
  "/api/sales/:id",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    try {
      const [sales] = await req.db.query("SELECT * FROM sales WHERE id = ?", [
        req.params.id,
      ]);
      if (sales.length === 0)
        return res.status(404).json({ error: "Sale not found" });

      const [items] = await req.db.query(
        `SELECT si.*, p.name as product_name, p.sku, p.category_name 
             FROM sale_items si LEFT JOIN products p ON si.product_id = p.id WHERE si.sale_id = ?`,
        [sales[0].id],
      );

      res.json({ sale: sales[0], items });
    } catch (error) {
      console.error("Error fetching sale detail:", error);
      res.status(500).json({ error: "Server error" });
    }
  },
);

app.get(
  "/api/sales/invoice/:invoiceNumber",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    try {
      const [sales] = await req.db.query(
        "SELECT * FROM sales WHERE invoice_number = ?",
        [req.params.invoiceNumber],
      );
      if (sales.length === 0)
        return res.status(404).json({ error: "Sale not found" });

      const [items] = await req.db.query(
        `SELECT si.*, p.name as product_name, p.sku, p.category_name 
             FROM sale_items si LEFT JOIN products p ON si.product_id = p.id WHERE si.sale_id = ?`,
        [sales[0].id],
      );

      res.json({ ...sales[0], items });
    } catch (error) {
      console.error("Error fetching sale by invoice:", error);
      res.status(500).json({ error: "Server error" });
    }
  },
);

// Get all sales (with optional date range filter)
app.get("/api/sales", authenticateToken, setTenantContext, async (req, res) => {
  try {
    const { start, end } = req.query;
    let salesQuery = "SELECT * FROM sales";
    let params = [];

    if (start && end) {
      salesQuery += " WHERE sale_date BETWEEN ? AND ?";
      params = [start, end];
    }
    salesQuery += " ORDER BY sale_date DESC";

    const [sales] = await req.db.query(salesQuery, params);

    // Get items for each sale
    const salesWithItems = [];
    for (const sale of sales) {
      const [items] = await req.db.query(
        `SELECT si.*, p.name as product_name, p.sku, p.category_name 
                 FROM sale_items si 
                 LEFT JOIN products p ON si.product_id = p.id 
                 WHERE si.sale_id = ?`,
        [sale.id],
      );

      salesWithItems.push({
        ...sale,
        items: items.map((item) => ({
          ...item,
          unit_price: parseFloat(item.unit_price),
          total: parseFloat(item.total),
        })),
      });
    }

    res.json(salesWithItems);
  } catch (error) {
    console.error("Error fetching sales:", error);
    res.status(500).json({ error: "Server error" });
  }
});

// ==================== CATEGORIES ENDPOINTS ====================

app.get(
  "/api/categories",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    try {
      const [categories] = await req.db.query(
        "SELECT * FROM categories ORDER BY name",
      );
      res.json(categories);
    } catch (error) {
      console.error("Error fetching categories:", error);
      res.status(500).json({ error: "Server error" });
    }
  },
);

app.post(
  "/api/categories",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    try {
      const { name, description, isVatExempt, markupPercent } = req.body;
      const markup =
        markupPercent != null && markupPercent !== ""
          ? parseFloat(markupPercent)
          : null;
      const [result] = await req.db.query(
        "INSERT INTO categories (name, description, is_vat_exempt, markup_percent, tenant_id) VALUES (?, ?, ?, ?, ?) RETURNING id",
        [name, description, isVatExempt ? 1 : 0, markup, req.user.tenant_id],
      );
      res.json({ id: result[0].id, message: "Category added successfully" });
    } catch (error) {
      console.error("Error adding category:", error);
      res.status(500).json({ error: "Server error" });
    }
  },
);

app.put(
  "/api/categories/:id",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    try {
      const { name, description, isVatExempt, markupPercent } = req.body;
      const markup =
        markupPercent != null && markupPercent !== ""
          ? parseFloat(markupPercent)
          : null;

      await req.db.query(
        `UPDATE categories SET 
                name = ?, 
                description = ?, 
                is_vat_exempt = ?, 
                markup_percent = ?
             WHERE id = ?`,
        [name, description, isVatExempt ? 1 : 0, markup, req.params.id],
      );

      res.json({ message: "Category updated successfully" });
    } catch (error) {
      console.error("Error updating category:", error);
      res.status(500).json({ error: "Server error" });
    }
  },
);

// ==================== DISCOUNT PIN ENDPOINTS ====================

// Generate a batch of discount PINs
app.post('/api/discount-pins/generate', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin' && req.user.role !== 'manager') {
        return res.status(403).json({ error: 'Access denied' });
    }

    try {
        const { count, maxDiscountType, maxDiscountValue, notes } = req.body;

        const numPins = parseInt(count) || 1;
        if (numPins < 1 || numPins > 100) {
            return res.status(400).json({ error: 'Count must be between 1 and 100' });
        }
        if (maxDiscountType !== 'percent' && maxDiscountType !== 'amount') {
            return res.status(400).json({ error: 'Invalid discount type' });
        }
        const maxValue = parseFloat(maxDiscountValue);
        if (!maxValue || maxValue <= 0) {
            return res.status(400).json({ error: 'Max discount value must be positive' });
        }
        if (maxDiscountType === 'percent' && maxValue > 100) {
            return res.status(400).json({ error: 'Percent discount cannot exceed 100' });
        }

        const generated = [];
        for (let i = 0; i < numPins; i++) {
            let pin;
            let attempts = 0;
            // Retry in case of collision
            do {
                pin = Math.floor(100000 + Math.random() * 900000).toString();
                const [existing] = await pool.query(
                    'SELECT id FROM discount_pins WHERE pin = ?',
                    [pin]
                );
                if (existing.length === 0) break;
                attempts++;
            } while (attempts < 10);

            if (attempts >= 10) {
                return res.status(500).json({ error: 'Could not generate unique PINs' });
            }

            const [result] = await pool.query(
                `INSERT INTO discount_pins 
                 (pin, max_discount_type, max_discount_value, notes, created_by) 
                 VALUES (?, ?, ?, ?, ?) RETURNING id`,
                [pin, maxDiscountType, maxValue, notes || null, req.user.id]
            );

            generated.push({
                id: result[0].id,
                pin,
                max_discount_type: maxDiscountType,
                max_discount_value: maxValue,
                notes: notes || null
            });
        }

        res.json({ pins: generated, count: generated.length });
    } catch (error) {
        console.error('Error generating discount PINs:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Validate a discount PIN
app.post('/api/discount-pins/validate', authenticateToken, async (req, res) => {
    try {
        const { pin, discountType, discountValue } = req.body;

        if (!pin) {
            return res.status(400).json({ error: 'PIN is required' });
        }

        const [rows] = await pool.query(
            'SELECT * FROM discount_pins WHERE pin = ?',
            [pin]
        );

        if (rows.length === 0) {
            return res.status(404).json({ error: 'Invalid PIN' });
        }

        const pinRow = rows[0];

        if (pinRow.used_at) {
            return res.status(400).json({ error: 'PIN already used' });
        }

        // Validate discount against PIN's max
        const requestedValue = parseFloat(discountValue);
        if (!requestedValue || requestedValue <= 0) {
            return res.status(400).json({ error: 'Invalid discount value' });
        }

        if (discountType !== pinRow.max_discount_type) {
            return res.status(400).json({ 
                error: `PIN allows ${pinRow.max_discount_type} discount only` 
            });
        }

        const maxValue = parseFloat(pinRow.max_discount_value);
        if (requestedValue > maxValue) {
            return res.status(400).json({ 
                error: `Discount exceeds PIN limit of ${maxValue}${discountType === 'percent' ? '%' : ''}` 
            });
        }

        res.json({
            valid: true,
            pin_id: pinRow.id,
            max_discount_type: pinRow.max_discount_type,
            max_discount_value: maxValue
        });
    } catch (error) {
        console.error('Error validating discount PIN:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

app.get('/api/discount-pins', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin' && req.user.role !== 'manager') {
        return res.status(403).json({ error: 'Access denied' });
    }

    try {
        const { status, start, end } = req.query;
        let query = `
            SELECT 
                dp.*,
                creator.username AS created_by_username,
                creator.full_name AS created_by_name,
                user_account.username AS used_by_username,
                user_account.full_name AS used_by_name,
                s.invoice_number AS sale_invoice
            FROM discount_pins dp
            LEFT JOIN users creator ON dp.created_by = creator.id
            LEFT JOIN users user_account ON dp.used_by = user_account.id
            LEFT JOIN sales s ON dp.sale_id = s.id
            WHERE 1=1
        `;
        let params = [];

        if (status === 'used') {
            query += ' AND dp.used_at IS NOT NULL';
        } else if (status === 'unused') {
            query += ' AND dp.used_at IS NULL';
        }

        if (start && end) {
            query += ' AND dp.created_at BETWEEN ? AND ?';
            params.push(start, end);
        }

        query += ' ORDER BY dp.created_at DESC';

        const [pins] = await pool.query(query, params);
        res.json(pins);
    } catch (error) {
        console.error('Error fetching discount PINs:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// ==================== USERS ENDPOINTS ====================

app.get("/api/users", authenticateToken, setTenantContext, async (req, res) => {
  try {
    if (req.user.role !== "admin")
      return res.status(403).json({ error: "Accessdenied" });
    const [users] = await req.db.query(
      "SELECT id, username, full_name, role, is_active, last_login, created_at FROM users ORDER BY created_at DESC",
    );
    res.json(users);
  } catch (error) {
    console.error("Error fetching users:", error);
    res.status(500).json({ error: "Server error" });
  }
});


app.get(
  "/api/users/:id",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    try {
      if (
        req.user.role !== "admin" &&
        req.user.id !== parseInt(req.params.id)
      ) {
        return res.status(403).json({ error: "Access denied" });
      }

      const [users] = await req.db.query(
        "SELECT id, username, full_name, role, is_active, last_login, created_at FROM users WHERE id = ?",
        [req.params.id],
      );
      if (users.length === 0) {
        return res.status(404).json({ error: "User not found" });
      }
      res.json(users[0]);
    } catch (error) {
      console.error("Error fetching user:", error);
      res.status(500).json({ error: "Server error" });
    }
  },
);

app.post(
  "/api/users",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    try {
      if (req.user.role !== "admin")
        return res.status(403).json({ error: "Access denied" });
      const { username, password, fullName, role } = req.body;
      const [existing] = await req.db.query(
        "SELECT id FROM users WHERE username = ?",
        [username],
      );
      if (existing.length > 0)
        return res.status(400).json({ error: "Username already exists" });

      const hashedPassword = await bcrypt.hash(password, 10);

      // Look up the role_id for the provided role string
      const [roleRows] = await req.db.query(
        "SELECT id FROM roles WHERE name = ?",
        [role],
      );
      const roleId = roleRows.length > 0 ? roleRows[0].id : null;

      const [result] = await req.db.query(
        "INSERT INTO users (username, password, full_name, role, role_id, tenant_id) VALUES (?, ?, ?, ?, ?, ?) RETURNING id",
        [username, hashedPassword, fullName, role, roleId, req.user.tenant_id],
      );
      res.json({ id: result[0].id, message: "User created successfully" });
    } catch (error) {
      console.error("Error creating user:", error);
      res.status(500).json({ error: "Server error" });
    }
  },
);

app.put(
  "/api/users/:id",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    try {
      if (req.user.role !== "admin") {
        return res.status(403).json({ error: "Access denied" });
      }

      const { fullName, role, isActive } = req.body;

      await req.db.query(
        "UPDATE users SET full_name = ?, role = ?, is_active = ?, updated_at = NOW() WHERE id = ?",
        [fullName, role, isActive, req.params.id],
      );

      res.json({ message: "User updated successfully" });
    } catch (error) {
      console.error("Error updating user:", error);
      res.status(500).json({ error: "Server error" });
    }
  },
);

app.patch(
  "/api/users/:id/password",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    try {
      if (
        req.user.role !== "admin" &&
        req.user.id !== parseInt(req.params.id)
      ) {
        return res.status(403).json({ error: "Access denied" });
      }

      const { password } = req.body;
      const hashedPassword = await bcrypt.hash(password, 10);

      await req.db.query(
        "UPDATE users SET password = ?, updated_at = NOW() WHERE id = ?",
        [hashedPassword, req.params.id],
      );

      res.json({ message: "Password updated successfully" });
    } catch (error) {
      console.error("Error updating password:", error);
      res.status(500).json({ error: "Server error" });
    }
  },
);

app.patch(
  "/api/users/:id/toggle",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    try {
      if (req.user.role !== "admin")
        return res.status(403).json({ error: "Accessdenied" });
      const [user] = await req.db.query(
        "SELECT is_active FROM users WHERE id = ?",
        [req.params.id],
      );
      if (user.length === 0)
        return res.status(404).json({ error: "User not found" });
      const newStatus = user[0].is_active ? 0 : 1;
      await req.db.query("UPDATE users SET is_active = ? WHERE id = ?", [
        newStatus,
        req.params.id,
      ]);
      const [updated] = await req.db.query(
        "SELECT id, username, full_name, role, is_active, last_login, created_at FROM users WHERE id = ?",
        [req.params.id],
      );
      res.json(updated[0]);
    } catch (error) {
      console.error("Error toggling user:", error);
      res.status(500).json({ error: "Server error" });
    }
  },
);

app.delete(
  "/api/users/:id",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    try {
      if (req.user.role !== "admin")
        return res.status(403).json({ error: "Accessdenied" });
      if (parseInt(req.params.id) === req.user.id)
        return res.status(400).json({ error: "Cannot delete yourself" });
      await req.db.query("DELETE FROM users WHERE id = ?", [req.params.id]);
      res.json({ message: "User deleted successfully" });
    } catch (error) {
      console.error("Error deleting user:", error);
      res.status(500).json({ error: "Server error" });
    }
  },
);

// ==================== CASH BOOK ENDPOINTS ====================

app.get(
  "/api/cash-book",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    try {
      const { start, end } = req.query;
      const [transactions] = await req.db.query(
        "SELECT * FROM cash_transactions WHERE date BETWEEN ? AND ? ORDER BY date DESC",
        [start, end],
      );
      res.json(transactions);
    } catch (error) {
      console.error("Error fetching cash transactions:", error);
      res.status(500).json({ error: "Server error" });
    }
  },
);

app.get(
  "/api/cash-book/summary",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    try {
      const { start, end } = req.query;
      const [transactions] = await req.db.query(
        "SELECT * FROM cash_transactions WHERE date BETWEEN ? AND ?",
        [start, end],
      );
      let cashIn = 0,
        cashOut = 0;
      for (const t of transactions) {
        const amt = parseFloat(t.amount) || 0;
        if (t.type === "cash_in") cashIn += amt;
        else cashOut += amt;
      }
      res.json({
        cashIn,
        cashOut,
        netCash: cashIn - cashOut,
        transactionCount: transactions.length,
      });
    } catch (error) {
      console.error("Error fetching cash summary:", error);
      res.status(500).json({ error: "Server error" });
    }
  },
);

app.post(
  "/api/cash-book",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    try {
      const { date, type, amount, category, description, reference, user_id } =
        req.body;
      const [result] = await req.db.query(
        "INSERT INTO cash_transactions (date, type, amount, category, description, reference, user_id, tenant_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?) RETURNING id",
        [
          date,
          type,
          amount,
          category,
          description,
          reference,
          user_id,
          req.user.tenant_id,
        ],
      );
      res.json({ id: result[0].id, message: "Transaction added successfully" });
    } catch (error) {
      console.error("Error adding cash transaction:", error);
      res.status(500).json({ error: "Server error" });
    }
  },
);

app.delete(
  "/api/cash-book/:id",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    try {
      await req.db.query("DELETE FROM cash_transactions WHERE id = ?", [
        req.params.id,
      ]);
      res.json({ message: "Transaction deleted successfully" });
    } catch (error) {
      console.error("Error deleting cash transaction:", error);
      res.status(500).json({ error: "Server error" });
    }
  },
);

// ==================== BANK BOOK ENDPOINTS ====================

app.get(
  "/api/bank-book",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    try {
      const { start, end } = req.query;
      const [transactions] = await req.db.query(
        "SELECT * FROM bank_transactions WHERE date BETWEEN ? AND ? ORDER BY date DESC",
        [start, end],
      );
      res.json(transactions);
    } catch (error) {
      console.error("Error fetching bank transactions:", error);
      res.status(500).json({ error: "Server error" });
    }
  },
);

app.post(
  "/api/bank-book",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    try {
      const {
        date,
        type,
        amount,
        accountName,
        bankName,
        description,
        reference,
        userId,
      } = req.body;
      const [result] = await req.db.query(
        "INSERT INTO bank_transactions (date, type, amount, account_name, bank_name, description, reference, user_id, tenant_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id",
        [
          date,
          type,
          amount,
          accountName,
          bankName,
          description,
          reference,
          userId,
          req.user.tenant_id,
        ],
      );
      res.json({ id: result[0].id, message: "Transaction added successfully" });
    } catch (error) {
      console.error("Error adding bank transaction:", error);
      res.status(500).json({ error: "Server error" });
    }
  },
);

app.delete(
  "/api/bank-book/:id",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    try {
      await req.db.query("DELETE FROM bank_transactions WHERE id = ?", [
        req.params.id,
      ]);
      res.json({ message: "Transaction deleted successfully" });
    } catch (error) {
      console.error("Error deleting bank transaction:", error);
      res.status(500).json({ error: "Server error" });
    }
  },
);

// ==================== STATES ENDPOINTS ====================

app.get('/api/states', authenticateToken, async (req, res) => {
    try {
        const [states] = await pool.query('SELECT * FROM states WHERE is_active = 1 ORDER BY name');
        res.json(states);
    } catch (error) {
        console.error('Error fetching states:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

app.get('/api/states/:id', authenticateToken, async (req, res) => {
    try {
        const [states] = await pool.query('SELECT * FROM states WHERE id = ?', [req.params.id]);
        if (states.length === 0) return res.status(404).json({ error: 'State not found' });
        res.json(states[0]);
    } catch (error) {
        console.error('Error fetching state:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// ==================== COMPANY ENDPOINTS ====================


// Configure multer for logo upload
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        const uploadDir = 'uploads/logos';
        if (!fs.existsSync(uploadDir)) {
            fs.mkdirSync(uploadDir, { recursive: true });
        }
        cb(null, uploadDir);
    },
    filename: function (req, file, cb) {
        const ext = path.extname(file.originalname);
        const filename = `company_logo_${Date.now()}${ext}`;
        cb(null, filename);
    }
});

const upload = multer({
    storage: storage,
    limits: { fileSize: 2 * 1024 * 1024 }, // 2MB limit
    fileFilter: function (req, file, cb) {
        console.log('=== FILE UPLOAD DEBUG ===');
        console.log('Original filename:', file.originalname);
        console.log('Mimetype:', file.mimetype);
        console.log('Extension:', path.extname(file.originalname).toLowerCase());
        
        // Check if extension is valid
        const allowedExtensions = /\.(jpeg|jpg|png|gif|bmp|webp)$/i;
        const extValid = allowedExtensions.test(file.originalname);
        
        // Check if mimetype is valid (or is octet-stream which might be an image)
        const allowedMimetypes = /image\/(jpeg|jpg|png|gif|bmp|webp)/i;
        const mimeValid = allowedMimetypes.test(file.mimetype);
        
        // Accept if EITHER extension OR mimetype is valid
        // Also accept application/octet-stream if it has a valid image extension
        const isValid = extValid || mimeValid;
        
        console.log('Extension valid?', extValid);
        console.log('Mimetype valid?', mimeValid);
        console.log('✅ Accepted?', isValid);
        
        if (isValid) {
            console.log('✅ File accepted');
            return cb(null, true);
        }
        console.log('❌ File rejected');
        cb(new Error('Only image files are allowed (jpeg, jpg, png, gif)'));
    }
});

// Create uploads directory if it doesn't exist
const uploadDir = 'uploads/logos';
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
    console.log('Created uploads directory');
}

// GET company
app.get(
  "/api/company",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    try {
      const [company] = await req.db.query("SELECT * FROM company LIMIT 1");
      if (company.length === 0) return res.json({});
      console.log("Company data:", company[0]);
      res.json(company[0]);
    } catch (error) {
      console.error("Error fetching company:", error);
      res.status(500).json({ error: "Server error" });
    }
  },
);

// POST/PUT company
app.post(
  "/api/company",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    try {
      const {
        name,
        address,
        phone,
        email,
        taxId,
        stateId,
        autoCashBook,
        autoBankBook,
        defaultMarkupPercent,
        vatEnabled,
        vatRate,
      } = req.body;
      const [existing] = await req.db.query("SELECT id FROM company LIMIT 1");

      const markup =
        defaultMarkupPercent != null ? parseFloat(defaultMarkupPercent) : 0;

      if (existing.length > 0) {
        await req.db.query(
          `UPDATE company SET 
                    name = ?, address = ?, phone = ?, email = ?, 
                    tax_id = ?, state_id = ?, auto_cash_book = ?, 
                    auto_bank_book = ?, default_markup_percent = ?,
                    vat_enabled = ?, vat_rate = ?, updated_at = NOW() 
                 WHERE id = ?`,
          [
            name,
            address,
            phone,
            email,
            taxId,
            stateId,
            autoCashBook ? 1 : 0,
            autoBankBook ? 1 : 0,
            markup,
            vatEnabled ? 1 : 0,
            vatRate != null ? parseFloat(vatRate) : 0,
            existing[0].id,
          ],
        );
        res.json({
          id: existing[0].id,
          message: "Company updated successfully",
        });
      } else {
        const [result] = await req.db.query(
          `INSERT INTO company 
                 (name, address, phone, email, tax_id, state_id, auto_cash_book, auto_bank_book, default_markup_percent, vat_enabled, vat_rate, created_at, updated_at, tenant_id) 
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW(), ?) RETURNING id`,
          [
            name,
            address,
            phone,
            email,
            taxId,
            stateId,
            autoCashBook ? 1 : 0,
            autoBankBook ? 1 : 0,
            markup,
            vatEnabled ? 1 : 0,
            vatRate != null ? parseFloat(vatRate) : 0,
            req.user.tenant_id,
          ],
        );
        res.json({ id: result[0].id, message: "Company created successfully" });
      }
    } catch (error) {
      console.error("Error saving company:", error);
      res.status(500).json({ error: "Server error" });
    }
  },
);

// POST upload company logo
app.post(
  "/api/company/logo",
  authenticateToken,
  setTenantContext,
  upload.single("logo"),
  async (req, res) => {
    try {
      console.log("=== LOGO UPLOAD ===");
      console.log("File received:", req.file);

      if (!req.file) {
        console.log("No file uploaded");
        return res.status(400).json({ error: "No file uploaded" });
      }

      const logoPath = `/uploads/logos/${req.file.filename}`;
      console.log("Logo path:", logoPath);

      // Check if company exists
      const [existing] = await req.db.query(
        "SELECT id, logo_path FROM company LIMIT 1",
      );
      console.log("Existing company:", existing.length > 0 ? "Yes" : "No");

      if (existing.length > 0) {
        // Delete old logo if exists
        if (existing[0].logo_path) {
          const oldPath = path.join(__dirname, "..", existing[0].logo_path);
          console.log("Old logo path:", oldPath);
          if (fs.existsSync(oldPath)) {
            fs.unlinkSync(oldPath);
            console.log("Deleted old logo");
          }
        }

        await req.db.query(
          "UPDATE company SET logo_path = ?, updated_at = NOW() WHERE id = ?",
          [logoPath, existing[0].id],
        );
        console.log("Updated company with new logo");
      } else {
        // Create company entry first if it doesn't exist
        console.log("Creating new company entry");
        const [result] = await req.db.query(
          `INSERT INTO company (name, logo_path, created_at, updated_at, tenant_id) 
                 VALUES ('Default Company', ?, NOW(), NOW(), ?) RETURNING id`,
          [logoPath, req.user.tenant_id],
        );
        console.log("Created company with ID:", result[0].id);
      }

      res.json({ logoPath, message: "Logo uploaded successfully" });
    } catch (error) {
      console.error("Error uploading logo:", error);
      console.error("Error details:", error.message);
      res.status(500).json({ error: error.message });
    }
  },
);

// DELETE company logo
app.delete(
  "/api/company/logo",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    try {
      const [existing] = await req.db.query(
        "SELECT id, logo_path FROM company LIMIT 1",
      );

      if (existing.length > 0 && existing[0].logo_path) {
        // Delete the file
        const oldPath = path.join(__dirname, existing[0].logo_path);
        if (fs.existsSync(oldPath)) {
          fs.unlinkSync(oldPath);
        }

        await req.db.query(
          "UPDATE company SET logo_path = NULL, updated_at = NOW() WHERE id = ?",
          [existing[0].id],
        );
      }

      res.json({ message: "Logo deleted successfully" });
    } catch (error) {
      console.error("Error deleting logo:", error);
      res.status(500).json({ error: "Server error" });
    }
  },
);
// PUT update company
app.put(
  "/api/company",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    try {
      const {
        id,
        name,
        address,
        phone,
        email,
        taxId,
        stateId,
        autoCashBook,
        autoBankBook,
        defaultMarkupPercent,
        vatEnabled,
        vatRate,
      } = req.body;

      const [existing] = await req.db.query(
        "SELECT id FROM company WHERE id = ?",
        [id],
      );
      if (existing.length === 0) {
        return res.status(404).json({ error: "Company not found" });
      }

      const markup =
        defaultMarkupPercent != null ? parseFloat(defaultMarkupPercent) : 0;

      await req.db.query(
        `UPDATE company SET 
                name = ?, address = ?, phone = ?, email = ?, 
                tax_id = ?, state_id = ?, auto_cash_book = ?, 
                auto_bank_book = ?, default_markup_percent = ?,
                vat_enabled = ?, vat_rate = ?, updated_at = NOW() 
             WHERE id = ?`,
        [
          name,
          address,
          phone,
          email,
          taxId,
          stateId,
          autoCashBook ? 1 : 0,
          autoBankBook ? 1 : 0,
          markup,
          vatEnabled ? 1 : 0,
          vatRate != null ? parseFloat(vatRate) : 0,
          id,
        ],
      );

      res.json({ id: id, message: "Company updated successfully" });
    } catch (error) {
      console.error("Error updating company:", error);
      res.status(500).json({ error: "Server error" });
    }
  },
);


// ==================== EXPENSES ENDPOINTS ====================

app.get(
  "/api/expenses",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    try {
      const { start, end } = req.query;
      let query = "SELECT * FROM expenses";
      let params = [];
      if (start && end) {
        query += " WHERE date BETWEEN ? AND ?";
        params = [start, end];
      }
      query += " ORDER BY date DESC";
      const [expenses] = await req.db.query(query, params);
      res.json(expenses);
    } catch (error) {
      console.error("Error fetching expenses:", error);
      res.status(500).json({ error: "Server error" });
    }
  },
);

app.post(
  "/api/expenses",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    try {
      const {
        date,
        amount,
        category,
        description,
        reference,
        notes,
        userId,
        vendor,
      } = req.body;
      const paymentMethod = req.body.paymentMethod || "cash";

      console.log("=== ADDING EXPENSE ===");
      console.log("paymentMethod:", paymentMethod);
      console.log("amount:", amount);
      console.log("category:", category);

      const [result] = await req.db.query(
        `INSERT INTO expenses 
             (date, amount, category, description, payment_method, reference, notes, user_id, vendor, tenant_id) 
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id`,
        [
          date,
          amount,
          category,
          description,
          paymentMethod,
          reference,
          notes,
          userId,
          vendor,
          req.user.tenant_id,
        ],
      );

      // Record in cash book or bank book based on payment method
      if (paymentMethod === "cash") {
        await req.db.query(
          `INSERT INTO cash_transactions 
                (date, type, amount, category, description, reference, user_id, created_at, tenant_id) 
                VALUES (?, 'cash_out', ?, ?, ?, ?, ?, NOW(), ?)`,
          [
            date,
            amount,
            category,
            description,
            reference,
            userId,
            req.user.tenant_id,
          ],
        );
        console.log("✅ Cash transaction recorded");
      } else if (
        paymentMethod === "card" ||
        paymentMethod === "transfer" ||
        paymentMethod === "bank"
      ) {
        // Get the first active bank account
        const [accounts] = await req.db.query(
          "SELECT id FROM bank_accounts WHERE is_active = 1 LIMIT 1",
        );
        const bankAccountId = accounts.length > 0 ? accounts[0].id : null;

        await req.db.query(
          `INSERT INTO bank_transactions 
                 (date, type, amount, account_name, bank_name, description, reference, user_id, bank_account_id, tenant_id) 
                 VALUES (?, 'withdrawal', ?, 'Expense Account', ?, ?, ?, ?, ?, ?)`,
          [
            date,
            amount,
            paymentMethod === "card" ? "Card Payment" : "Bank Transfer",
            description,
            reference,
            userId,
            bankAccountId,
            req.user.tenant_id,
          ],
        );

        if (bankAccountId) {
          await req.db.query(
            "UPDATE bank_accounts SET current_balance = current_balance - ? WHERE id = ?",
            [amount, bankAccountId],
          );
          console.log(`✅ Bank account balance updated: -${amount}`);
        }
        console.log("✅ Bank transaction recorded");
      }

      res.json({ id: result[0].id, message: "Expense added successfully" });
    } catch (error) {
      console.error("Error adding expense:", error);
      res.status(500).json({ error: "Server error" });
    }
  },
);

app.delete(
  "/api/expenses/:id",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    try {
      await req.db.query("DELETE FROM expenses WHERE id = ?", [req.params.id]);
      res.json({ message: "Expense deleted successfully" });
    } catch (error) {
      console.error("Error deleting expense:", error);
      res.status(500).json({ error: "Server error" });
    }
  },
);

// ==================== SALES RETURNS ENDPOINTS ====================

app.get(
  "/api/sales-returns/items/:invoiceNumber",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    try {
      const { invoiceNumber } = req.params;
      console.log("=== GET ITEMS FOR RETURN ===");
      console.log("Invoice Number:", invoiceNumber);

      const [sales] = await req.db.query(
        "SELECT id FROM sales WHERE invoice_number= ?",
        [invoiceNumber],
      );
      if (sales.length === 0)
        return res.status(404).json({ error: "Sale not found" });

      const saleId = sales[0].id;

      // Nigeria VAT rate is 7.5%
      const VAT_RATE = 0.075;

      const [items] = await req.db.query(
        `
            SELECT 
                si.id as sale_item_id, 
                si.product_id, 
                p.name as product_name, 
                p.sku, 
                p.category_name,
                si.quantity as quantity_sold, 
                -- Store ex-VAT price as reference
                si.unit_price as unit_price_ex_vat,
                si.total as total_ex_vat,
                -- Calculate VAT-inclusive price for display and return
                ROUND(si.unit_price * (1 + ?), 2) as unit_price,
                ROUND(si.total * (1 + ?), 2) as total,
                ROUND(si.unit_price * ?, 2) as vat_amount,
                COALESCE(SUM(ri.quantity), 0) as quantity_returned,
                (si.quantity - COALESCE(SUM(ri.quantity), 0)) as quantity_available
            FROM sale_items si
            JOIN products p ON si.product_id = p.id
            LEFT JOIN return_items ri ON ri.sale_item_id = si.id
            LEFT JOIN sales_returns sr ON ri.return_id = sr.id AND sr.status != 'rejected'
            WHERE si.sale_id = ?
            GROUP BY si.id, si.product_id, p.name, p.sku, p.category_name, si.quantity, si.unit_price, si.total
            HAVING (si.quantity - COALESCE(SUM(ri.quantity), 0)) > 0
        `,
        [VAT_RATE, VAT_RATE, VAT_RATE, saleId],
      );

      console.log("Items found:", items.length);
      if (items.length > 0) {
        console.log("First item - ex-VAT:", items[0].unit_price_ex_vat);
        console.log("First item - with VAT:", items[0].unit_price);
      }

      res.json(items);
    } catch (error) {
      console.error("Error fetching sale items for return:", error);
      res.status(500).json({ error: error.message });
    }
  },
);

app.post(
  "/api/sales-returns",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    try {
      const { saleId, invoiceNumber, items, reason, cashierId } = req.body;
      const returnNumber = `RET-${Date.now()}`;

      console.log("=== CREATE RETURN ===");
      console.log("Items received:", JSON.stringify(items, null, 2));

      // Calculate total refund - unit_price is now VAT-inclusive from GET
      let totalRefund = 0;
      for (const item of items) {
        const qty = parseFloat(item.quantity) || 0;
        const price = parseFloat(item.unit_price) || 0;
        const subtotal = qty * price;
        totalRefund += subtotal;
        console.log(
          `Item: ${item.product_name}, Qty: ${qty}, Price (VAT-inclusive): ${price}, Subtotal: ${subtotal}`,
        );
      }

      console.log("Total Refund (VAT inclusive):", totalRefund);

      const [returnResult] = await req.db.query(
        `INSERT INTO sales_returns (return_number, sale_id, invoice_number, return_date, total_refund, reason, status, cashier_id, tenant_id) 
             VALUES (?, ?, ?, NOW(), ?, ?, 'pending', ?, ?) RETURNING id`,
        [
          returnNumber,
          saleId,
          invoiceNumber,
          totalRefund,
          reason,
          cashierId,
          req.user.tenant_id,
        ],
      );
      const returnId = returnResult[0].id;

      for (const item of items) {
        await req.db.query(
          "INSERT INTO return_items (return_id, sale_item_id, product_id, product_name, sku, quantity, unit_price, total, reason, tenant_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
          [
            returnId,
            item.sale_item_id,
            item.product_id,
            item.product_name,
            item.sku,
            item.quantity,
            item.unit_price,
            item.quantity * item.unit_price,
            item.reason || reason,
            req.user.tenant_id,
          ],
        );
      }

      res.json({
        id: returnId,
        return_number: returnNumber,
        message: "Return created successfully",
      });
    } catch (error) {
      console.error("Error creating return:", error);
      res.status(500).json({ error: "Server error" });
    }
  },
);

app.patch(
  "/api/sales-returns/:id/complete",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    try {
      // Get return details
      const [returns] = await req.db.query(
        "SELECT * FROM sales_returns WHERE id = ?",
        [req.params.id],
      );
      if (returns.length === 0) {
        return res.status(404).json({ error: "Return not found" });
      }
      const returnData = returns[0];

      // Get the original sale
      const [sales] = await req.db.query("SELECT * FROM sales WHERE id = ?", [
        returnData.sale_id,
      ]);
      if (sales.length === 0) {
        return res.status(404).json({ error: "Original sale not found" });
      }
      const sale = sales[0];

      // Get return items
      const [items] = await req.db.query(
        "SELECT * FROM return_items WHERE return_id = ?",
        [req.params.id],
      );

      // Restock items
      for (const item of items) {
        await req.db.query(
          "UPDATE products SET stock_quantity = stock_quantity + ? WHERE id = ?",
          [item.quantity, item.product_id],
        );
      }

      // Reverse payment based on original payment method
      const refundAmount = returnData.total_refund;
      const dateStr = new Date().toISOString().slice(0, 19).replace("T", " ");
      const invoiceNumber = sale.invoice_number;

      if (sale.payment_method === "Cash") {
        // Record refund as cash_out
        await req.db.query(
          `INSERT INTO cash_transactions 
                 (date, type, amount, category, description, reference, user_id, tenant_id) 
                 VALUES (?, 'cash_out', ?, 'Sales Return', ?, ?, ?, ?)`,
          [
            dateStr,
            refundAmount,
            `Refund for sale #${invoiceNumber}`,
            `RET-${returnData.return_number}`,
            req.user.id,
            req.user.tenant_id,
          ],
        );
        console.log("✅ Cash refund recorded");
      } else if (
        sale.payment_method === "Card" ||
        sale.payment_method === "Transfer"
      ) {
        // Get bank account used in the original sale
        const [bankTx] = await req.db.query(
          "SELECT bank_account_id FROM bank_transactions WHERE reference = ? AND type = ? LIMIT 1",
          [invoiceNumber, "deposit"],
        );
        const bankAccountId =
          bankTx.length > 0 ? bankTx[0].bank_account_id : null;

        await req.db.query(
          `INSERT INTO bank_transactions 
                 (date, type, amount, account_name, bank_name, description, reference, user_id, bank_account_id, tenant_id) 
                 VALUES (?, 'withdrawal', ?, 'Refund Account', ?, ?, ?, ?, ?, ?)`,
          [
            dateStr,
            refundAmount,
            "Sales Refund",
            `Refund for sale #${invoiceNumber}`,
            `RET-${returnData.return_number}`,
            req.user.id,
            bankAccountId,
            req.user.tenant_id,
          ],
        );

        if (bankAccountId) {
          await req.db.query(
            "UPDATE bank_accounts SET current_balance = current_balance - ? WHERE id = ?",
            [refundAmount, bankAccountId],
          );
          console.log(`✅ Bank account refund recorded: -${refundAmount}`);
        }
        console.log("✅ Bank refund recorded");
      } else if (sale.payment_method === "Credit") {
        // Reverse credit sale
        await req.db.query(
          "UPDATE customers SET current_balance = current_balance - ? WHERE id = ?",
          [refundAmount, sale.customer_id],
        );
        console.log("✅ Customer credit reversed");
      }

      // Update return status
      await req.db.query("UPDATE sales_returns SET status = ? WHERE id = ?", [
        "completed",
        req.params.id,
      ]);

      res.json({ message: "Return completed successfully" });
    } catch (error) {
      console.error("Error completing return:", error);
      res.status(500).json({ error: "Server error" });
    }
  },
);

app.get(
  "/api/sales-returns",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    try {
      const { start, end } = req.query;
      let query = "SELECT * FROM sales_returns";
      let params = [];
      if (start && end) {
        query += " WHERE return_date BETWEEN ? AND ?";
        params = [start, end];
      }
      query += " ORDER BY return_date DESC";

      const [returns] = await req.db.query(query, params);
      const returnsWithItems = [];
      for (const ret of returns) {
        const [items] = await req.db.query(
          "SELECT * FROM return_items WHERE return_id = ?",
          [ret.id],
        );
        returnsWithItems.push({ ...ret, items });
      }
      res.json(returnsWithItems);
    } catch (error) {
      console.error("Error fetching returns:", error);
      res.status(500).json({ error: "Server error" });
    }
  },
);

app.get(
  "/api/sales-returns/:id",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    try {
      const [returns] = await req.db.query(
        "SELECT * FROM sales_returns WHERE id = ?",
        [req.params.id],
      );
      if (returns.length === 0)
        return res.status(404).json({ error: "Return not found" });
      const [items] = await req.db.query(
        "SELECT * FROM return_items WHERE return_id = ?",
        [req.params.id],
      );
      res.json({ ...returns[0], items });
    } catch (error) {
      console.error("Error fetching return:", error);
      res.status(500).json({ error: "Server error" });
    }
  },
);

// ==================== CREDIT SALES ENDPOINTS ====================

// Get credit sales
app.get(
  "/api/credit-sales",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    try {
      const { status } = req.query;
      let query = `
            SELECT cs.*, c.name as customer_name, u.full_name as approved_by_name
            FROM credit_sales cs
            JOIN customers c ON cs.customer_id = c.id
            LEFT JOIN users u ON cs.approved_by = u.id
        `;
      let params = [];

      if (status) {
        query += " WHERE cs.status = ?";
        params.push(status);
      }

      query += " ORDER BY cs.created_at DESC";

      const [creditSales] = await req.db.query(query, params);
      res.json(creditSales);
    } catch (error) {
      console.error("Error fetching credit sales:", error);
      res.status(500).json({ error: "Server error" });
    }
  },
);

// Create credit sale
app.post(
  "/api/credit-sales",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    try {
      const {
        sale_id,
        customer_id,
        invoice_number,
        total,
        due_date,
        notes,
        items,
      } = req.body;

      console.log("=== CREATING CREDIT SALE ===");
      console.log("Sale ID:", sale_id);
      console.log("Customer ID:", customer_id);
      console.log("Invoice:", invoice_number);
      console.log("Total:", total);
      console.log("Due Date:", due_date);

      const [result] = await req.db.query(
        `INSERT INTO credit_sales 
             (sale_id, customer_id, invoice_number, sale_date, total, due_date, status, notes, items, tenant_id) 
             VALUES (?, ?, ?, NOW(), ?, ?, 'pending', ?, ?, ?) RETURNING id`,
        [
          sale_id,
          customer_id,
          invoice_number,
          total,
          due_date,
          notes,
          JSON.stringify(items),
          req.user.tenant_id,
        ],
      );

      console.log("Credit sale created, ID:", result[0].id);

      await req.db.query(
        "UPDATE customers SET current_balance = current_balance + ? WHERE id = ?",
        [total, customer_id],
      );

      res.json({
        id: result[0].id,
        message: "Credit sale created successfully",
      });
    } catch (error) {
      console.error("Error creating credit sale:", error);
      res.status(500).json({ error: error.message });
    }
  },
);

// Approve credit sale
app.patch(
  "/api/credit-sales/:id/approve",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    try {
      console.log("=== APPROVE CREDIT SALE ===");

      const [creditSale] = await req.db.query(
        "SELECT * FROM credit_sales WHERE id = ?",
        [req.params.id],
      );

      if (creditSale.length === 0) {
        return res.status(404).json({ error: "Credit sale not found" });
      }

      const [sale] = await req.db.query(
        "SELECT cashier_id, invoice_number FROM sales WHERE id = ?",
        [creditSale[0].sale_id],
      );

      await req.db.query(
        `UPDATE credit_sales 
             SET status = 'approved', approved_by = ?, approved_at = NOW() 
             WHERE id = ?`,
        [req.user.id, req.params.id],
      );

      await req.db.query(
        `INSERT INTO notifications (user_id, title, message, type, reference_id, tenant_id) 
             VALUES (?, 'Credit Sale Approved', ?, 'credit_approved', ?, ?)`,
        [
          sale[0].cashier_id,
          `Credit sale ${creditSale[0].invoice_number} has been approved.`,
          creditSale[0].sale_id,
          req.user.tenant_id,
        ],
      );

      res.json({ message: "Credit sale approved. Cashier notified." });
    } catch (error) {
      console.error("Error approving credit sale:", error);
      res.status(500).json({ error: error.message });
    }
  },
);

// Reject credit sale
app.patch(
  "/api/credit-sales/:id/reject",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    try {
      const { reason } = req.body;

      if (req.user.role !== "admin" && req.user.role !== "manager") {
        return res
          .status(403)
          .json({ error: "Only managers and admins can reject credit sales" });
      }

      const [creditSale] = await req.db.query(
        "SELECT * FROM credit_sales WHERE id = ?",
        [req.params.id],
      );

      if (creditSale.length === 0) {
        return res.status(404).json({ error: "Credit sale not found" });
      }

      const [sale] = await req.db.query(
        "SELECT cashier_id, invoice_number FROM sales WHERE id = ?",
        [creditSale[0].sale_id],
      );

      await req.db.query(
        "UPDATE customers SET current_balance = current_balance - ? WHERE id = ?",
        [creditSale[0].total, creditSale[0].customer_id],
      );

      await req.db.query(
        `UPDATE credit_sales 
             SET status = 'rejected', rejection_reason = ?, approved_by = ?, approved_at = NOW() 
             WHERE id = ?`,
        [reason, req.user.id, req.params.id],
      );

      await req.db.query(
        `INSERT INTO notifications (user_id, title, message, type, reference_id, tenant_id) 
             VALUES (?, 'Credit Sale Rejected', ?, 'credit_rejected', ?, ?)`,
        [
          sale[0].cashier_id,
          `Credit sale ${creditSale[0].invoice_number} has been rejected. Reason: ${reason}. Return products to shelf.`,
          creditSale[0].sale_id,
          req.user.tenant_id,
        ],
      );

      res.json({ message: "Credit sale rejected. Cashier notified." });
    } catch (error) {
      console.error("Error rejecting credit sale:", error);
      res.status(500).json({ error: "Server error" });
    }
  },
);

// Complete credit sale (cashier releases products)
app.patch(
  "/api/credit-sales/:id/complete",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    try {
      const [creditSale] = await req.db.query(
        "SELECT * FROM credit_sales WHERE (id = ? OR sale_id = ?) AND status = ?",
        [req.params.id, req.params.id, "approved"],
      );

      if (creditSale.length === 0) {
        return res
          .status(404)
          .json({ error: "Credit sale not found or not approved" });
      }

      const items =
        typeof creditSale[0].items === "string"
          ? JSON.parse(creditSale[0].items)
          : creditSale[0].items;

      for (const item of items) {
        const [currentStock] = await req.db.query(
          "SELECT stock_quantity FROM products WHERE id = ?",
          [item.product_id],
        );
        const balanceBefore = currentStock[0]?.stock_quantity || 0;
        const balanceAfter = balanceBefore - item.quantity;

        await req.db.query(
          "UPDATE products SET stock_quantity = stock_quantity - ? WHERE id = ?",
          [item.quantity, item.product_id],
        );

        const [product] = await req.db.query(
          "SELECT name, sku, unit_id FROM products WHERE id = ?",
          [item.product_id],
        );

        await req.db.query(
          `INSERT INTO stock_movements 
                 (product_id, product_name, sku, date, reference, movement_type, 
                  quantity, balance_before, balance_after, notes, user_id, invoice_number, tenant_id)
                 VALUES (?, ?, ?, NOW(), ?, 'OUT', ?, ?, ?, ?, ?, ?, ?)`,
          [
            item.product_id,
            product[0]?.name || "",
            product[0]?.sku || "",
            `CREDIT-${creditSale[0].invoice_number}`,
            item.quantity,
            balanceBefore,
            balanceAfter,
            `Credit sale completed #${creditSale[0].invoice_number}`,
            req.user.id,
            creditSale[0].invoice_number,
            req.user.tenant_id,
          ],
        );
      }

      await req.db.query(
        `UPDATE credit_sales 
             SET status = 'paid' 
             WHERE id = ?`,
        [req.params.id],
      );

        await req.db.query(
            `UPDATE notifications SET is_read = 1 WHERE reference_id = ? AND type IN ('credit_approved', 'credit_rejected')`,
            [creditSale[0].sale_id],
        );

      res.json({ message: "Credit sale completed. Stock deducted." });
    } catch (error) {
      console.error("Error completing credit sale:", error);
      res.status(500).json({ error: "Server error" });
    }
  },
);


// ==================== CUSTOMERS ENDPOINTS ====================

app.get(
  "/api/customers",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    try {
      const [customers] = await req.db.query(`
            SELECT c.*, s.name as state_name 
            FROM customers c
            LEFT JOIN states s ON c.state_id = s.id
            WHERE c.is_active = 1 
            ORDER BY c.name
        `);
      res.json(customers);
    } catch (error) {
      console.error("Error fetching customers:", error);
      res.status(500).json({ error: "Server error" });
    }
  },
);

app.get(
  "/api/customers/:id",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    try {
      const [customers] = await req.db.query(
        `
            SELECT c.*, s.name as state_name 
            FROM customers c
            LEFT JOIN states s ON c.state_id = s.id
            WHERE c.id = ?
        `,
        [req.params.id],
      );

      if (customers.length === 0) {
        return res.status(404).json({ error: "Customer not found" });
      }
      res.json(customers[0]);
    } catch (error) {
      console.error("Error fetching customer:", error);
      res.status(500).json({ error: "Server error" });
    }
  },
);

app.post(
  "/api/customers",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    try {
      const {
        name,
        phone,
        email,
        address,
        stateId,
        taxId,
        creditLimit,
        creditDays,
      } = req.body;

      const [result] = await req.db.query(
        `INSERT INTO customers (name, phone, email, address, state_id, tax_id, credit_limit, credit_days, is_active, created_at, updated_at, tenant_id) 
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, NOW(), NOW(), ?) RETURNING id`,
        [
          name,
          phone,
          email,
          address,
          stateId,
          taxId,
          creditLimit || 0,
          creditDays || 0,
          req.user.tenant_id,
        ],
      );

      const [newCustomer] = await req.db.query(
        `
            SELECT c.*, s.name as state_name 
            FROM customers c
            LEFT JOIN states s ON c.state_id = s.id
            WHERE c.id = ?
        `,
        [result[0].id],
      );

      res.json(newCustomer[0]);
    } catch (error) {
      console.error("Error adding customer:", error);
      res.status(500).json({ error: "Server error" });
    }
  },
);

app.put(
  "/api/customers/:id",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    try {
      const {
        name,
        phone,
        email,
        address,
        stateId,
        taxId,
        creditLimit,
        creditDays,
        isActive,
      } = req.body;

      await req.db.query(
        `UPDATE customers SET 
                name = ?, phone = ?, email = ?, address = ?, state_id = ?, tax_id =?,
                credit_limit = ?, credit_days = ?, is_active = ?, updated_at = NOW()
             WHERE id = ?`,
        [
          name,
          phone,
          email,
          address,
          stateId,
          taxId,
          creditLimit || 0,
          creditDays || 0,
          isActive === undefined ? 1 : isActive ? 1 : 0,
          req.params.id,
        ],
      );

      res.json({ message: "Customer updated successfully" });
    } catch (error) {
      console.error("Error updating customer:", error);
      res.status(500).json({ error: "Server error" });
    }
  },
);

app.delete(
  "/api/customers/:id",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    try {
      await req.db.query("UPDATE customers SET is_active = 0 WHERE id = ?", [
        req.params.id,
      ]);
      res.json({ message: "Customer deleted successfully" });
    } catch (error) {
      console.error("Error deleting customer:", error);
      res.status(500).json({ error: "Server error" });
    }
  },
);

app.get(
  "/api/customers/:id/balance",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    try {
      const [purchases] = await req.db.query(
        "SELECT COALESCE(SUM(total), 0) as total FROM sales WHERE customer_id = ?",
        [req.params.id],
      );
      res.json({ balance: purchases[0].total || 0 });
    } catch (error) {
      console.error("Error fetching customer balance:", error);
      res.status(500).json({ error: "Server error" });
    }
  },
);

// ==================== VENDORS ENDPOINTS ====================

app.get(
  "/api/vendors",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    try {
      const [vendors] = await req.db.query(`
            SELECT v.*, s.name as state_name 
            FROM vendors v
            LEFT JOIN states s ON v.state_id = s.id
            ORDER BY v.name
        `);
      res.json(vendors);
    } catch (error) {
      console.error("Error fetching vendors:", error);
      res.status(500).json({ error: "Server error" });
    }
  },
);

app.get(
  "/api/vendors/:id",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    try {
      const [vendors] = await req.db.query(
        `
            SELECT v.*, s.name as state_name 
            FROM vendors v
            LEFT JOIN states s ON v.state_id = s.id
            WHERE v.id = ?
        `,
        [req.params.id],
      );

      if (vendors.length === 0) {
        return res.status(404).json({ error: "Vendor not found" });
      }
      res.json(vendors[0]);
    } catch (error) {
      console.error("Error fetching vendor:", error);
      res.status(500).json({ error: "Server error" });
    }
  },
);

app.post(
  "/api/vendors",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    try {
      const {
        name,
        contactPerson,
        phone,
        email,
        address,
        stateId,
        taxId,
        paymentTerms,
        isVatRegistered,
      } = req.body;

      const [result] = await req.db.query(
        `INSERT INTO vendors (name, contact_person, phone, email, address, state_id, tax_id, payment_terms, is_vat_registered, is_active, created_at, updated_at, tenant_id) 
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, NOW(), NOW(), ?) RETURNING id`,
        [
          name,
          contactPerson,
          phone,
          email,
          address,
          stateId,
          taxId,
          paymentTerms,
          isVatRegistered ? 1 : 0,
          req.user.tenant_id,
        ],
      );

      const [newVendor] = await req.db.query(
        `
            SELECT v.*, s.name as state_name 
            FROM vendors v
            LEFT JOIN states s ON v.state_id = s.id
            WHERE v.id = ?
        `,
        [result[0].id],
      );

      res.json(newVendor[0]);
    } catch (error) {
      console.error("Error adding vendor:", error);
      res.status(500).json({ error: "Server error" });
    }
  },
);

app.put(
  "/api/vendors/:id",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    try {
      const {
        name,
        contactPerson,
        phone,
        email,
        address,
        stateId,
        taxId,
        paymentTerms,
        isVatRegistered,
        isActive,
      } = req.body;

      await req.db.query(
        `UPDATE vendors SET 
                name = ?, contact_person = ?, phone = ?, email = ?, address = ?, state_id = ?,
                tax_id = ?, payment_terms = ?, is_vat_registered = ?, is_active = ?, updated_at = NOW()
             WHERE id = ?`,
        [
          name,
          contactPerson,
          phone,
          email,
          address,
          stateId,
          taxId,
          paymentTerms,
          isVatRegistered ? 1 : 0,
          isActive !== undefined ? (isActive ? 1 : 0) : 1,
          req.params.id,
        ],
      );

      res.json({ message: "Vendor updated successfully" });
    } catch (error) {
      console.error("Error updating vendor:", error);
      res.status(500).json({ error: "Server error" });
    }
  },
);

app.delete(
  "/api/vendors/:id",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    try {
      await req.db.query("UPDATE vendors SET is_active = 0 WHERE id = ?", [
        req.params.id,
      ]);
      res.json({ message: "Vendor deleted successfully" });
    } catch (error) {
      console.error("Error deleting vendor:", error);
      res.status(500).json({ error: "Server error" });
    }
  },
);

// ==================== UNITS ENDPOINTS ====================

app.get("/api/units", authenticateToken, setTenantContext, async (req, res) => {
  try {
    const [units] = await req.db.query(`
            SELECT u.*, bu.name as base_unit_name 
            FROM units u
            LEFT JOIN units bu ON u.base_unit_id = bu.id
            WHERE u.is_active = 1 
            ORDER BY u.name
        `);
    res.json(units);
  } catch (error) {
    console.error("Error fetching units:", error);
    res.status(500).json({ error: "Server error" });
  }
});

app.get(
  "/api/units/:id",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    try {
      const [units] = await req.db.query(
        `
            SELECT u.*, bu.name as base_unit_name 
            FROM units u
            LEFT JOIN units bu ON u.base_unit_id = bu.id
            WHERE u.id = ?
        `,
        [req.params.id],
      );

      if (units.length === 0) {
        return res.status(404).json({ error: "Unit not found" });
      }
      res.json(units[0]);
    } catch (error) {
      console.error("Error fetching unit:", error);
      res.status(500).json({ error: "Server error" });
    }
  },
);

app.post(
  "/api/units",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    try {
      const { name, symbol, baseUnitId, conversionFactor, isBaseUnit } =
        req.body;

      const [result] = await req.db.query(
        `INSERT INTO units (name, symbol, base_unit_id, conversion_factor, is_base_unit, is_active, created_at, updated_at, tenant_id) 
             VALUES (?, ?, ?, ?, ?, 1, NOW(), NOW(), ?) RETURNING id`,
        [
          name,
          symbol,
          baseUnitId || null,
          conversionFactor || 1.0,
          isBaseUnit ? 1 : 0,
          req.user.tenant_id,
        ],
      );

      const [newUnit] = await req.db.query(
        `
            SELECT u.*, bu.name as base_unit_name 
            FROM units u
            LEFT JOIN units bu ON u.base_unit_id = bu.id
            WHERE u.id = ?
        `,
        [result[0].id],
      );

      res.json(newUnit[0]);
    } catch (error) {
      console.error("Error adding unit:", error);
      res.status(500).json({ error: "Server error" });
    }
  },
);

app.put(
  "/api/units/:id",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    try {
      const { name, symbol, baseUnitId, conversionFactor, isBaseUnit } =
        req.body;

      await req.db.query(
        `UPDATE units SET 
                name = ?, symbol = ?, base_unit_id = ?, conversion_factor = ?,
                is_base_unit = ?, updated_at = NOW()
             WHERE id = ?`,
        [
          name,
          symbol,
          baseUnitId || null,
          conversionFactor || 1.0,
          isBaseUnit ? 1 : 0,
          req.params.id,
        ],
      );

      res.json({ message: "Unit updated successfully" });
    } catch (error) {
      console.error("Error updating unit:", error);
      res.status(500).json({ error: "Server error" });
    }
  },
);

app.delete(
  "/api/units/:id",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    try {
      await req.db.query("UPDATE units SET is_active = 0 WHERE id = ?", [
        req.params.id,
      ]);
      res.json({ message: "Unit deleted successfully" });
    } catch (error) {
      console.error("Error deleting unit:", error);
      res.status(500).json({ error: "Server error" });
    }
  },
);

app.get(
  "/api/purchase-orders",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    try {
      const [orders] = await req.db.query(`
            SELECT po.*, v.name as vendor_name 
            FROM purchase_orders po
            LEFT JOIN vendors v ON po.vendor_id = v.id
            ORDER BY po.order_date DESC
        `);
      res.json(orders);
    } catch (error) {
      console.error("Error fetching purchase orders:", error);
      res.status(500).json({ error: "Server error" });
    }
  },
);

app.get(
  "/api/purchase-orders/:id",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    try {
      const [orders] = await req.db.query(
        `
            SELECT po.*, v.name as vendor_name 
            FROM purchase_orders po
            LEFT JOIN vendors v ON po.vendor_id = v.id
            WHERE po.id = ?
        `,
        [req.params.id],
      );

      if (orders.length === 0) {
        return res.status(404).json({ error: "Purchase order not found" });
      }

      const [items] = await req.db.query(
        `
            SELECT poi.*, p.name as product_name, p.sku
            FROM purchase_order_items poi
            LEFT JOIN products p ON poi.product_id = p.id
            WHERE poi.purchase_order_id = ?
        `,
        [req.params.id],
      );

      res.json({
        purchaseOrder: orders[0],
        items: items,
      });
    } catch (error) {
      console.error("Error fetching purchase order detail:", error);
      res.status(500).json({ error: "Server error" });
    }
  },
);

// Create purchase order - WITH UNIT CONVERSION SUPPORT
app.post(
  "/api/purchase-orders",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    try {
      const { vendorId, items, notes } = req.body;
      const poNumber = `PO-${Date.now()}`;

      let subtotal = 0;
      for (const item of items) {
        subtotal += item.quantity * item.unitPrice;
      }
      const tax = subtotal * 0.075;
      const total = subtotal + tax;

      const [result] = await req.db.query(
        `INSERT INTO purchase_orders 
             (po_number, vendor_id, order_date, subtotal, tax, total, status, notes, created_at, updated_at, tenant_id) 
             VALUES (?, ?, NOW(), ?, ?, ?, 'pending', ?, NOW(), NOW(), ?) RETURNING id`,
        [poNumber, vendorId, subtotal, tax, total, notes, req.user.tenant_id],
      );

      const poId = result[0].id;

      for (const item of items) {
        // Store order unit information for conversion during receiving
        await req.db.query(
          `INSERT INTO purchase_order_items 
                 (purchase_order_id, product_id, quantity, unit_price, total, received_quantity,
                  order_unit_id, order_unit_name, order_unit_symbol, order_quantity, tenant_id) 
                 VALUES (?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?)`,
          [
            poId,
            item.productId,
            item.quantity,
            item.unitPrice,
            item.quantity * item.unitPrice,
            item.orderUnitId,
            item.orderUnitName,
            item.unitSymbol,
            item.quantity,
            req.user.tenant_id,
          ],
        );
      }

      res.json({
        id: poId,
        po_number: poNumber,
        message: "Purchase order created successfully",
      });
    } catch (error) {
      console.error("Error creating purchase order:", error);
      res.status(500).json({ error: "Server error" });
    }
  },
);

// Receive purchase order items - WITH UNIT CONVERSION
app.post(
  "/api/purchase-orders/:id/receive",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    try {
      const { items, invoiceNumber } = req.body;

      console.log("=== RECEIVE PURCHASE ORDER ===");
      console.log("PO ID:", req.params.id);
      console.log("Invoice:", invoiceNumber);

      // Update invoice number if provided
      if (invoiceNumber) {
        await req.db.query(
          "UPDATE purchase_orders SET invoice_number = ? WHERE id = ?",
          [invoiceNumber, req.params.id],
        );
      }

      // Process each item
      for (const item of items) {
        // Get purchase order item details
        const [poItem] = await req.db.query(
          "SELECT order_unit_id, order_quantity, order_unit_name, product_id,quantity as ordered_quantity FROM purchase_order_items WHERE id = ?",
          [item.id],
        );

        if (poItem.length === 0) {
          console.log(`Item ${item.id} not found, skipping`);
          continue;
        }

        // Calculate stock quantity (with unit conversion if needed)
        let stockQuantity = item.receivedQuantity;

        if (poItem[0].order_unit_id && poItem[0].order_quantity) {
          const [orderUnit] = await req.db.query(
            "SELECT conversion_factor FROM units WHERE id = ?",
            [poItem[0].order_unit_id],
          );
          if (orderUnit.length > 0) {
            stockQuantity =
              item.receivedQuantity * orderUnit[0].conversion_factor;
            console.log(
              `Converting ${item.receivedQuantity} ${poItem[0].order_unit_name} to ${stockQuantity} base units`,
            );
          }
        }

        // Update received quantity in purchase_order_items
        await req.db.query(
          "UPDATE purchase_order_items SET received_quantity = ? WHERE id = ?",
          [item.receivedQuantity, item.id],
        );

        // Update product stock
        await req.db.query(
          "UPDATE products SET stock_quantity = stock_quantity + ? WHERE id = ?",
          [stockQuantity, item.productId],
        );

        // Get current stock for balance
        const [currentStock] = await req.db.query(
          "SELECT stock_quantity FROM products WHERE id = ?",
          [item.productId],
        );
        const balanceAfter = currentStock[0]?.stock_quantity || 0;
        const balanceBefore = balanceAfter - stockQuantity;

        // Get product details
        const [product] = await req.db.query(
          "SELECT name, sku, unit_id FROM products WHERE id = ?",
          [item.productId],
        );
        console.log("Product found:", product);
        console.log("Product name:", product[0]?.name);
        console.log("Product sku:", product[0]?.sku);

        // Get unit symbol
        let unitSymbol = "";
        if (product[0]?.unit_id) {
          const [unit] = await req.db.query(
            "SELECT symbol FROM units WHERE id = ?",
            [product[0].unit_id],
          );
          unitSymbol = unit[0]?.symbol || "";
        }

        // Record stock movement
        await req.db.query(
          `INSERT INTO stock_movements 
                (product_id, product_name, sku, date, reference, movement_type, quantity, balance_before, balance_after, notes, user_id, unit_symbol, invoice_number, tenant_id)
                VALUES (?, ?, ?, NOW(), ?, 'IN', ?, ?, ?, ?, ?, ?, ?, ?)`,
          [
            item.productId,
            product[0]?.name || "",
            product[0]?.sku || "",
            `PO-${req.params.id}`,
            stockQuantity,
            balanceBefore,
            balanceAfter,
            `Received from PO #${req.params.id}${invoiceNumber ? ` (Invoice: ${invoiceNumber})` : ""}`,
            req.user.id,
            unitSymbol,
            invoiceNumber || null,
            req.user.tenant_id,
          ],
        );
      }

      // Check if ALL items are fully received
      const [allItems] = await req.db.query(
        "SELECT id, quantity, received_quantity FROM purchase_order_items WHERE purchase_order_id = ?",
        [req.params.id],
      );

      console.log("=== CHECKING RECEIVED STATUS ===");
      console.log("Items found:", allItems.length);

      let totalItems = allItems.length;
      let fullyReceived = 0;

      for (const item of allItems) {
        console.log(
          `Item ${item.id}: quantity=${item.quantity}, received=${item.received_quantity}`,
        );
        if (item.received_quantity >= item.quantity) {
          fullyReceived++;
        }
      }

      console.log(
        `Total items: ${totalItems}, Fully received: ${fullyReceived}`,
      );

      let newStatus = "pending";
      if (fullyReceived === totalItems && totalItems > 0) {
        newStatus = "received";
      } else if (fullyReceived > 0) {
        newStatus = "partial";
      } else {
        newStatus = "pending";
      }

      console.log(`Setting PO status to: ${newStatus}`);

      await req.db.query(
        "UPDATE purchase_orders SET status = ?, updated_at = NOW() WHERE id = ?",
        [newStatus, req.params.id],
      );

      console.log("✅ Receive completed successfully");
      res.json({ message: "Items received successfully", status: newStatus });
    } catch (error) {
      console.error("❌ Error receiving items:", error);
      res.status(500).json({ error: error.message || "Server error" });
    }
  },
);

// Cancel purchase order
app.patch(
  "/api/purchase-orders/:id/cancel",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    try {
      const { reason } = req.body;
      await req.db.query(
        "UPDATE purchase_orders SET status = ?, notes = COALESCE(notes, '') || ' | Cancelled: ' || ?, updated_at = NOW() WHERE id = ?",
        ["cancelled", reason, req.params.id],
      );
      res.json({ message: "Purchase order cancelled" });
    } catch (error) {
      console.error("Error cancelling purchase order:", error);
      res.status(500).json({ error: "Server error" });
    }
  },
);

// ==================== VENDOR PAYMENTS ENDPOINTS ====================

app.post(
  "/api/vendor-payments",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    try {
      const {
        vendorId,
        purchaseOrderId,
        paymentDate,
        amount,
        paymentMethod,
        reference,
        notes,
        createdBy,
        bankAccountId,
      } = req.body;

      console.log("=== VENDOR PAYMENT ===");
      console.log("bankAccountId:", bankAccountId);
      console.log("paymentMethod:", paymentMethod);
      console.log("amount:", amount);

      const [result] = await req.db.query(
        `INSERT INTO vendor_payments 
             (vendor_id, purchase_order_id, payment_date, amount, payment_method, reference, notes, created_by, created_at, updated_at, tenant_id) 
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW(), ?) RETURNING id`,
        [
          vendorId,
          purchaseOrderId || null,
          paymentDate,
          amount,
          paymentMethod,
          reference,
          notes,
          createdBy,
          req.user.tenant_id,
        ],
      );

      // Update bank account balance if this is a bank payment
      if (
        bankAccountId &&
        (paymentMethod === "Bank Transfer" || paymentMethod === "Cheque")
      ) {
        await req.db.query(
          "UPDATE bank_accounts SET current_balance = current_balance - ? WHERE id = ?",
          [amount, bankAccountId],
        );
        console.log(`Subtracted ${amount} from bank account ${bankAccountId}`);
      }

      const [newPayment] = await req.db.query(
        `
            SELECT vp.*, v.name as vendor_name, po.po_number as purchase_order_number
            FROM vendor_payments vp
            LEFT JOIN vendors v ON vp.vendor_id = v.id
            LEFT JOIN purchase_orders po ON vp.purchase_order_id = po.id
            WHERE vp.id = ?
        `,
        [result[0].id],
      );

      res.json(newPayment[0]);
    } catch (error) {
      console.error("Error adding vendor payment:", error);
      res.status(500).json({ error: "Server error" });
    }
  },
);

app.get(
  "/api/vendor-payments/summary",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    try {
      const [vendors] = await req.db.query(`
            SELECT 
                v.id as vendor_id,
                v.name as vendor_name,
                COALESCE((SELECT SUM(total) FROM purchase_orders WHERE vendor_id = v.id AND status IN ('received', 'completed')), 0) as total_purchases,
                COALESCE((SELECT SUM(amount) FROM vendor_payments WHERE vendor_id = v.id), 0) as total_payments,
                COALESCE((SELECT SUM(total) FROM purchase_orders WHERE vendor_id = v.id AND status IN ('received', 'completed')), 0) - 
                COALESCE((SELECT SUM(amount) FROM vendor_payments WHERE vendor_id = v.id), 0) as balance
            FROM vendors v
            WHERE v.is_active = 1
            ORDER BY v.name
        `);
      res.json(vendors);
    } catch (error) {
      console.error("Error fetching vendor payment summary:", error);
      res.status(500).json({ error: "Server error" });
    }
  },
);

app.delete(
  "/api/vendor-payments/:id",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    try {
      await req.db.query("DELETE FROM vendor_payments WHERE id = ?", [
        req.params.id,
      ]);
      res.json({ message: "Payment deleted successfully" });
    } catch (error) {
      console.error("Error deleting vendor payment:", error);
      res.status(500).json({ error: "Server error" });
    }
  },
);

// ==================== VENDOR INVOICES ENDPOINTS ====================

app.get(
  "/api/vendors/:id/invoices",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    try {
      const vendorId = req.params.id;

      const [allPOs] = await req.db.query(
        `
            SELECT 
                po.id,
                po.po_number,
                po.invoice_number,
                po.order_date,
                po.total,
                po.status,
                COALESCE(SUM(vp.amount), 0) as paid_amount
            FROM purchase_orders po
            LEFT JOIN vendor_payments vp ON po.id = vp.purchase_order_id
            WHERE po.vendor_id = ? 
                AND po.status = 'received'
            GROUP BY po.id, po.po_number, po.invoice_number, po.order_date, po.total, po.status
            ORDER BY po.order_date DESC
        `,
        [vendorId],
      );

      const grouped = {};

      for (const po of allPOs) {
        let key;
        if (po.invoice_number && po.invoice_number.trim() !== "") {
          key = po.invoice_number;
        } else {
          key = po.po_number;
        }

        if (!grouped[key]) {
          grouped[key] = {
            invoice_number: key,
            invoice_date: po.order_date,
            purchase_orders: [],
            total: 0,
            paid: 0,
            balance: 0,
          };
        }

        const balance = parseFloat(po.total) - parseFloat(po.paid_amount);

        grouped[key].purchase_orders.push({
          id: po.id,
          po_number: po.po_number,
          total: parseFloat(po.total),
          paid: parseFloat(po.paid_amount),
          balance: balance,
        });

        grouped[key].total += parseFloat(po.total);
        grouped[key].paid += parseFloat(po.paid_amount);
        grouped[key].balance += balance;
      }

      const result = Object.values(grouped).filter((inv) => inv.balance > 0);

      res.json(result);
    } catch (error) {
      console.error("Error fetching vendor invoices:", error);
      res.status(500).json({ error: "Server error" });
    }
  },
);

// ==================== STOCK MOVEMENTS ENDPOINTS ====================

app.get(
  "/api/stock-movements",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    try {
      const { productId, start, end, reference } = req.query;
      let query = "SELECT * FROM stock_movements WHERE 1=1";
      let params = [];

      if (productId) {
        query += " AND product_id = ?";
        params.push(productId);
      }
      if (start && end) {
        query += " AND date BETWEEN ? AND ?";
        params.push(start, end);
      }
      if (reference) {
        query += " AND reference = ?";
        params.push(reference);
      }

      query += " ORDER BY date DESC";

      const [movements] = await req.db.query(query, params);
      res.json(movements);
    } catch (error) {
      console.error("Error fetching stock movements:", error);
      res.status(500).json({ error: "Server error" });
    }
  },
);

app.get(
  "/api/products/:id/bincard",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    try {
      const productId = req.params.id;

      const [movements] = await req.db.query(
        `
            SELECT * FROM stock_movements 
            WHERE product_id = ? 
            ORDER BY date DESC
        `,
        [productId],
      );

      res.json(movements);
    } catch (error) {
      console.error("Error fetching bincard:", error);
      res.status(500).json({ error: "Server error" });
    }
  },
);

app.post(
  "/api/stock-movements",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    try {
      const {
        product_id,
        reference,
        movement_type,
        quantity,
        notes,
        invoice_number,
      } = req.body;

      console.log("=== STOCK MOVEMENT ===");
      console.log("product_id:", product_id);
      console.log("movement_type:", movement_type);
      console.log("quantity:", quantity);

      const balanceBefore = 0;

      const adjustment = movement_type === "IN" ? quantity : -quantity;

      const [product] = await req.db.query(
        "SELECT name, sku, unit_id FROM products WHERE id = ?",
        [product_id],
      );

      let unitSymbol = "";
      if (product[0]?.unit_id) {
        const [unit] = await req.db.query(
          "SELECT symbol FROM units WHERE id = ?",
          [product[0].unit_id],
        );
        unitSymbol = unit[0]?.symbol || "";
      }

      // Get the actual stock after update
      const [afterStock] = await req.db.query(
        "SELECT stock_quantity FROM products WHERE id = ?",
        [product_id],
      );
      const balanceAfter = afterStock[0]?.stock_quantity || 0;

      const [result] = await req.db.query(
        `INSERT INTO stock_movements 
             (product_id, product_name, sku, date, reference, movement_type, 
              quantity, balance_before, balance_after, notes, user_id, unit_symbol, tenant_id)
             VALUES (?, ?, ?, NOW(), ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id`,
        [
          product_id,
          product[0]?.name || "",
          product[0]?.sku || "",
          reference,
          movement_type,
          quantity,
          balanceBefore,
          balanceAfter,
          notes ||
            `Manual adjustment (${movement_type === "IN" ? "add" : "remove"})`,
          req.user.id,
          unitSymbol,
          req.user.tenant_id,
        ],
      );

      console.log("✅ Stock movement recorded, ID:", result[0].id);
      res.json({
        id: result[0].id,
        message: "Stock movement recorded successfully",
        balance_after: balanceAfter,
      });
    } catch (error) {
      console.error("❌ Error recording stock movement:", error);
      res.status(500).json({ error: error.message || "Server error" });
    }
  },
);

// ==================== NOTIFICATIONS ENDPOINTS ====================

// Get notifications for current user
app.get(
  "/api/notifications",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    try {
      const [notifications] = await req.db.query(
        "SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC",
        [req.user.id],
      );
      res.json(notifications);
    } catch (error) {
      console.error("Error fetching notifications:", error);
      res.status(500).json({ error: "Server error" });
    }
  },
);

// Mark notification as read
app.patch(
  "/api/notifications/:id/read",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    try {
      await req.db.query(
        "UPDATE notifications SET is_read = 1 WHERE id = ? AND user_id = ?",
        [req.params.id, req.user.id],
      );
      res.json({ message: "Notification marked as read" });
    } catch (error) {
      console.error("Error marking notification read:", error);
      res.status(500).json({ error: "Server error" });
    }
  },
);

// ==================== BANKS ENDPOINTS ====================

app.get("/api/banks", authenticateToken, setTenantContext, async (req, res) => {
  try {
    const [banks] = await req.db.query(
      "SELECT * FROM banks WHERE is_active = 1 ORDER BY name",
    );
    res.json(banks);
  } catch (error) {
    console.error("Error fetching banks:", error);
    res.status(500).json({ error: "Server error" });
  }
});

app.post(
  "/api/banks",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    try {
      const { name, code } = req.body;
      const [result] = await req.db.query(
        "INSERT INTO banks (name, code, is_active, created_at, tenant_id) VALUES (?, ?, 1, NOW(), ?) RETURNING id",
        [name, code, req.user.tenant_id],
      );
      const [newBank] = await req.db.query("SELECT * FROM banks WHERE id = ?", [
        result[0].id,
      ]);
      res.json(newBank[0]);
    } catch (error) {
      console.error("Error adding bank:", error);
      res.status(500).json({ error: "Server error" });
    }
  },
);

app.put(
  "/api/banks/:id",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    try {
      const { name, code } = req.body;
      await req.db.query("UPDATE banks SET name = ?, code = ? WHERE id = ?", [
        name,
        code,
        req.params.id,
      ]);
      res.json({ message: "Bank updated successfully" });
    } catch (error) {
      console.error("Error updating bank:", error);
      res.status(500).json({ error: "Server error" });
    }
  },
);

app.delete(
  "/api/banks/:id",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    try {
      await req.db.query("DELETE FROM banks WHERE id = ?", [req.params.id]);
      res.json({ message: "Bank deleted successfully" });
    } catch (error) {
      console.error("Error deleting bank:", error);
      res.status(500).json({ error: "Server error" });
    }
  },
);

// ==================== BANK ACCOUNTS ENDPOINTS ====================

app.get(
  "/api/bank-accounts",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    try {
      const [accounts] = await req.db.query(
        "SELECT * FROM bank_accounts WHERE is_active = 1 ORDER BY account_name",
      );
      res.json(accounts);
    } catch (error) {
      console.error("Error fetching bank accounts:", error);
      res.status(500).json({ error: "Server error" });
    }
  },
);

app.post(
  "/api/bank-accounts",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    try {
      const {
        account_name,
        bank_name,
        bank_id,
        account_number,
        opening_balance,
      } = req.body;
      const [result] = await req.db.query(
        "INSERT INTO bank_accounts (account_name, bank_name, bank_id, account_number, opening_balance, current_balance, is_active, created_at, tenant_id) VALUES (?, ?, ?, ?, ?, ?, 1, NOW(), ?) RETURNING id",
        [
          account_name,
          bank_name,
          bank_id,
          account_number,
          opening_balance || 0,
          opening_balance || 0,
          req.user.tenant_id,
        ],
      );
      const [newAccount] = await req.db.query(
        "SELECT * FROM bank_accounts WHERE id = ?",
        [result[0].id],
      );
      res.json(newAccount[0]);
    } catch (error) {
      console.error("Error adding bank account:", error);
      res.status(500).json({ error: "Server error" });
    }
  },
);

app.patch(
  "/api/bank-accounts/:id/balance",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    try {
      const { amount, type } = req.body;
      const operation = type === "deposit" ? "+" : "-";
      await req.db.query(
        `UPDATE bank_accounts SET current_balance = current_balance ${operation} ? WHERE id = ?`,
        [amount, req.params.id],
      );
      res.json({ message: "Balance updated" });
    } catch (error) {
      console.error("Error updating balance:", error);
      res.status(500).json({ error: "Server error" });
    }
  },
);


// ==================== CREDIT PAYMENTS ENDPOINT ====================

app.post(
  "/api/credit-payments",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    const {
      credit_sale_id,
      customer_id,
      amount,
      payment_method,
      reference_number,
      notes,
      account_name,
      bank_name,
    } = req.body;

    try {
      console.log("=== CREDIT PAYMENT ===");
      console.log("credit_sale_id:", credit_sale_id);
      console.log("customer_id:", customer_id);
      console.log("amount:", amount);
      console.log("payment_method:", payment_method);

      // Insert the payment
      const [result] = await req.db.query(
        `INSERT INTO credit_payments 
            (credit_sale_id, customer_id, amount, payment_method, reference_number,notes, recorded_by, payment_date, tenant_id) 
            VALUES (?, ?, ?, ?, ?, ?, ?, NOW(), ?)`,
        [
          credit_sale_id,
          customer_id,
          amount,
          payment_method,
          reference_number,
          notes,
          req.user.id,
          req.user.tenant_id,
        ],
      );

      // Update credit sale status
      const [sale] = await req.db.query(
        "SELECT total FROM credit_sales WHERE id = ?",
        [credit_sale_id],
      );

      if (sale.length === 0) {
        return res.status(404).json({ error: "Credit sale not found" });
      }

      // Get total paid so far
      const [paid] = await req.db.query(
        "SELECT COALESCE(SUM(amount), 0) as total FROM credit_payments WHERE credit_sale_id = ?",
        [credit_sale_id],
      );

      const totalPaidSoFar = paid[0].total;
      const newTotalPaid = totalPaidSoFar + amount;

      let newStatus = "partially_paid";
      if (newTotalPaid >= sale[0].total) {
        newStatus = "paid";
      }

      await req.db.query("UPDATE credit_sales SET status = ? WHERE id = ?", [
        newStatus,
        credit_sale_id,
      ]);

      // Update customer balance
      await req.db.query(
        "UPDATE customers SET current_balance = current_balance - ? WHERE id = ?",
        [amount, customer_id],
      );

      // Record in cash/bank book
      const description = `Credit payment from customer - Sale ID: ${credit_sale_id}`;
      const dateStr = new Date().toISOString().slice(0, 19).replace("T", " ");

      if (payment_method === "cash") {
        await req.db.query(
          `INSERT INTO cash_transactions (date, type, amount, category, description, reference, user_id, tenant_id) 
                 VALUES (?, 'cash_in', ?, 'Credit Payment', ?, ?, ?, ?)`,
          [
            dateStr,
            amount,
            description,
            reference_number || `PAY-${credit_sale_id}`,
            req.user.id,
            req.user.tenant_id,
          ],
        );
        console.log("Cash transaction recorded for credit payment");
      } else if (payment_method === "card" || payment_method === "transfer") {
        // Get the first active bank account
        const [accounts] = await req.db.query(
          "SELECT id FROM bank_accounts WHERE is_active = 1 LIMIT 1",
        );
        const bankAccountId = accounts.length > 0 ? accounts[0].id : null;

        await req.db.query(
          `INSERT INTO bank_transactions (date, type, amount, account_name, bank_name, description, reference, user_id, bank_account_id, tenant_id) 
                 VALUES (?, 'deposit', ?, ?, ?, ?, ?, ?, ?, ?)`,
          [
            dateStr,
            amount,
            account_name || "Customer Payment",
            bank_name || "Bank Transfer",
            description,
            reference_number || `PAY-${credit_sale_id}`,
            req.user.id,
            bankAccountId,
            req.user.tenant_id,
          ],
        );
        console.log("Bank transaction recorded for credit payment");

        if (bankAccountId) {
          await req.db.query(
            "UPDATE bank_accounts SET current_balance = current_balance + ? WHERE id = ?",
            [amount, bankAccountId],
          );
          console.log(`Added ${amount} to bank account ${bankAccountId}`);
        }
      }

      res.json({ success: true, message: "Payment recorded successfully" });
    } catch (error) {
      console.error("Error recording credit payment:", error);
      res.status(500).json({ error: "Server error" });
    }
  },
);

// ==================== LAYAWAY ENDPOINTS ====================

app.post(
  "/api/layaway",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    try {
      const {
        saleId,
        customerId,
        invoiceNumber,
        totalAmount,
        depositAmount,
        items,
      } = req.body;
      const balance = totalAmount - depositAmount;
      const userId = req.user.id;

      console.log("=== CREATE LAYAWAY ===");
      console.log("Sale ID:", saleId);
      console.log("Invoice:", invoiceNumber);
      console.log("Total:", totalAmount);
      console.log("Deposit:", depositAmount);
      console.log("Balance:", balance);

      // Create layaway order
      const [result] = await req.db.query(
        `INSERT INTO layaway_orders 
             (sale_id, customer_id, invoice_number, total_amount, deposit_amount, paid_amount, balance, status, items, cashier_id, tenant_id) 
             VALUES (?, ?, ?, ?, ?, ?, ?, 'deposit_paid', ?, ?, ?) RETURNING id`,
        [
          saleId,
          customerId,
          invoiceNumber,
          totalAmount,
          depositAmount,
          depositAmount,
          balance,
          items,
          userId,
          req.user.tenant_id,
        ],
      );

      const layawayId = result[0].id;

      // Record the deposit payment in layaway_payments
      await req.db.query(
        `INSERT INTO layaway_payments 
             (layaway_id, amount, payment_method, recorded_by, tenant_id) 
             VALUES (?, ?, 'deposit', ?, ?)`,
        [layawayId, depositAmount, userId, req.user.tenant_id],
      );

      // ===== RECORD DEPOSIT IN CASH/BANK BOOK =====
      if (depositAmount > 0) {
        const dateStr = new Date().toISOString().slice(0, 19).replace("T", " ");
        const description = `Layaway deposit - ${invoiceNumber}`;
        const reference = `LAY-${layawayId}`;

        // Record as cash_in (default to cash for deposit)
        await req.db.query(
          `INSERT INTO cash_transactions 
                 (date, type, amount, category, description, reference, user_id, tenant_id) 
                 VALUES (?, 'cash_in', ?, 'Layaway Deposit', ?, ?, ?, ?)`,
          [
            dateStr,
            depositAmount,
            description,
            reference,
            userId,
            req.user.tenant_id,
          ],
        );
        console.log("✅ Cash deposit recorded for layaway");
      }

      res.json({ id: layawayId, message: "Layaway created successfully" });
    } catch (error) {
      console.error("Error creating layaway:", error);
      res.status(500).json({ error: error.message });
    }
  },
);

// ==================== LAYAWAY ENDPOINTS ====================

app.get(
  "/api/layaway",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    try {
      const [orders] = await req.db.query(`
            SELECT * FROM layaway_orders 
            ORDER BY created_at DESC
        `);
      res.json(orders);
    } catch (error) {
      console.error("Error fetching layaway orders:", error);
      res.status(500).json({ error: "Server error" });
    }
  },
);

app.get(
  "/api/layaway/:id",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    try {
      const [orders] = await req.db.query(
        "SELECT * FROM layaway_orders WHERE id = ?",
        [req.params.id],
      );
      if (orders.length === 0) {
        return res.status(404).json({ error: "Layaway order not found" });
      }
      res.json(orders[0]);
    } catch (error) {
      console.error("Error fetching layaway order:", error);
      res.status(500).json({ error: "Server error" });
    }
  },
);

// Record layaway payment
app.post(
  "/api/layaway/:id/payment",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    try {
      const { amount, payment_method } = req.body;
      const layawayId = req.params.id;
      const parsedAmount = parseFloat(amount);
      const userId = req.user.id;

      console.log("=== RECORD LAYAWAY PAYMENT ===");
      console.log("Layaway ID:", layawayId);
      console.log("Amount:", parsedAmount);
      console.log("Payment Method:", payment_method);
      console.log("User ID:", userId);

      // Get current order
      const [orders] = await req.db.query(
        "SELECT * FROM layaway_orders WHERE id = ? AND status IN (?, ?, ?)",
        [layawayId, "deposit_paid", "partial", "active"],
      );

      if (orders.length === 0) {
        return res
          .status(404)
          .json({ error: "Layaway order not found or already completed" });
      }

      const order = orders[0];

      // Record payment in layaway_payments
      await req.db.query(
        `INSERT INTO layaway_payments 
             (layaway_id, amount, payment_method, recorded_by, tenant_id) 
             VALUES (?, ?, ?, ?, ?)`,
        [layawayId, parsedAmount, payment_method, userId, req.user.tenant_id],
      );

      // Update order
      const newPaidAmount = parseFloat(order.paid_amount) + parsedAmount;
      const newBalance = parseFloat(order.total_amount) - newPaidAmount;
      let newStatus = "partial";
      if (newBalance <= 0) {
        newStatus = "completed";
      }

      await req.db.query(
        `UPDATE layaway_orders 
             SET paid_amount = ?, balance = ?, status = ?, updated_at = NOW()
             WHERE id = ?`,
        [newPaidAmount, newBalance, newStatus, layawayId],
      );

      // ===== RECORD IN CASH/BANK BOOK =====
      const dateStr = new Date().toISOString().slice(0, 19).replace("T", " ");
      const description = `Layaway payment - ${order.invoice_number}`;
      const reference = `LAY-${layawayId}`;

      if (payment_method === "cash") {
        // Record in cash_book as cash_in
        await req.db.query(
          `INSERT INTO cash_transactions 
                 (date, type, amount, category, description, reference, user_id, tenant_id) 
                 VALUES (?, 'cash_in', ?, 'Layaway Payment', ?, ?, ?, ?)`,
          [
            dateStr,
            parsedAmount,
            description,
            reference,
            userId,
            req.user.tenant_id,
          ],
        );
        console.log("✅ Cash transaction recorded for layaway payment");
      } else if (payment_method === "card" || payment_method === "transfer") {
        // Get the first active bank account
        const [accounts] = await req.db.query(
          "SELECT id FROM bank_accounts WHERE is_active = 1 LIMIT 1",
        );
        const bankAccountId = accounts.length > 0 ? accounts[0].id : null;

        // Record in bank_book
        await req.db.query(
          `INSERT INTO bank_transactions 
                 (date, type, amount, account_name, bank_name, description, reference, user_id, bank_account_id, tenant_id) 
                 VALUES (?, 'deposit', ?, 'Layaway Account', 'Layaway Payment', ?, ?, ?, ?, ?)`,
          [
            dateStr,
            parsedAmount,
            description,
            reference,
            userId,
            bankAccountId,
            req.user.tenant_id,
          ],
        );

        // Update bank account balance
        if (bankAccountId) {
          await req.db.query(
            "UPDATE bank_accounts SET current_balance = current_balance + ? WHERE id = ?",
            [parsedAmount, bankAccountId],
          );
          console.log(`✅ Bank account balance updated: +${parsedAmount}`);
        }
        console.log("✅ Bank transaction recorded for layaway payment");
      }

      // If completed, deduct stock
      if (newStatus === "completed") {
        let items = [];
        try {
          items =
            typeof order.items === "string"
              ? JSON.parse(order.items)
              : order.items;
        } catch (e) {
          console.error("Failed to parse items:", e);
        }

        for (const item of items) {
          // Get current stock
          const [currentStock] = await req.db.query(
            "SELECT stock_quantity FROM products WHERE id = ?",
            [item.product_id],
          );
          const balanceBefore = currentStock[0]?.stock_quantity || 0;

          // Update stock
          await req.db.query(
            "UPDATE products SET stock_quantity = stock_quantity - ? WHERE id = ?",
            [item.quantity, item.product_id],
          );

          const balanceAfter = balanceBefore - item.quantity;

          // Get product details
          const [product] = await req.db.query(
            "SELECT name, sku, unit_id FROM products WHERE id = ?",
            [item.product_id],
          );

          // Record stock movement
          await req.db.query(
            `INSERT INTO stock_movements 
                     (product_id, product_name, sku, date, reference, movement_type, 
                      quantity, balance_before, balance_after, notes, user_id, invoice_number, tenant_id)
                     VALUES (?, ?, ?, NOW(), ?, 'OUT', ?, ?, ?, ?, ?, ?, ?)`,
            [
              item.product_id,
              product[0]?.name || "",
              product[0]?.sku || "",
              `LAYAWAY-${order.invoice_number}`,
              item.quantity,
              balanceBefore,
              balanceAfter,
              `Layaway completed - ${order.invoice_number}`,
              userId,
              order.invoice_number,
              req.user.tenant_id,
            ],
          );
        }
      }

      res.json({
        message: "Payment recorded successfully",
        new_balance: newBalance,
        status: newStatus,
      });
    } catch (error) {
      console.error("Error recording layaway payment:", error);
      res.status(500).json({ error: error.message });
    }
  },
);

app.patch(
  "/api/layaway/:id/complete",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    try {
      const [orders] = await req.db.query(
        "SELECT * FROM layaway_orders WHERE id = ?",
        [req.params.id],
      );

      if (orders.length === 0) {
        return res
          .status(404)
          .json({ error: "Layaway order not found or already completed" });
      }

      const order = orders[0];

      // Check if balance is zero
      if (parseFloat(order.balance) > 0) {
        return res
          .status(400)
          .json({ error: "Cannot complete: balance remains" });
      }

      let items = [];
      try {
        items =
          typeof order.items === "string"
            ? JSON.parse(order.items)
            : order.items;
      } catch (e) {
        console.error("Failed to parse items:", e);
      }

      for (const item of items) {
        // Update stock
        await req.db.query(
          "UPDATE products SET stock_quantity = stock_quantity - ? WHERE id = ?",
          [item.quantity, item.product_id],
        );

        // Get product details
        const [product] = await req.db.query(
          "SELECT name, sku, unit_id FROM products WHERE id = ?",
          [item.product_id],
        );

        // Record stock movement
        await req.db.query(
          `INSERT INTO stock_movements 
                (product_id, product_name, sku, date, reference, movement_type, 
                quantity, balance_before, balance_after, notes, user_id, invoice_number, tenant_id)
                VALUES (?, ?, ?, NOW(), ?, 'OUT', ?, ?, ?, ?, ?, ?, ?)`,
          [
            item.product_id,
            product[0]?.name || "",
            product[0]?.sku || "",
            `LAYAWAY-${order.invoice_number}`,
            item.quantity,
            0,
            0,
            `Layaway completed - ${order.invoice_number}`,
            req.user.id,
            order.invoice_number,
            req.user.tenant_id,
          ],
        );
      }

      await req.db.query(
        "UPDATE layaway_orders SET status = ?, updated_at = NOW() WHERE id = ?",
        ["completed", req.params.id],
      );

      res.json({ message: "Layaway completed successfully" });
    } catch (error) {
      console.error("Error completing layaway:", error);
      res.status(500).json({ error: error.message });
    }
  },
);

app.patch(
  "/api/layaway/:id/cancel",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    try {
      const { reason } = req.body;
      await req.db.query(
        "UPDATE layaway_orders SET status = ?, notes = COALESCE(notes, '') || ' | Cancelled: ' || ?, updated_at = NOW() WHERE id = ?",
        ["cancelled", reason, req.params.id],
      );
      res.json({ message: "Layaway cancelled" });
    } catch (error) {
      console.error("Error cancelling layaway:", error);
      res.status(500).json({ error: "Server error" });
    }
  },
);

// Get customer credit summary
app.get(
  "/api/customers/:id/credit-summary",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    try {
      const [result] = await req.db.query(
        `SELECT 
                c.id, c.name, c.credit_limit, c.current_balance,
                (SELECT COALESCE(SUM(total), 0) FROM credit_sales 
                 WHERE customer_id = c.id AND status IN ('approved', 'goods_released', 'partially_paid')) as total_outstanding,
                (SELECT COUNT(*) FROM credit_sales 
                 WHERE customer_id = c.id AND status IN ('approved', 'goods_released', 'partially_paid')) as outstanding_count,
                (SELECT COALESCE(SUM(amount), 0) FROM credit_payments cp 
                 JOIN credit_sales cs ON cp.credit_sale_id = cs.id 
                 WHERE cs.customer_id = c.id) as total_paid
             FROM customers c WHERE c.id = ?`,
        [req.params.id],
      );
      res.json(result[0]);
    } catch (error) {
      console.error("Error getting credit summary:", error);
      res.status(500).json({ error: "Server error" });
    }
  },
);

// Get customer outstanding sales
app.get(
  "/api/customers/:id/outstanding-sales",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    try {
      const [sales] = await req.db.query(
        `SELECT 
                cs.id, cs.invoice_number, cs.sale_date, cs.due_date, cs.total,
                COALESCE((SELECT SUM(amount) FROM credit_payments WHERE credit_sale_id = cs.id), 0) as paid_amount,
                COALESCE(cs.total - COALESCE((SELECT SUM(amount) FROM credit_payments WHERE credit_sale_id = cs.id), 0), 0) as remaining_amount
             FROM credit_sales cs 
             WHERE cs.customer_id = ? AND cs.status IN ('approved', 'goods_released', 'partially_paid')
             ORDER BY cs.due_date ASC`,
        [req.params.id],
      );
      res.json(sales);
    } catch (error) {
      console.error("Error getting outstanding sales:", error);
      res.status(500).json({ error: "Server error" });
    }
  },
);

// ==================== BACKUP ENDPOINTS ====================

app.get(
  "/api/backup/export",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    try {
      console.log("✅ BACKUP EXPORT CALLED");
      console.log("=== BACKUP EXPORT === tenant:", req.user.tenant_id);

      // Global tables that must NOT be exported per-tenant:
      // - tenants: contains other tenants' account info
      // - permissions: shared RBAC catalog
      // - states: shared Nigerian states reference
      const GLOBAL_TABLES = ["tenants", "permissions", "states"];

      // Get all tables, filter out globals
      const [tables] = await req.db.query(
        "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' AND table_type = 'BASE TABLE'",
      );
      const tenantTables = tables.filter(
        (t) => !GLOBAL_TABLES.includes(t.table_name),
      );

      let sql = `-- ZiteMart backup for tenant ${req.user.tenant_id}\n-- Generated ${new Date().toISOString()}\n\n`;

      for (const table of tenantTables) {
        const tableName = table.table_name;
        // req.db + RLS scopes each SELECT to the current tenant
        const [rows] = await req.db.query(`SELECT * FROM "${tableName}"`);

        if (rows.length > 0) {
          const columns = Object.keys(rows[0])
            .map((c) => `"${c}"`)
            .join(", ");
          for (const row of rows) {
            const values = Object.values(row)
              .map((v) => {
                if (v === null || v === undefined) return "NULL";
                if (typeof v === "number") return String(v);
                if (typeof v === "boolean") return v ? "TRUE" : "FALSE";
                if (v instanceof Date) return `'${v.toISOString()}'`;
                if (typeof v === "object")
                  return `'${JSON.stringify(v).replace(/'/g, "''")}'`;
                return `'${String(v).replace(/'/g, "''")}'`;
              })
              .join(", ");
            sql += `INSERT INTO "${tableName}" (${columns}) VALUES (${values});\n`;
          }
        }
      }

      res.setHeader("Content-Type", "application/sql");
      res.setHeader(
        "Content-Disposition",
        `attachment; filename=zitemart_tenant_${req.user.tenant_id}_backup.sql`,
      );
      res.send(sql);
    } catch (error) {
      console.error("Error exporting database:", error);
      res.status(500).json({ error: error.message });
    }
  },
);

app.post(
  "/api/backup/import",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    try {
      // Stub — no tenant-scoped import yet. Returns success without doing anything.
      res.json({ message: "Import endpoint ready" });
    } catch (error) {
      console.error("Error importing database:", error);
      res.status(500).json({ error: error.message });
    }
  },
);

app.post(
  "/api/backup/restore",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    try {
      // Stub — no tenant-scoped restore yet.
      res.json({ message: "Restore endpoint ready" });
    } catch (error) {
      console.error("Error restoring database:", error);
      res.status(500).json({ error: error.message });
    }
  },
);

// ==================== ROLES & PERMISSIONS ENDPOINTS ====================

// Get all roles with their permission counts
app.get("/api/roles", authenticateToken, setTenantContext, async (req, res) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({ error: "Access denied" });
  }

  try {
    const [roles] = await req.db.query(`
            SELECT r.*, 
                (SELECT COUNT(*) FROM role_permissions WHERE role_id = r.id) AS permission_count,
                (SELECT COUNT(*) FROM users WHERE role_id = r.id) AS user_count
            FROM roles r
            ORDER BY r.is_system DESC, r.name
        `);
    res.json(roles);
  } catch (error) {
    console.error("Error fetching roles:", error);
    res.status(500).json({ error: "Server error" });
  }
});

// Get permission catalog (all available permissions, grouped)
// NOTE: permissions is a GLOBAL table (no tenant_id). Stays on pool.query.
app.get("/api/permissions", authenticateToken, async (req, res) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({ error: "Access denied" });
  }

  try {
    const [permissions] = await pool.query(
      "SELECT * FROM permissions ORDER BY category, sort_order",
    );
    res.json(permissions);
  } catch (error) {
    console.error("Error fetching permissions:", error);
    res.status(500).json({ error: "Server error" });
  }
});

// Get a single role with its permission ids
app.get(
  "/api/roles/:id",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    if (req.user.role !== "admin") {
      return res.status(403).json({ error: "Access denied" });
    }

    try {
      const [roles] = await req.db.query("SELECT * FROM roles WHERE id = ?", [
        req.params.id,
      ]);
      if (roles.length === 0) {
        return res.status(404).json({ error: "Role not found" });
      }

      const [perms] = await req.db.query(
        "SELECT permission_id FROM role_permissions WHERE role_id = ?",
        [req.params.id],
      );

      res.json({
        ...roles[0],
        permission_ids: perms.map((p) => p.permission_id),
      });
    } catch (error) {
      console.error("Error fetching role:", error);
      res.status(500).json({ error: "Server error" });
    }
  },
);

// Create a new role
app.post(
  "/api/roles",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    if (req.user.role !== "admin") {
      return res.status(403).json({ error: "Access denied" });
    }

    try {
      const { name, description } = req.body;
      if (!name || name.trim() === "") {
        return res.status(400).json({ error: "Role name is required" });
      }

      const [existing] = await req.db.query(
        "SELECT id FROM roles WHERE name = ?",
        [name],
      );
      if (existing.length > 0) {
        return res.status(400).json({ error: "Role name already exists" });
      }

      const [result] = await req.db.query(
        "INSERT INTO roles (name, description, is_system, tenant_id) VALUES (?, ?, 0, ?) RETURNING id",
        [name.trim(), description || null, req.user.tenant_id],
      );

      res.json({ id: result[0].id, message: "Role created" });
    } catch (error) {
      console.error("Error creating role:", error);
      res.status(500).json({ error: "Server error" });
    }
  },
);

// Update role name/description
app.put(
  "/api/roles/:id",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    if (req.user.role !== "admin") {
      return res.status(403).json({ error: "Access denied" });
    }

    try {
      const { name, description } = req.body;

      const [roles] = await req.db.query(
        "SELECT is_system FROM roles WHERE id = ?",
        [req.params.id],
      );
      if (roles.length === 0) {
        return res.status(404).json({ error: "Role not found" });
      }

      const [adminRole] = await req.db.query(
        "SELECT id FROM roles WHERE name = 'admin' LIMIT 1",
      );
      if (adminRole.length > 0 && adminRole[0].id === parseInt(req.params.id)) {
        return res
          .status(400)
          .json({ error: "The admin role cannot be deleted" });
      }

      await req.db.query(
        "UPDATE roles SET name = ?, description = ? WHERE id = ?",
        [name, description || null, req.params.id],
      );

      res.json({ message: "Role updated" });
    } catch (error) {
      console.error("Error updating role:", error);
      res.status(500).json({ error: "Server error" });
    }
  },
);

// Delete a role
app.delete(
  "/api/roles/:id",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    if (req.user.role !== "admin") {
      return res.status(403).json({ error: "Access denied" });
    }

    try {
      const [roles] = await req.db.query(
        "SELECT is_system FROM roles WHERE id = ?",
        [req.params.id],
      );
      if (roles.length === 0) {
        return res.status(404).json({ error: "Role not found" });
      }

      if (roles[0].is_system) {
        return res
          .status(400)
          .json({ error: "System roles cannot be deleted" });
      }

      const [users] = await req.db.query(
        "SELECT COUNT(*) AS count FROM users WHERE role_id = ?",
        [req.params.id],
      );
      if (users[0].count > 0) {
        return res.status(400).json({
          error: `Cannot delete: ${users[0].count} user(s) are assigned to this role`,
        });
      }

      await req.db.query("DELETE FROM roles WHERE id = ?", [req.params.id]);
      res.json({ message: "Role deleted" });
    } catch (error) {
      console.error("Error deleting role:", error);
      res.status(500).json({ error: "Server error" });
    }
  },
);

app.put(
  "/api/roles/:id/permissions",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    if (req.user.role !== "admin") {
      return res.status(403).json({ error: "Access denied" });
    }

    try {
      const { permission_ids } = req.body;
      if (!Array.isArray(permission_ids)) {
        return res
          .status(400)
          .json({ error: "permission_ids must be an array" });
      }

      const [roles] = await req.db.query("SELECT id FROM roles WHERE id = ?", [
        req.params.id,
      ]);
      if (roles.length === 0) {
        return res.status(404).json({ error: "Role not found" });
      }

      await req.db.query("DELETE FROM role_permissions WHERE role_id = ?", [
        req.params.id,
      ]);

      if (permission_ids.length > 0) {
        const placeholders = permission_ids.map(() => "(?, ?, ?)").join(", ");
        const flatParams = [];
        for (const pid of permission_ids) {
          flatParams.push(req.params.id, pid, req.user.tenant_id);
        }
        await req.db.query(
          `INSERT INTO role_permissions (role_id, permission_id, tenant_id) VALUES ${placeholders}`,
          flatParams,
        );
      }

      res.json({ message: "Permissions updated" });
    } catch (error) {
      console.error("Error updating permissions:", error);
      res.status(500).json({ error: "Server error" });
    }
  },
);

// Get the current user's permissions (for the Flutter app)
app.get(
  "/api/my-permissions",
  authenticateToken,
  setTenantContext,
  async (req, res) => {
    try {
      const [rows] = await req.db.query(
        `
            SELECT p.code
            FROM role_permissions rp
            JOIN permissions p ON rp.permission_id = p.id
            JOIN users u ON u.role_id = rp.role_id
            WHERE u.id = ?
        `,
        [req.user.id],
      );

      const codes = rows.map((r) => r.code);
      res.json({ permissions: codes });
    } catch (error) {
      console.error("Error fetching my permissions:", error);
      res.status(500).json({ error: "Server error" });
    }
  },
);


// ==================== START SERVER ====================

app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
    console.log(`   Test API: http://localhost:${PORT}/api/test (needs token)`);
    console.log(`   Login: http://localhost:${PORT}/api/login`);
});