import 'dotenv/config';
import express from 'express';
import fs from 'fs';
// import { createServer as createViteServer } from 'vite';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { createProxyMiddleware } from 'http-proxy-middleware';
import path from 'path';
import { fileURLToPath } from 'url';
import ccxt, { binance, bitget } from 'ccxt';
import { PassThrough } from 'stream';
import { WebSocketServer, WebSocket } from 'ws';
import crypto from 'crypto';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ============================================================
// 🔥 AES-256-GCM SECURITY MODULE
// ============================================================
const ENCRYPTION_MASTER_KEY = process.env.ENCRYPTION_MASTER_KEY || crypto.randomBytes(32).toString('hex');

function encryptAPIKey(text: string): string {
  if (!text) return text;
  if (text.startsWith('ENC:')) return text; // already encrypted
  try {
    const iv = crypto.randomBytes(12);
    // Ensure key is exactly 32 bytes (256 bits)
    const keyString = ENCRYPTION_MASTER_KEY.padEnd(64, '0').slice(0, 64);
    const key = Buffer.from(keyString, 'hex');
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag().toString('hex');
    return `ENC:${iv.toString('hex')}:${authTag}:${encrypted}`;
  } catch (error) {
    console.error('[Security] Encryption failed:', error);
    return text; // Fallback to raw if encrypt fails
  }
}

function decryptAPIKey(encryptedText: string): string {
  if (!encryptedText || !encryptedText.startsWith('ENC:')) return encryptedText;
  try {
    const parts = encryptedText.split(':');
    if (parts.length !== 4) return encryptedText;
    const [_, ivHex, authTagHex, cipherText] = parts;
    const iv = Buffer.from(ivHex, 'hex');
    const authTag = Buffer.from(authTagHex, 'hex');
    const keyString = ENCRYPTION_MASTER_KEY.padEnd(64, '0').slice(0, 64);
    const key = Buffer.from(keyString, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(authTag);
    let decrypted = decipher.update(cipherText, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch (error) {
    console.error('[Security] Decryption failed:', error);
    return ''; // Return empty string to prevent sending garbage to CCXT
  }
}

// ============================================================
// 🔥 PAYMENT GATEWAY (XENDIT & STRIPE HYBRID)
// ============================================================
// Xendit untuk lokal IDR, Stripe untuk Global USD
import Stripe from 'stripe';

let stripeClient: Stripe | null = null;
function getStripe(): Stripe {
  if (!stripeClient) {
    const key = process.env.STRIPE_SECRET_KEY || 'sk_test_dummy';
    stripeClient = new Stripe(key, { apiVersion: '2023-10-16' }); 
  }
  return stripeClient;
}


// ============================================================
// 🔥 GLOBAL STATE FOR ACTIVE ORDERS & DIAGNOSTICS
// ============================================================
const activeTrailingOrders = new Map<string, any>();
const activeAlgoOrders = new Map<string, any>();
const webhookLogs: any[] = [];

function addWebhookLog(gateway: string, type: string, status: string, details: any) {
  webhookLogs.push({
    timestamp: new Date().toISOString(),
    gateway,
    type,
    status,
    details
  });
  if (webhookLogs.length > 50) webhookLogs.shift();
}

// Helper function for rounding to tick size
function roundToTick(value: number, tickSize: number): number {
  if (!value || isNaN(value) || !tickSize || tickSize === 0) return value;
  const factor = 1 / tickSize;
  const rounded = Math.round(value * factor) / factor;
  
  let decimals = 0;
  const tickStr = tickSize.toString();
  if (tickStr.includes('e')) {
    decimals = Math.abs(parseInt(tickStr.split('e')[1]));
  } else if (tickStr.includes('.')) {
    decimals = tickStr.split('.')[1].length;
  }
  
  return parseFloat(rounded.toFixed(decimals));
}

/**
 * Cara profesional (strict) untuk normalisasi simbol
 */
function normalizeSymbol(symbol: any): string {
  if (symbol === undefined || symbol === null) {
    return "";
  }
  
  let s = "";
  try {
    if (typeof symbol === "string") {
      s = symbol.trim();
    } else if (typeof symbol === "number") {
      s = String(symbol).trim();
    } else if (symbol && typeof symbol === "object") {
      s = symbol.symbol || symbol.instId || "";
      if (typeof s === "string") s = s.trim();
    } else {
      return "";
    }
  } catch (err) {
    return "";
  }
  
  if (!s || s === "") {
    return "";
  }
  
  try {
    s = s.toUpperCase();
  } catch (err) {
    return "";
  }
  
  try {
    const parts = s.split(/[/\-:_]/);
    if (parts.length > 0 && parts[0] && typeof parts[0] === "string" && parts[0] !== "") {
      s = parts[0];
    } else {
      s = s.replace(/[/\-:_]/g, "");
    }
  } catch (err) {
    return "";
  }
  
  if (typeof s !== "string") {
    return "";
  }
  
  try {
    if (s.length > 0) {
      s = s.replace(/_UMCBL/g, "")
           .replace(/_SUMCBL/g, "")
           .replace(/-PERP/g, "")
           .replace(/-SWAP/g, "")
           .replace(/USDT/g, "")
           .replace(/USD/g, "");
    }
  } catch (replaceError) {
    return "";
  }
  
  try {
    const result = s.replace(/[/\-:_]/g, "").replace(/[^A-Z0-9]/g, "");
    return result || "";
  } catch (err) {
    return "";
  }
}

/**
 * Sanitizer Layer (LEVEL PRO)
 */
function normalizeBitgetPlanOrder(order: any, defaultPlanType: string) {
  if (!order || typeof order !== 'object') {
    return null;
  }

  let rawSymbol = null;
  
  if (order.symbol && typeof order.symbol === 'string' && order.symbol.trim()) {
    rawSymbol = order.symbol;
  } else if (order.instId && typeof order.instId === 'string' && order.instId.trim()) {
    rawSymbol = order.instId;
  } else if (order.instId && typeof order.instId === 'object' && order.instId.symbol) {
    rawSymbol = order.instId.symbol;
  } else if (order.symbol && typeof order.symbol === 'object' && order.symbol.value) {
    rawSymbol = order.symbol.value;
  }
  
  if (!rawSymbol || typeof rawSymbol !== 'string') {
    return null;
  }
  
  const cleanSymbol = normalizeSymbol(rawSymbol);
  if (!cleanSymbol || cleanSymbol === "") {
    return null;
  }
  
  const safeExtract = (field: any, defaultValue: any = '') => {
    if (field === undefined || field === null) return defaultValue;
    if (typeof field === 'string') return field;
    if (typeof field === 'number') return String(field);
    return defaultValue;
  };
  
  const pType = safeExtract(order.planType || order.plan_type, defaultPlanType);
  const isTrailing = pType === 'track_plan';
  
  return {
    id: safeExtract(order.orderId || order.order_id),
    symbol: cleanSymbol,
    type: isTrailing ? 'trailing_stop' : safeExtract(order.orderType || order.order_type),
    side: safeExtract(order.side),
    price: safeExtract(order.price),
    stopPrice: safeExtract(order.triggerPrice || order.trigger_price),
    amount: safeExtract(order.size, '0'),
    status: safeExtract(order.planStatus || order.plan_status, 'pending'),
    orderType: isTrailing ? 'trailing' : 'plan',
    planType: pType,
    triggerType: safeExtract(order.triggerType || order.trigger_type),
    positionSide: safeExtract(order.posSide || order.positionSide || order.position_side),
    executePrice: safeExtract(order.executePrice || order.execute_price),
    cTime: safeExtract(order.cTime || order.c_time),
    tradeSide: safeExtract(order.tradeSide || order.trade_side, 'open').toLowerCase(),
    callbackRatio: safeExtract(order.callbackRatio || order.callback_ratio),
    callback_rate: safeExtract(order.callbackRatio || order.callback_ratio),
    isTrailing: isTrailing
  };
}

function mapBitgetStatus(state: string): string {
  if (!state || typeof state !== "string") {
    return "unknown";
  }
  
  const statusMap: { [key: string]: string } = {
    'new': 'open',
    'live': 'open',
    'filled': 'closed',
    'cancelled': 'canceled',
    'partially_filled': 'open',
    'pending': 'open',
    'partially_canceled': 'canceled'
  };
  return statusMap[state] || state;
}

// ============================================================
// FUNGSI FINAL TRAILING STOP (BITGET ONLY)
// ============================================================
async function createBitgetTrailingStop({
  ex,
  symbol,
  positionSide,
  filledSize,
  entryPrice,
  callbackRate,
  marginMode = 'crossed',
  tradeSide = 'close'
}: any) {
  if (!symbol) {
    console.warn("[Server] createBitgetTrailingStop called with empty symbol");
    throw new Error("SYMBOL_REQUIRED");
  }

  if (!entryPrice || entryPrice <= 0) {
    throw new Error("INVALID_ENTRY_PRICE");
  }

  if (callbackRate < 0.1 || callbackRate > 10) {
    throw new Error(`INVALID_CALLBACK: ${callbackRate}% (allowed 0.1 - 10)`);
  }

  const market = ex.market(symbol);
  const minSize = market?.limits?.amount?.min || 1;
  const size = Math.floor(filledSize);

  if (size < minSize) {
    throw new Error(`SIZE_TOO_SMALL: ${size} < ${minSize}`);
  }

  let cleanSymbol = normalizeSymbol(symbol);
  if (cleanSymbol.includes(':')) {
    cleanSymbol = cleanSymbol.split(':')[0];
  }
  cleanSymbol = cleanSymbol.replace('/', '').toUpperCase();

  const productType = market?.info?.productType || 'USDT-FUTURES';
  const marginCoin = market?.info?.marginCoin || 'USDT';

  let side = 'buy';
  if (positionSide === 'LONG') {
    side = tradeSide === 'open' ? 'buy' : 'sell';
  } else {
    side = tradeSide === 'open' ? 'sell' : 'buy';
  }

  const callbackRatio = (callbackRate / 100).toString();
  const triggerPrice = ex.priceToPrecision(symbol, entryPrice);

  const params = {
    planType: 'track_plan',
    symbol: cleanSymbol,
    productType,
    marginCoin,
    marginMode: marginMode === 'crossed' ? 'cross' : marginMode,
    size: size.toString(),
    callbackRatio,
    triggerPrice,
    price: "",
    triggerType: 'mark_price',
    side,
    tradeSide,
    orderType: 'market',
    clientOid: `ts_${Date.now()}`
  };

  console.log('[TRAILING FINAL PARAMS]', JSON.stringify(params, null, 2));

  const res = await ex.request('v2/mix/order/place-plan-order', 'private', 'POST', params);

  if (res?.code !== '00000') {
    throw new Error(`BITGET_TRAILING_FAILED: ${res?.msg}`);
  }

  return res.data?.orderId;
}

// ============================================================
// MAIN SERVER FUNCTION
// ============================================================
async function startServer() {
  const app = express();
  app.set('trust proxy', 1); // Trust first proxy for express-rate-limit
  const PORT = process.env.PORT || 3000;

  // Anti-DDoS & Security Headers
  app.use(helmet({
    contentSecurityPolicy: false, // Let Vite/Tauri handle CSP
    crossOriginEmbedderPolicy: false
  }));

  const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100000, // Very high limit
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many requests from this IP, please try again later.' },
    validate: { xForwardedForHeader: false, trustProxy: false }
  });
  
  app.use('/api', globalLimiter);

  // Stricter rate limit for trading and exchange-related APIs
  const tradingLimiter = rateLimit({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 50000, // Very high limit
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many requests to trading API from this IP, please try again later.' },
    validate: { xForwardedForHeader: false, trustProxy: false }
  });
  
  app.use('/api/portal', tradingLimiter);

  app.use(cors({
    origin: (origin, callback) => {
      callback(null, origin || '*');
    },
    credentials: true,
    methods: ['GET', 'POST', 'OPTIONS', 'PUT', 'PATCH', 'DELETE'],
    allowedHeaders: ['*'],
    exposedHeaders: ['*'],
    maxAge: 86400
  }));

  app.options(/.*/, cors());
  // ===================================
  // STRIPE WEBHOOK (MUST BE BEFORE express.json())
  // ===================================
  app.post('/api/webhooks/stripe', express.raw({type: 'application/json'}), async (req, res) => {
    console.log('[Stripe Webhook] Received event');
    const sig = req.headers['stripe-signature'];
    const endpointSecret = process.env.STRIPE_WEBHOOK_SECRET?.trim();

    let event;
    try {
      if (!endpointSecret) {
        console.error('[Stripe Webhook] Missing STRIPE_WEBHOOK_SECRET');
        addWebhookLog('stripe', 'unknown', 'error', 'Missing STRIPE_WEBHOOK_SECRET');
        return res.status(400).send("Missing STRIPE_WEBHOOK_SECRET");
      }
      const stripe = getStripe();
      event = stripe.webhooks.constructEvent(req.body, sig as string, endpointSecret);
    } catch (err: any) {
      console.error(`[Stripe Webhook] Error:`, err.message);
      addWebhookLog('stripe', 'unknown', 'error', `Construct Error: ${err.message}`);
      return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    addWebhookLog('stripe', event.type, 'received', { id: event.id });

    if (event.type === 'checkout.session.completed') {
      const session = event.data.object as any;
      const userId = session.metadata?.userId;
      const planId = session.metadata?.planId || 'premium';

      if (userId) {
        if (process.env.SUPABASE_SERVICE_ROLE_KEY) {
          try {
            const { createClient } = await import('@supabase/supabase-js');
            const supabaseUrl = process.env.VITE_SUPABASE_URL || '';
            const supabase = createClient(supabaseUrl, process.env.SUPABASE_SERVICE_ROLE_KEY);
            
            const { error: profileError } = await supabase.from('profiles').update({
              plan_tier: planId,
              subscription_status: 'active',
              stripe_customer_id: session.customer
            }).eq('id', userId);

            if (profileError) {
               console.error('[Stripe Webhook] Error updating profile:', profileError);
               // Try a fallback update with fewer fields in case stripe_customer_id column is missing
               const { error: fallbackError } = await supabase.from('profiles').update({
                  plan_tier: planId,
                  subscription_status: 'active'
                 }).eq('id', userId);
               if (fallbackError) console.error('[Stripe Webhook] Fallback profile update also failed:', fallbackError);
            }

            const { error: paymentError } = await supabase.from('payment_history').insert({
              user_id: userId,
              gateway: 'stripe',
              transaction_id: session.id,
              amount: session.amount_total ? session.amount_total / 100 : 0,
              currency: session.currency?.toUpperCase() || 'USD',
              status: 'paid',
              description: `Checkout for ${planId}`
            });
            if (paymentError) console.error('[Stripe Webhook] Error inserting payment history:', paymentError);

            console.log(`[Stripe Webhook] Process finished for user ${userId} to plan ${planId}`);
          } catch (dbErr) {
            console.error('[Stripe Webhook] Database update failed:', dbErr);
          }
        } else {
            console.error('[Stripe Webhook] FATAL: Missing SUPABASE_SERVICE_ROLE_KEY in environment block! Database cannot be updated.');
        }
      } else {
        console.warn(`[Stripe Webhook] Received webhook but no userId in metadata.`);
      }
    }

    res.json({received: true});
  });

  app.use(express.json());

  // ===================================
  // 🔥 SECURITY ENCRYPTION ENDPOINT
  // ===================================
  app.post('/api/security/encrypt', async (req, res) => {
    try {
      const { payload } = req.body;
      if (!payload || typeof payload !== 'object') {
        return res.status(400).json({ error: 'Invalid payload' });
      }
      const encryptedPayload: any = {};
      for (const [key, value] of Object.entries(payload)) {
        if (typeof value === 'string' && value && !value.startsWith('ENC:')) {
          encryptedPayload[key] = encryptAPIKey(value);
        } else {
          encryptedPayload[key] = value;
        }
      }
      res.json({ success: true, data: encryptedPayload });
    } catch (error: any) {
      console.error('[Security API] Encrypt failed:', error);
      res.status(500).json({ error: error.message });
    }
  });

  // URL rewrite middleware for backward compatibility with stale browser tabs
  app.use((req, res, next) => {
    if (req.url.startsWith('/api/broker/')) {
      req.url = req.url.replace('/api/broker/', '/api/portal/');
    } else if (req.url.startsWith('/api/exchange/')) {
      req.url = req.url.replace('/api/exchange/', '/api/portal/');
    } else if (req.url.startsWith('/api/terminal/')) {
      req.url = req.url.replace('/api/terminal/', '/api/portal/');
    } else if (req.url.startsWith('/api/market-data/')) {
      req.url = req.url.replace('/api/market-data/', '/api/datafeed/');
    } else if (req.url.startsWith('/api/metrics/')) {
      req.url = req.url.replace('/api/metrics/', '/api/datafeed/');
    }
    next();
  });

  app.get("/api/health", (req, res) => {
    res.json({ 
      status: "ok", 
      uptime: process.uptime(),
      memory: process.memoryUsage(),
      env: process.env.NODE_ENV
    });
  });

  // ===================================
  // STRIPE BILLING (GLOBAL PAYMENT)
  // ===================================
  app.post("/api/stripe/create-portal-session", async (req, res) => {
    try {
      const stripe = getStripe();
      const { email, returnUrl } = req.body;
      
      let customerId = req.body.customerId;
      if (!customerId && email) {
        const customers = await stripe.customers.list({ email: email, limit: 1 });
        if (customers.data.length > 0) {
          customerId = customers.data[0].id;
        } else {
          const newCustomer = await stripe.customers.create({ email: email, description: 'AI Studio Global Customer' });
          customerId = newCustomer.id;
        }
      }

      if (!customerId) {
        const newCustomer = await stripe.customers.create({ description: 'AI Studio Global Anonymous Customer' });
        customerId = newCustomer.id;
      }

      const portalSession = await stripe.billingPortal.sessions.create({
        customer: customerId,
        return_url: returnUrl || req.headers.origin || 'http://localhost:3000',
      });

      res.json({ url: portalSession.url });
    } catch (error: any) {
      console.error('[Stripe] Portal Error:', error);
      res.status(500).json({ error: error.message || 'Failed to create Stripe portal session' });
    }
  });

  // ===================================
  // STRIPE CHECKOUT (GLOBAL PAYMENT)
  // ===================================
  app.post("/api/payment/stripe-checkout", async (req, res) => {
    try {
      const stripe = getStripe();
      const { email, amount, description, userId, planId, successUrl, cancelUrl } = req.body;
      
      const origin = req.headers.origin || `${req.protocol}://${req.get('host')}`;
      
      const session = await stripe.checkout.sessions.create({
        payment_method_types: ['card'],
        customer_email: email || undefined,
        metadata: {
          userId: userId || '',
          planId: planId || ''
        },
        line_items: [{
          price_data: {
            currency: 'usd',
            product_data: {
              name: description || 'CryptoFlow Nexus Subscription',
            },
            unit_amount: amount ? Math.round(amount * 100) : 7999, // in cents
          },
          quantity: 1,
        }],
        mode: 'payment',
        success_url: successUrl || (origin + '?payment=success&provider=stripe&session_id={CHECKOUT_SESSION_ID}'),
        cancel_url: cancelUrl || (origin + '?payment=canceled'),
      });

      res.json({ url: session.url });
    } catch (error: any) {
      console.error('[Stripe] Checkout Error:', error);
      res.status(500).json({ error: error.message || 'Failed to create Stripe checkout session' });
    }
  });

  // ===================================
  // XENDIT INVOICE (INDONESIA PAYMENT)
  // ===================================
  app.post("/api/payment/xendit-invoice", async (req, res) => {
    try {
      const { email, amount, description, userId, planId, successUrl, cancelUrl } = req.body;
      const key = process.env.XENDIT_SECRET_KEY || "xnd_development_dummy"; 
      
      const origin = req.headers.origin || `${req.protocol}://${req.get('host')}`;
      const externalId = `inv-nexus-${Date.now()}-${userId || 'guest'}`;

      const response = await fetch('https://api.xendit.co/v2/invoices', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Basic ${Buffer.from(key + ':').toString('base64')}`
        },
        body: JSON.stringify({
          external_id: externalId,
          amount: amount || 150000,
          payer_email: email || 'user@example.com',
          description: description || 'Langganan CryptoFlow Nexus Pro (1 Bulan)',
          currency: 'IDR',
          customer_notification_preference: {
            invoice_created: ['email', 'whatsapp'],
            invoice_reminder: ['email', 'whatsapp'],
            invoice_paid: ['email', 'whatsapp']
          },
          success_redirect_url: successUrl ? successUrl.replace('XENDIT_EXTERNAL_ID_PLACEHOLDER', externalId) : (origin + `?payment=success&provider=xendit&external_id=${externalId}`),
          failure_redirect_url: cancelUrl || (origin + '?payment=canceled'),
          metadata: {
            userId: userId || '',
            planId: planId || ''
          }
        })
      });

      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.message || 'Gagal membuat Invoice Xendit');
      }

      res.json({ url: data.invoice_url });
    } catch (error: any) {
      console.error('[Xendit] Invoice Error:', error);
      res.status(500).json({ error: error.message || 'Terjadi kesalahan saat memproses pembayaran Xendit' });
    }
  });

  // ===================================
  // XENDIT WEBHOOK
  // ===================================
  // XENDIT WEBHOOK
  // ===================================
  app.post('/api/webhooks/xendit', async (req, res) => {
    console.log('[Xendit Webhook] Received webhook');
    
    // Validate Xendit Token
    const xenditToken = process.env.XENDIT_WEBHOOK_TOKEN?.trim();
    const reqToken = req.headers['x-callback-token'];

    if (xenditToken && reqToken !== xenditToken) {
      console.error('[Xendit Webhook] INVALID TOKEN DETECTED', { 
         expected: xenditToken ? 'SET' : 'NOT_SET', 
         received: reqToken ? 'SET' : 'NOT_SET' 
      });
      addWebhookLog('xendit', 'callback', 'error', 'Invalid Token');
      return res.status(403).json({ error: 'Unauthorized webhook' });
    }

    const invoice = req.body;
    addWebhookLog('xendit', 'paid', 'received', { id: invoice?.id, external_id: invoice?.external_id, status: invoice?.status });
    
    // Accept it to prevent retries
    res.json({ received: true });

    if (invoice.status === 'PAID') {
      const userId = invoice.metadata?.userId;
      const planId = (invoice.metadata?.planId || 'premium').toLowerCase();

      console.log(`[Xendit Webhook] Processing payment for User: ${userId}, Plan: ${planId}`);

      if (userId) {
        if (process.env.SUPABASE_SERVICE_ROLE_KEY) {
           try {
              const { createClient } = await import('@supabase/supabase-js');
              const supabaseUrl = process.env.VITE_SUPABASE_URL || '';
              const supabase = createClient(supabaseUrl, process.env.SUPABASE_SERVICE_ROLE_KEY);
              
              // Force lowercase for plan_tier to match frontend logic
              const { error: profileError } = await supabase.from('profiles').update({
                plan_tier: planId,
                subscription_status: 'active',
                xendit_customer_id: invoice.customer_id || 'xendit-guest',
                updated_at: new Date().toISOString()
              }).eq('id', userId);

              if (profileError) {
                 console.error('[Xendit Webhook] Error updating profile:', profileError);
                 // Fallback without xendit_customer_id in case column is missing
                 const { error: fallbackError } = await supabase.from('profiles').update({
                    plan_tier: planId,
                    subscription_status: 'active'
                   }).eq('id', userId);
                 if (fallbackError) console.error('[Xendit Webhook] Fallback profile update also failed:', fallbackError);
              }

              const { error: paymentError } = await supabase.from('payment_history').insert({
                user_id: userId,
                gateway: 'xendit',
                transaction_id: invoice.id,
                amount: invoice.amount,
                currency: 'IDR',
                status: 'paid',
                description: `Invoice ${invoice.external_id} Paid`
              });
              if (paymentError) console.error('[Xendit Webhook] Error inserting payment history:', paymentError);

              console.log(`[Xendit Webhook] Process finished for user ${userId}`);
           } catch (dbErr) {
              console.error('[Xendit Webhook] Database update failed:', dbErr);
           }
        } else {
           console.error('[Xendit Webhook] FATAL: Missing SUPABASE_SERVICE_ROLE_KEY in environment block! Database cannot be updated.');
        }
      } else {
         console.warn('[Xendit Webhook] Received paid status but no userId in metadata.');
      }
    }
  });

  // ===================================
  // VERIFY PAYMENT FROM SUCCESS REDIRECT (Client Fallback)
  // ===================================
  app.get('/api/payment/verify', async (req, res) => {
    try {
      const { provider, session_id, external_id } = req.query;

      if (!process.env.SUPABASE_SERVICE_ROLE_KEY) {
        return res.status(500).json({ error: 'Supabase Server Credentials Missing' });
      }

      const { createClient } = await import('@supabase/supabase-js');
      const supabaseUrl = process.env.VITE_SUPABASE_URL || '';
      const supabase = createClient(supabaseUrl, process.env.SUPABASE_SERVICE_ROLE_KEY);

      if (provider === 'stripe' && session_id) {
        const stripe = getStripe();
        const session = await stripe.checkout.sessions.retrieve(session_id as string);
        if (session && session.payment_status === 'paid') {
          const userId = session.metadata?.userId;
          const planId = session.metadata?.planId;
          if (userId && planId) {
            const { error: updateErr } = await supabase.from('profiles').update({
              plan_tier: planId,
              subscription_status: 'active',
              stripe_customer_id: session.customer as string
            }).eq('id', userId);

            if (updateErr) {
               console.error('[Verify API Error] Failed to update profiles in DB:', updateErr);
               return res.status(500).json({ error: `Database update failed: ${updateErr.message}` });
            }

            // Insert into payment history
            await supabase.from('payment_history').insert({
              user_id: userId,
              gateway: 'stripe',
              transaction_id: session.id,
              amount: session.amount_total ? session.amount_total / 100 : 0,
              currency: session.currency?.toUpperCase() || 'USD',
              status: 'paid',
              description: `Subscription Upgrade to ${planId.toUpperCase()}`
            });
            
            // Also log to webhook logs for diagnostic visibility
            addWebhookLog('stripe', 'client-verify', 'success', { session_id, planId, userId });
            return res.json({ success: true, verified: true, plan_tier: planId });
          }
        }
      } else if (provider === 'xendit' && external_id) {
        const key = process.env.XENDIT_SECRET_KEY || "xnd_development_dummy"; 
        const response = await fetch(`https://api.xendit.co/v2/invoices?external_id=${external_id}`, {
          method: 'GET',
          headers: {
            'Authorization': `Basic ${Buffer.from(key + ':').toString('base64')}`
          }
        });
        const data = await response.json();
        
        if (data && data.length > 0) {
           const matchingInvoice = data.find((inv: any) => inv.status === 'PAID');
           if (matchingInvoice) {
              const userId = matchingInvoice.metadata?.userId;
              const planId = (matchingInvoice.metadata?.planId || 'premium').toLowerCase();
              if (userId && planId) {
                const { error: updateErr } = await supabase.from('profiles').update({
                  plan_tier: planId,
                  subscription_status: 'active',
                  updated_at: new Date().toISOString()
                }).eq('id', userId);

                if (updateErr) {
                   console.error('[Verify API Error] Failed to update profiles in DB:', updateErr);
                   return res.status(500).json({ error: `Database update failed: ${updateErr.message}` });
                }

                // Insert into payment history
                await supabase.from('payment_history').insert({
                  user_id: userId,
                  gateway: 'xendit',
                  transaction_id: matchingInvoice.id,
                  amount: matchingInvoice.amount,
                  currency: 'IDR',
                  status: 'paid',
                  description: `Subscription Upgrade to ${planId.toUpperCase()}`
                });
                
                addWebhookLog('xendit', 'client-verify', 'success', { external_id, planId, userId });
                return res.json({ success: true, verified: true, plan_tier: planId });
              }
           }
        }
      }
      
      return res.json({ success: true, verified: false });
    } catch (err: any) {
      console.error('[Verify API Error]:', err);
      res.status(500).json({ error: err.message });
    }
  });

  // ===================================
  // PAYMENT HISTORY API
  // ===================================
  app.post('/api/payment/history', async (req, res) => {
     try {
       const { userId } = req.body;
       if (!userId || !process.env.SUPABASE_SERVICE_ROLE_KEY) {
         return res.json({ history: [] }); // Empty fallback
       }
       
       const { createClient } = await import('@supabase/supabase-js');
       const supabaseUrl = process.env.VITE_SUPABASE_URL || '';
       const supabase = createClient(supabaseUrl, process.env.SUPABASE_SERVICE_ROLE_KEY);
       
       const { data, error } = await supabase
         .from('payment_history')
         .select('*')
         .eq('user_id', userId)
         .order('created_at', { ascending: false });
         
       if (error) throw error;
       res.json({ history: data || [] });
     } catch (err: any) {
       console.error('[Payment History] Error:', err);
       res.status(500).json({ error: 'Failed to fetch payment history' });
     }
  });

  app.use((req, res, next) => {
    if (req.path.startsWith('/api')) {
      console.log(`[Server] ${req.method} ${req.path}`);
    }
    next();
  });

  const SUPABASE_ANON_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImFueHhoeWpkanh4eGN2YWR5amprIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzAxOTY5MjgsImV4cCI6MjA4NTc3MjkyOH0.tFDUHWXMdzblk-uy91qipUeQJghU2JR0hC2oy5BhHE4";

  // --- AI & Supabase Proxy Endpoints ---
  app.use('/api/supabase', createProxyMiddleware({
    target: 'https://anyxhyjdjxxxcvadyjjk.supabase.co',
    changeOrigin: true,
    secure: false,
    pathRewrite: { '^/api/supabase': '' },
    onProxyReq: (proxyReq, req) => {
      proxyReq.setHeader('apikey', SUPABASE_ANON_KEY);
      proxyReq.setHeader('Authorization', `Bearer ${SUPABASE_ANON_KEY}`);
      proxyReq.setHeader('Origin', 'https://anyxhyjdjxxxcvadyjjk.supabase.co');
      proxyReq.setHeader('Referer', 'https://anyxhyjdjxxxcvadyjjk.supabase.co/');
    }
  }));

  app.use('/api/ai/openai', createProxyMiddleware({
    target: 'https://api.openai.com/v1',
    changeOrigin: true,
    pathRewrite: { '^/api/ai/openai': '' },
    onProxyReq: (proxyReq, req) => {
      const auth = req.headers['authorization'];
      if (auth) proxyReq.setHeader('Authorization', auth);
      proxyReq.setHeader('Origin', 'https://api.openai.com');
      proxyReq.setHeader('Referer', 'https://api.openai.com/');
    }
  }));

  app.use('/api/ai/grok', createProxyMiddleware({
    target: 'https://api.x.ai/v1',
    changeOrigin: true,
    pathRewrite: { '^/api/ai/grok': '' },
    onProxyReq: (proxyReq, req) => {
      const auth = req.headers['authorization'];
      if (auth) proxyReq.setHeader('Authorization', auth);
      proxyReq.setHeader('Origin', 'https://api.x.ai');
      proxyReq.setHeader('Referer', 'https://api.x.ai/');
    }
  }));

  app.use('/api/ai/deepseek', createProxyMiddleware({
    target: 'https://api.deepseek.com',
    changeOrigin: true,
    pathRewrite: { '^/api/ai/deepseek': '' },
    onProxyReq: (proxyReq, req) => {
      const auth = req.headers['authorization'];
      if (auth) proxyReq.setHeader('Authorization', auth);
      proxyReq.setHeader('Origin', 'https://api.deepseek.com');
      proxyReq.setHeader('Referer', 'https://api.deepseek.com/');
    }
  }));

  // --- Exchange API Endpoints ---
  const exchangeCache = new Map<string, any>();
  const cmcCache = new Map<string, { data: any; timestamp: number }>();

  setInterval(() => {
    console.log('[Server] Clearing Exchange Cache (TTL)');
    exchangeCache.clear();
  }, 1000 * 60 * 10);
  
  const cryptocompareCache = new Map<string, { data: any; timestamp: number }>();
  const CMC_CACHE_TTL = 120000;
  const CRYPTOCOMPARE_CACHE_TTL = 300000;
  const initializationPromises = new Map<string, Promise<any>>();
  const failedExchanges = new Map<string, { ts: number, error: string }>();

  const getExchangeInstance = async (type: string, inputKeys: any) => {
    if (!inputKeys) throw new Error("Missing exchange keys");
    
    // 🔥 Securely decrypt keys memory-only before initiating connection
    const keys = { ...inputKeys };
    if (keys.apiKey) keys.apiKey = decryptAPIKey(keys.apiKey);
    if (keys.secret) keys.secret = decryptAPIKey(keys.secret);
    if (keys.password) keys.password = decryptAPIKey(keys.password); // Bitget passphrase

    const cacheKey = `${type}-${keys.apiKey}`;
    
    if (exchangeCache.has(cacheKey) && cacheKey !== `${type}-undefined` && cacheKey !== `${type}-`) {
      return exchangeCache.get(cacheKey);
    }

    const failure = failedExchanges.get(cacheKey);
    if (failure && Date.now() - failure.ts < 30000) {
      throw new Error(`Exchange ${type} recently failed: ${failure.error}. Retrying in ${Math.ceil((30000 - (Date.now() - failure.ts)) / 1000)}s`);
    }

    if (initializationPromises.has(cacheKey)) {
      return initializationPromises.get(cacheKey);
    }

    const initPromise = (async () => {
      let ex: any = null;
      const commonOptions = {
        timeout: 30000,
        enableRateLimit: true,
      };

      try {
        if (type === 'binance') {
          const BinanceClass = binance || (ccxt as any).binance;
          if (!BinanceClass) throw new Error('Binance class not found in ccxt');
          ex = new BinanceClass({
            apiKey: keys.apiKey,
            secret: keys.secret,
            ...commonOptions,
            options: { 
              defaultType: 'future',
              warnOnFetchOpenOrdersWithoutSymbol: false
            }
          });
        } else if (type === 'bitget') {
          const BitgetClass = bitget || (ccxt as any).bitget;
          if (!BitgetClass) throw new Error('Bitget class not found in ccxt');
          ex = new BitgetClass({
            apiKey: keys.apiKey,
            secret: keys.secret,
            password: keys.passphrase,
            ...commonOptions,
            options: { defaultType: 'swap' }
          });
        }

        if (ex) {
          console.log(`[Server] Loading markets for ${type}...`);
          const loadPromise = ex.loadMarkets();
          const timeoutPromise = new Promise((_, reject) => setTimeout(() => reject(new Error('Market load timeout')), 20000));
          await Promise.race([loadPromise, timeoutPromise]);
          
          exchangeCache.set(cacheKey, ex);
          failedExchanges.delete(cacheKey);
          return ex;
        }
        throw new Error(`Unsupported exchange type: ${type}`);
      } catch (e: any) {
        console.error(`[Server] Failed to initialize ${type} exchange:`, e.message);
        failedExchanges.set(cacheKey, { ts: Date.now(), error: e.message });
        throw e;
      } finally {
        initializationPromises.delete(cacheKey);
      }
    })();

    initializationPromises.set(cacheKey, initPromise);
    return initPromise;
  };

  const resolveSymbol = (ex: any, inputSymbol: any) => {
    if (inputSymbol === undefined || inputSymbol === null) {
      console.warn("[Server] resolveSymbol received undefined/null");
      return "";
    }
    if (typeof inputSymbol !== "string") {
      console.warn("[Server] resolveSymbol received non-string:", typeof inputSymbol);
      return "";
    }
    if (inputSymbol.trim() === "") {
      console.warn("[Server] resolveSymbol received empty string");
      return "";
    }
    
    const normalized = normalizeSymbol(inputSymbol);
    if (!normalized) {
      console.warn("[Server] resolveSymbol: normalizeSymbol returned empty for:", inputSymbol);
      return "";
    }
    
    const clean = normalized.replace(/\s*\(B\)$|\s*\(BG\)$/, '').replace(/[-/]/g, '').toUpperCase();
    if (!clean) {
      console.warn("[Server] resolveSymbol: clean symbol is empty for normalized:", normalized);
      return "";
    }
    
    const markets = ex.markets;
    if (!markets) {
      console.warn("[Server] resolveSymbol: markets not loaded");
      return inputSymbol;
    }
    
    const usdtPerp = `${clean}/USDT:USDT`;
    if (markets[usdtPerp]) return usdtPerp;

    const usdtPair = `${clean}/USDT`;
    if (markets[usdtPair]) return usdtPair;

    const usdtDirect = `${clean}USDT`;
    if (markets[usdtDirect]) return usdtDirect;

    if (markets[inputSymbol]) return inputSymbol;

    const marketKeys = Object.keys(markets);
    const fuzzyUSDT = marketKeys.find(k => {
      if (!k.includes('USDT')) return false;
      const normalizedK = normalizeSymbol(k);
      if (!normalizedK) return false;
      const cleaned = normalizedK.replace(/[:/]/g, '').toUpperCase();
      return cleaned && clean && cleaned.startsWith(clean);
    });
    
    return fuzzyUSDT || inputSymbol;
  };

  // --- Bitget Strategy & Plan Orders Endpoints ---
  app.post('/api/portal/bitget-trailing', async (req, res) => {
    try {
      const order = req.body.order || req.body;
      const { symbol, side, size, quantity, callbackRatio, callbackRate, triggerPrice, triggerType } = order;
      const keys = req.body.keys || order.keys;
      const ex = await getExchangeInstance('bitget', keys);
      if (!ex) throw new Error("Invalid exchange");

      const qty = quantity || size;
      const cbRate = callbackRate || (callbackRatio ? parseFloat(callbackRatio) * 100 : 0);

      const orderId = await createBitgetTrailingStop({
        ex,
        symbol,
        positionSide: side === 'buy' ? 'LONG' : 'SHORT',
        filledSize: qty,
        entryPrice: triggerPrice,
        callbackRate: cbRate,
        tradeSide: 'open'
      });

      res.json({ success: true, orderId });
    } catch (error: any) {
      console.error("[Server API] Bitget Trailing Error:", error.message);
      res.status(500).json({ error: error.message });
    }
  });

  // 🔥 FIXED: Binance Trailing Stop dengan penyimpanan ke memory
  app.post('/api/portal/binance-trailing', async (req, res) => {
    try {
      const { symbol, side, quantity, callbackRate, triggerPrice, positionSide, keys } = req.body;
      const ex = await getExchangeInstance('binance', keys);
      if (!ex) throw new Error("Invalid exchange");

      const resolvedSymbol = resolveSymbol(ex, symbol);
      const isFutures = resolvedSymbol.includes(':') || resolvedSymbol.includes('USDT');
      
      let binancePositionMode = 'HEDGE';
      try {
        const fetchDualTuple = await ex.fapiPrivateGetPositionSideDual();
        const dm = fetchDualTuple?.dualSidePosition;
        if (dm === false || dm === 'false') binancePositionMode = 'ONE_WAY';
      } catch (e) {
        console.warn('[Server API] Failed to fetch Binance positionSide dual setting, assuming HEDGE mode');
      }
      const effectivePositionSide = binancePositionMode === 'HEDGE' ? (positionSide || 'LONG').toUpperCase() : 'BOTH';

      let currentPositionAmt = 0;
      try {
        const positions = await ex.fetchPositions([resolvedSymbol]);
        const pos = positions.find((p: any) => p.symbol === resolvedSymbol && (positionSide ? p.side.toUpperCase() === positionSide.toUpperCase() : true));
        if (pos) {
          currentPositionAmt = Math.abs(Number(pos.contracts || pos.positionAmt || 0));
        }
      } catch (e) {
        console.warn("[Binance Trailing] Could not fetch positions, proceeding with execution", e);
      }

      if (currentPositionAmt === 0) {
        throw new Error("Sistem menolak Trailing: Tidak ada posisi untuk ditutup.");
      }

      const oppositeSide = side === 'buy' ? 'sell' : 'buy';
      
      const tsParams: any = {
        positionSide: effectivePositionSide
      };
      if (effectivePositionSide === 'BOTH') {
        tsParams.reduceOnly = true;
      }

      let order;
      if (isFutures) {
        tsParams.callbackRate = callbackRate;
        if (triggerPrice) {
          tsParams.activationPrice = parseFloat(ex.priceToPrecision(resolvedSymbol, triggerPrice));
        }
        order = await ex.createOrder(resolvedSymbol, 'TRAILING_STOP_MARKET', oppositeSide, quantity, undefined, tsParams);
      } else {
        const trailingDelta = Math.round(callbackRate * 100);
        tsParams.trailingDelta = trailingDelta;
        const orderType = oppositeSide === 'sell' ? 'STOP_LOSS' : 'TAKE_PROFIT';
        order = await ex.createOrder(resolvedSymbol, orderType, oppositeSide, quantity, undefined, tsParams);
      }

      // 🔥 FIX: Simpan trailing order ke memory
      if (order && order.id) {
        const trailingOrderData = {
          id: order.id,
          symbol: resolvedSymbol,
          side: oppositeSide,
          callbackRate,
          triggerPrice,
          positionSide: positionSide || 'BOTH',
          createdAt: Date.now(),
          type: 'TRAILING_STOP_MARKET',
          status: 'active',
          algoId: order.id,
          algoStatus: 'WORKING'
        };
        
        activeTrailingOrders.set(order.id, trailingOrderData);
        activeAlgoOrders.set(order.id, trailingOrderData);
        
        console.log(`[Binance Trailing] Saved order ${order.id} to memory`);
        
        // Broadcast ke semua client
        broadcast({ 
          type: 'ALGO_ORDER_CREATED', 
          order: {
            id: order.id,
            symbol: resolvedSymbol,
            type: 'TRAILING_STOP_MARKET',
            callbackRate,
            status: 'active'
          }
        });
      }

      res.json({ success: true, orderId: order.id, order });
    } catch (error: any) {
      console.error("[Server API] Binance Trailing Error:", error.message);
      res.status(500).json({ error: error.message });
    }
  });

  app.post('/api/portal/bitget-strategy-orders', async (req, res) => {
    try {
      const { keys } = req.body;
      const ex = await getExchangeInstance('bitget', keys);
      if (!ex) throw new Error("Invalid exchange");

      const planTypes = ["normal_plan", "track_plan"];
      let allOrders: any[] = [];

      for (const planType of planTypes) {
        try {
          let response;
          
          if (planType === 'track_plan') {
            response = await ex.request('v2/mix/order/orders-plan-history', 'private', 'GET', {
              productType: 'USDT-FUTURES',
              planType: 'track_plan',
              limit: '100'
            });
          } else {
            response = await ex.request('v2/mix/order/orders-plan-pending', 'private', 'GET', {
              productType: 'USDT-FUTURES',
              planType: planType,
              limit: '100'
            });
          }

          if (!response || typeof response !== 'object') {
            continue;
          }

          if (response?.code !== '00000') {
            continue;
          }
          
          const data = response.data;
          
          if (!data) {
            continue;
          }

          let planOrders: any[] = [];
          if (data?.entrustedList && Array.isArray(data.entrustedList)) {
            planOrders = data.entrustedList;
          } else if (data?.entrusted_list && Array.isArray(data.entrusted_list)) {
            planOrders = data.entrusted_list;
          } else if (Array.isArray(data)) {
            planOrders = data;
          } else if (data?.list && Array.isArray(data.list)) {
            planOrders = data.list;
          }
          
          if (planOrders.length === 0) {
            continue;
          }
          
          const validOrders = planOrders
            .map((order: any) => {
              try {
                return normalizeBitgetPlanOrder(order, planType);
              } catch (err) {
                return null;
              }
            })
            .filter((order: any) => order !== null && order.symbol !== '');
          
          allOrders = [...allOrders, ...validOrders];
          
        } catch (err) {
          continue;
        }
      }

      res.json({
        success: true,
        orders: allOrders,
        count: allOrders.length
      });
    } catch (error: any) {
      res.status(500).json({ 
        success: false, 
        error: error.message, 
        orders: [],
        count: 0 
      });
    }
  });

  app.post('/api/portal/bitget-cancel-plan', async (req, res) => {
    try {
      const { orderId, symbol, planType, keys } = req.body;
      const ex = await getExchangeInstance('bitget', keys);
      if (!ex) throw new Error("Invalid exchange");

      let bitgetSymbol = normalizeSymbol(symbol);
      if (bitgetSymbol.includes('/')) bitgetSymbol = bitgetSymbol.replace('/', '');
      
      const params = {
        symbol: bitgetSymbol,
        orderId: orderId,
        productType: 'USDT-FUTURES',
        planType: planType || 'track_plan'
      };

      const response = await ex.request('v2/mix/order/cancel-plan-order', 'private', 'POST', params);
      
      if (response?.code === '00000') {
        res.json({ success: true });
      } else {
        throw new Error(response?.msg || "Failed to cancel plan order");
      }
    } catch (error: any) {
      console.error("[Server API] Bitget Cancel Plan Error:", error.message);
      res.status(500).json({ error: error.message });
    }
  });

  app.post('/api/portal/bitget-add-strategy', async (req, res) => {
    try {
      const { order, keys } = req.body;
      const ex = await getExchangeInstance('bitget', keys);
      if (!ex) throw new Error("Invalid exchange");

      res.json({ success: true, message: "Strategy order registered" });
    } catch (error: any) {
      console.error("[Server API] Bitget Add Strategy Error:", error.message);
      res.status(500).json({ error: error.message });
    }
  });

  app.post('/api/portal/balances', async (req, res) => {
    try {
      const { binance, bitget } = req.body;
      const results = { binance: 0, bitget: 0 };
      const promises: Promise<void>[] = [];

      if (binance?.apiKey && binance?.secret) {
        promises.push((async () => {
          try {
            const ex = await getExchangeInstance('binance', binance);
            if (!ex) return;
            const bal = await ex.fetchBalance().catch(e => {
              console.warn("[Server API] Binance fetchBalance failed:", e.message);
              return null;
            });
            if (bal) results.binance = bal?.total?.USDT || 0;
          } catch (e: any) {
            console.error("[Server API] Binance Balance Outer Error:", e.message);
          }
        })());
      }

      if (bitget?.apiKey && bitget?.secret) {
        promises.push((async () => {
          try {
            const ex = await getExchangeInstance('bitget', bitget);
            if (!ex) return;
            const bal = await ex.fetchBalance().catch(e => {
              console.warn("[Server API] Bitget fetchBalance failed:", e.message);
              return null;
            });
            if (bal) results.bitget = bal?.total?.USDT || 0;
          } catch (e: any) {
            console.error("[Server API] Bitget Balance Outer Error:", e.message);
          }
        })());
      }

      await Promise.all(promises);
      res.json(results);
    } catch (error: any) {
      console.error("[Server API] General Balance Error:", error.message);
      res.status(500).json({ error: error.message });
    }
  });

  app.post('/api/portal/positions', async (req, res) => {
    try {
      const { binance, bitget } = req.body;
      let allPositions: any[] = [];
      const promises: Promise<void>[] = [];

      if (binance?.apiKey && binance?.secret) {
        promises.push((async () => {
          try {
            const ex = await getExchangeInstance('binance', binance);
            if (!ex) return;
            
            // Lakukan sekuensial atau try-catch per call agar tidak crash bersamaan
            let pos: any = null;
            let openOrders: any = null;
            
            try {
              pos = await ex.fetchPositions();
            } catch (e: any) {
              console.warn("[Server API] Binance fetchPositions failed:", e.message);
            }
            
            try {
              // Be cautious with fetchOpenOrders without symbol as it might time out
              openOrders = await ex.fetchOpenOrders(undefined, undefined, 50); 
            } catch (e: any) {
              console.warn("[Server API] Binance fetchOpenOrders failed:", e.message);
            }

            if (pos && Array.isArray(pos)) {
              allPositions = [...allPositions, ...pos.filter((p: any) => Number(p.contracts) !== 0).map((p: any) => {
                const symbolOrders = Array.isArray(openOrders) ? openOrders.filter((o: any) => o.symbol === p.symbol) : [];
                const slOrder = symbolOrders.find((o: any) => o.type === 'stop_market' || o.type === 'STOP_MARKET');
                const tpOrder = symbolOrders.find((o: any) => o.type === 'take_profit_market' || o.type === 'TAKE_PROFIT_MARKET');

                return {
                  symbol: p.symbol,
                  entryPrice: p.entryPrice,
                  markPrice: p.markPrice,
                  size: p.contracts,
                  side: p.side === 'long' ? 'LONG' : 'SHORT',
                  unrealizedPnl: p.unrealizedPnl,
                  unrealizedPnlPct: p.percentage || 0,
                  leverage: p.leverage,
                  exchange: 'binance',
                  liquidationPrice: p.liquidationPrice,
                  marginType: p.marginMode,
                  stopLoss: slOrder?.stopPrice || slOrder?.price,
                  takeProfit: tpOrder?.stopPrice || tpOrder?.price
                };
              })];
            }
          } catch (e: any) {
            console.error("[Server API] Binance Position Outer Error:", e.message);
          }
        })());
      }

      if (bitget?.apiKey && bitget?.secret) {
        promises.push((async () => {
          try {
            const ex = await getExchangeInstance('bitget', bitget);
            if (!ex) return;
            
            let pos: any = null;
            let openOrders: any = null;
            
            try {
              pos = await ex.fetchPositions();
            } catch (e: any) {
              console.warn("[Server API] Bitget fetchPositions failed:", e.message);
            }
            
            try {
              openOrders = await ex.fetchOpenOrders(undefined, undefined, 50);
            } catch (e: any) {
              console.warn("[Server API] Bitget fetchOpenOrders failed:", e.message);
            }
            
            if (pos && Array.isArray(pos)) {
              allPositions = [...allPositions, ...pos.filter((p: any) => Number(p.contracts) !== 0).map((p: any) => {
                const symbolOrders = Array.isArray(openOrders) ? openOrders.filter((o: any) => o.symbol === p.symbol) : [];
                const slOrder = symbolOrders.find((o: any) => o.type === 'stop_market' || o.type === 'STOP_MARKET');
                const tpOrder = symbolOrders.find((o: any) => o.type === 'take_profit_market' || o.type === 'TAKE_PROFIT_MARKET');

                return {
                  symbol: p.symbol,
                  entryPrice: p.entryPrice,
                  markPrice: p.markPrice,
                  size: p.contracts,
                  side: p.side === 'long' ? 'LONG' : 'SHORT',
                  unrealizedPnl: p.unrealizedPnl,
                  unrealizedPnlPct: p.percentage || 0,
                  leverage: p.leverage,
                  exchange: 'bitget',
                  liquidationPrice: p.liquidationPrice,
                  marginType: p.marginMode,
                  stopLoss: slOrder?.stopPrice || slOrder?.price,
                  takeProfit: tpOrder?.stopPrice || tpOrder?.price
                };
              })];
            }
          } catch (e: any) {
            console.error("[Server API] Bitget Position Outer Error:", e.message);
          }
        })());
      }

      await Promise.all(promises);
      res.json(allPositions);
    } catch (error: any) {
      console.error("[Server API] General Position Error:", error.message);
      res.status(500).json({ error: error.message });
    }
  });

  app.post('/api/portal/market-info', async (req, res) => {
    try {
      const { symbol, exchange, keys } = req.body;
      const ex = await getExchangeInstance(exchange, keys);
      if (!ex) throw new Error("Invalid exchange");

      const resolved = resolveSymbol(ex, symbol);
      const market = ex.market(resolved);
      
      res.json({
        symbol: resolved,
        precision: market.precision,
        limits: market.limits,
        info: market.info
      });
    } catch (error: any) {
      console.error("[Server API] Market Info Error:", error.message);
      res.status(500).json({ error: error.message });
    }
  });

  app.post('/api/portal/order', async (req, res) => {
    try {
      const { exchange, keys, order } = req.body;
      const ex = await getExchangeInstance(exchange, keys);
      if (!ex) throw new Error("Invalid exchange");

      if (!order.symbol || !order.quantity) {
        throw new Error("Invalid order input");
      }

      const symbol = resolveSymbol(ex, order.symbol);
      const side = order.side.toLowerCase() === 'buy' ? 'buy' : 'sell';

      let amount = parseFloat(ex.amountToPrecision(symbol, order.quantity));
      
      if (exchange === 'bitget') {
        try {
          const market = ex.market(symbol);
          let prec = market.precision?.amount;
          
          if (market.info && market.info.quantityPrecision !== undefined) {
            prec = parseInt(market.info.quantityPrecision);
            console.log(`[Bitget V2] Found quantityPrecision in raw info: ${prec}`);
          }

          if (prec !== undefined) {
            if (prec === 0 || prec >= 1) {
              const d = Math.floor(prec);
              const factor = Math.pow(10, d);
              amount = Math.floor(order.quantity * factor) / factor;
              console.log(`[Bitget V2] Decimal Rounding: ${order.quantity} -> ${amount} (Prec: ${d})`);
            } else {
              const factor = 1 / prec;
              amount = Math.floor(order.quantity * factor) / factor;
              console.log(`[Bitget V2] Tick Rounding: ${order.quantity} -> ${amount} (Tick: ${prec})`);
            }
          } else {
            amount = Math.floor(order.quantity);
            console.log(`[Bitget V2] Fallback Integer Rounding: ${order.quantity} -> ${amount}`);
          }
        } catch (e) {
          amount = Math.floor(order.quantity);
        }
      }

      const type = order.type?.toLowerCase() || 'market';
      const price = type === 'limit' ? parseFloat(ex.priceToPrecision(symbol, order.price)) : undefined;

      console.log(`[Server API] Processing Order:`, {
        symbol, side, type, price, quantity: order.quantity, amount, exchange, postOnly: order.postOnly
      });

      if (order.marginMode) {
        try {
          const mode = order.marginMode.toLowerCase() === 'crossed' ? 'crossed' : 'isolated';
          console.log(`[Server API] Setting Margin Mode to ${mode} for ${symbol} on ${exchange}`);
          
          const marginParams: any = {};
          if (exchange === 'bitget') {
            marginParams.productType = 'USDT-FUTURES';
            marginParams.marginCoin = 'USDT';
          }
          
          await ex.setMarginMode(mode, symbol, marginParams);
          console.log(`[Server API] Margin Mode set successfully to ${mode}`);
        } catch (e: any) {
          console.warn(`[Server API] Margin Mode sync info:`, e.message);
        }
      }

      if (order.leverage) {
        try {
          const lev = Number(order.leverage);
          console.log(`[Server API] Setting Leverage to ${lev}x for ${symbol} on ${exchange}`);
          
          let productType = 'USDT-FUTURES';
          let marginCoin = 'USDT';

          if (exchange === 'bitget') {
            try {
              const market = ex.market(symbol);
              if (market && market.info) {
                if (market.info.productType) productType = market.info.productType;
                if (market.info.marginCoin) marginCoin = market.info.marginCoin;
                console.log(`[Bitget V2] Auto-detected: productType=${productType}, marginCoin=${marginCoin}`);
              }
            } catch (marketErr) {
              console.warn(`[Bitget V2] Could not auto-detect market info for leverage, using defaults.`);
            }
          }

          const levParams: any = { productType, marginCoin };

          if (exchange === 'bitget') {
            const sides = ['long', 'short'];
            for (const side of sides) {
              try {
                await ex.setLeverage(lev, symbol, { ...levParams, holdSide: side });
                console.log(`[Server API] Bitget leverage set for ${side} side`);
              } catch (sideErr: any) {
                console.warn(`[Server API] Bitget leverage for ${side} failed:`, sideErr.message);
              }
            }
            try {
              await ex.setLeverage(lev, symbol, levParams);
              console.log(`[Server API] Bitget leverage set (fallback/one-way)`);
            } catch (e) {}
          } else {
            await ex.setLeverage(lev, symbol, levParams);
          }
          
          console.log(`[Server API] Leverage sync process completed`);
          
          if (exchange === 'bitget') {
            await new Promise(resolve => setTimeout(resolve, 1500));
          }
        } catch (e: any) {
          console.error(`[Server API] Failed to set leverage:`, e.message);
        }
      }

      const params: any = {};
      
      if (order.leverage) {
        params.leverage = Number(order.leverage);
      }
      
      if (order.positionSide) {
        params.positionSide = order.positionSide.toUpperCase();
      }

      let slAttached = false;
      let tpAttached = false;
      
      if (exchange === 'bitget') {
        const side_lower = side.toLowerCase();
        const pos_side_lower = (order.positionSide || 'LONG').toLowerCase();
        params.tradeSide = (side_lower === 'buy' && pos_side_lower === 'long') || (side_lower === 'sell' && pos_side_lower === 'short') ? 'open' : 'close';
        
        try {
          const market = ex.market(symbol);
          if (market && market.info) {
            params.productType = market.info.productType || 'USDT-FUTURES';
            params.marginCoin = market.info.marginCoin || 'USDT';
          } else {
            params.productType = 'USDT-FUTURES';
            params.marginCoin = 'USDT';
          }
        } catch (e) {
          params.productType = 'USDT-FUTURES';
          params.marginCoin = 'USDT';
        }
        
        let tickSize = order.tickSize || 0.0001;
        try {
          const market = ex.market(symbol);
          if (market && market.precision && market.precision.price) {
            tickSize = market.precision.price;
            console.log(`[Bitget V2] Using exchange precision: ${tickSize}`);
          }
        } catch (precErr) {
          console.warn(`[Bitget V2] Could not fetch market precision, using fallback: ${tickSize}`);
        }

        console.log(`[Bitget V2 Debug] TickSize: ${tickSize}, SL: ${order.stopLoss}, TP: ${order.takeProfit}`);
        
        const hasSL = order.stopLoss && Number(order.stopLoss) > 0;
        const hasTP = order.takeProfit && Number(order.takeProfit) > 0;

        if (hasSL) {
          const slPrice = ex.priceToPrecision(symbol, order.stopLoss);
          params.presetStopLossPrice = slPrice;
          params.stopLossPrice = slPrice; 
          params.slTriggerType = 'mark';
          params.slOrderType = 'market';
          params.stopLoss = {
            'triggerPrice': slPrice,
            'price': slPrice,
            'type': 'market'
          };
          slAttached = true;
          console.log(`[Bitget V2 Debug] SL Params Prepared: ${slPrice} (Type: ${type})`);
        }
        if (hasTP) {
          const tpPrice = ex.priceToPrecision(symbol, order.takeProfit);
          params.presetTakeProfitPrice = tpPrice;
          params.takeProfitPrice = tpPrice; 
          params.tpTriggerType = 'mark';
          params.tpOrderType = 'market';
          params.takeProfit = {
            'triggerPrice': tpPrice,
            'price': tpPrice,
            'type': 'market'
          };
          tpAttached = true;
          console.log(`[Bitget V2 Debug] TP Params Prepared: ${tpPrice} (Type: ${type})`);
        }
      }

      if (exchange === 'bitget' && order.leverage) {
        params.leverage = Number(order.leverage);
      }

      if (order.timestamp) {
        const age = Date.now() - order.timestamp;
        if (age > 5000) {
          console.warn(`[Race Condition] Order stale: ${age}ms old. Rejecting.`);
          throw new Error(`ORDER_STALE: Order data is too old (${age}ms). Please retry.`);
        }
      }

      if (order.postOnly && type === 'limit') {
        try {
          const ob = await ex.fetchOrderBook(symbol, 10);
          const bestBid = ob.bids[0][0];
          const bestAsk = ob.asks[0][0];

          let isMarketable = false;
          const bitgetBuffer = exchange === 'bitget' ? 0.001 : 0; 

          if (side === 'buy') {
            const maxSafeBuyPrice = bestAsk * (1 - bitgetBuffer);
            if (order.price >= maxSafeBuyPrice) {
              isMarketable = true;
            }
          } else if (side === 'sell') {
            const minSafeSellPrice = bestBid * (1 + bitgetBuffer);
            if (order.price <= minSafeSellPrice) {
              isMarketable = true;
            }
          }

          if (isMarketable) {
            const marketPrice = side === 'buy' ? bestAsk : bestBid;
            const reason = bitgetBuffer > 0 
              ? `Price too close to market for Bitget (0.1% safety buffer required).`
              : `Price would execute immediately.`;
            throw new Error(`POST_ONLY_VIOLATION: ${side.toUpperCase()} limit at ${order.price} rejected. ${reason} Best ${side === 'buy' ? 'Ask' : 'Bid'}: ${marketPrice}`);
          }
        } catch (obErr: any) {
          if (obErr.message.includes('POST_ONLY_VIOLATION')) throw obErr;
          console.error(`[Strict Mode] Orderbook validation failed:`, obErr.message);
          throw new Error(`Cannot verify order safety (Orderbook Fetch Failed): ${obErr.message}`);
        }

        if (exchange === 'binance') {
          params.timeInForce = 'GTX';
        } else if (exchange === 'bitget') {
          if (!params.stopPrice) {
            params.postOnly = true;
            params.timeInForce = 'PO';
          } else {
            console.log(`[Bitget V2] Plan Order detected, skipping Post-Only/PO TIF`);
          }
        }
      }
      if (order.timeInForce && !order.postOnly) {
        params.timeInForce = order.timeInForce.toUpperCase();
      }

      let finalType = type;
      const isNativeTrailing = order.isTrailing || order.isNativeTrailing;
      const callbackRate = order.callbackRate || order.trailingCallback || 1.0;

      console.log(`[Institutional Formula] Executing ${finalType} ${side} on ${symbol}:`, { amount, price, params });
      
      let response: any;
      
      if (exchange === 'bitget' && isNativeTrailing) {
        console.log(`[Trailing Stop Entry] Using Trailing Stop API for entry on ${symbol}`);
        try {
          let triggerPrice = price;
          if (!triggerPrice || triggerPrice <= 0) {
            const ticker = await ex.fetchTicker(symbol);
            triggerPrice = ticker.last;
          }

          const trailingId = await createBitgetTrailingStop({
            ex,
            symbol,
            positionSide: order.positionSide || 'LONG',
            filledSize: amount,
            entryPrice: triggerPrice,
            callbackRate,
            marginMode: order.marginMode || 'crossed',
            tradeSide: 'open'
          });
          
          return res.json({
            success: true,
            client_order_id: trailingId,
            order_id: trailingId,
            status: 'open',
            exchange,
            symbol,
            message: 'Trailing stop entry placed successfully (Plan Order).'
          });
        } catch (error: any) {
          console.error(`[Trailing Stop Entry] FAILED:`, error.message);
          throw error;
        }
      }

      let retries = 3;
      while (retries > 0) {
        try {
          response = await ex.createOrder(symbol, finalType, side, amount, price, params);
          if (response?.id) break;
          throw new Error('EXCHANGE_ORDER_FAILED_NO_ID');
        } catch (e: any) {
          const msg = e.message.toLowerCase();
          if (msg.includes('insufficient') || msg.includes('invalid') || msg.includes('post_only') || msg.includes('balance')) {
            throw e;
          }
          
          retries--;
          console.error(`[Institutional Formula] Order Attempt Failed (${3 - retries}/3):`, e.message);
          if (retries === 0) throw e;
          await new Promise(resolve => setTimeout(resolve, 1000));
        }
      }
      
      if (!response?.id) {
        throw new Error('EXCHANGE_ORDER_FAILED');
      }

      await new Promise(r => setTimeout(r, 300));
      
      let realFilled = 0;
      let orderStatus = null;
      
      try {
        orderStatus = await ex.fetchOrder(response.id, symbol);
        realFilled = orderStatus.filled || 0;
        console.log(`[Institutional Formula] Verified Fill for ${response.id}: ${realFilled}`);
      } catch (fetchErr: any) {
        console.warn(`[Institutional Formula] Fill verification failed, falling back to initial response:`, fetchErr.message);
        realFilled = response.filled || 0;
      }

      let filledSize = realFilled > 0 ? realFilled : (finalType === 'market' ? amount : 0);

      if (type === 'limit' && isNativeTrailing && filledSize === 0) {
        console.log(`[Trailing Stop] Waiting for LIMIT order ${response.id} to fill...`);
        
        let pollCount = 0;
        const maxPolls = 60;
        
        while (pollCount < maxPolls && filledSize === 0) {
          await new Promise(resolve => setTimeout(resolve, 1000));
          try {
            orderStatus = await ex.fetchOrder(response.id, symbol);
            filledSize = orderStatus.filled || 0;
            console.log(`[Trailing Stop] Poll ${pollCount + 1}: filled = ${filledSize}/${amount}`);
            
            if (filledSize > 0) {
              console.log(`[Trailing Stop] Order filled! Creating trailing stop...`);
              break;
            }
          } catch (err: any) {
            console.warn(`[Trailing Stop] Poll error:`, err.message);
          }
          pollCount++;
        }
        
        if (filledSize === 0) {
          console.log(`[Trailing Stop] Timeout waiting for fill. Trailing stop NOT created.`);
          return res.json({
            success: true,
            pending: true,
            message: 'Limit order placed but not filled within timeout. Trailing stop not attached.',
            client_order_id: response.id,
            order_id: response.id,
            status: response.status,
            exchange,
            symbol: response.symbol
          });
        }
      }

      if (filledSize > 0) {
        filledSize = parseFloat(ex.amountToPrecision(symbol, filledSize));
        if (exchange === 'bitget') {
          try {
            const market = ex.market(symbol);
            if (market && market.precision && market.precision.amount === 0) {
              filledSize = Math.floor(filledSize);
            }
          } catch (e) {}
        }
      }

      if (!filledSize || filledSize === 0) {
        const trailingMsg = (order.isTrailing || order.isNativeTrailing) ? ' (Trailing Stop will be attached after fill)' : '';
        return res.json({
          success: true,
          pending: true,
          message: `Order placed but not filled yet (Sitting in Orderbook)${trailingMsg}`,
          client_order_id: response.id,
          order_id: response.id,
          status: response.status,
          exchange,
          symbol: response.symbol,
          slAttached,
          tpAttached
        });
      }

      const oppositeSide = side === 'buy' ? 'sell' : 'buy';

      const safeCreate = async (fn: () => Promise<any>) => {
        try {
          return await fn();
        } catch (e: any) {
          console.error('[SAFE ORDER ERROR]', e.message);
          return null;
        }
      };

      let slResult = null;
      if (order.stopLoss && Number(order.stopLoss) > 0 && !slAttached) {
        slResult = await safeCreate(async () => {
          const slPrice = ex.priceToPrecision(symbol, order.stopLoss);
          const slParams: any = {
            stopPrice: slPrice,
            workingType: 'mark'
          };
          if (exchange !== 'binance' || !order.positionSide || order.positionSide.toUpperCase() === 'BOTH') {
            slParams.reduceOnly = true;
          }
          if (exchange === 'bitget') {
            try {
              const market = ex.market(symbol);
              if (market && market.info) {
                slParams.productType = market.info.productType || 'USDT-FUTURES';
                slParams.marginCoin = market.info.marginCoin || 'USDT';
              }
            } catch (e) {}
            slParams.slTriggerType = 'mark';
            slParams.triggerType = 'mark';
            slParams.slOrderType = 'market';
          }
          if (order.positionSide) {
            slParams.positionSide = order.positionSide.toUpperCase();
          }
          return await ex.createOrder(symbol, 'stop_market', oppositeSide, filledSize, undefined, slParams);
        });
      }

      let tpResult = null;
      if (order.takeProfit && Number(order.takeProfit) > 0 && !tpAttached) {
        tpResult = await safeCreate(async () => {
          const tpPrice = ex.priceToPrecision(symbol, order.takeProfit);
          const tpParams: any = {
            stopPrice: tpPrice,
            workingType: 'mark'
          };
          if (exchange !== 'binance' || !order.positionSide || order.positionSide.toUpperCase() === 'BOTH') {
            tpParams.reduceOnly = true;
          }
          if (exchange === 'bitget') {
            try {
              const market = ex.market(symbol);
              if (market && market.info) {
                tpParams.productType = market.info.productType || 'USDT-FUTURES';
                tpParams.marginCoin = market.info.marginCoin || 'USDT';
              }
            } catch (e) {}
            tpParams.tpTriggerType = 'mark';
            tpParams.triggerType = 'mark';
            tpParams.tpOrderType = 'market';
          }
          if (order.positionSide) {
            tpParams.positionSide = order.positionSide.toUpperCase();
          }
          return await ex.createOrder(symbol, 'take_profit_market', oppositeSide, filledSize, undefined, tpParams);
        });
      }

      let trailingResult = null;
      if (isNativeTrailing && filledSize > 0) {
        trailingResult = await safeCreate(async () => {
          console.log(`[Server API] Setting Native Trailing Stop for ${symbol} with ${callbackRate}% callback`);
          
          if (exchange === 'bitget') {
            try {
              let finalOrderStatus = orderStatus;
              if (!finalOrderStatus || finalOrderStatus.filled === 0) {
                finalOrderStatus = await ex.fetchOrder(response.id, symbol);
              }
              
              const entryPrice = finalOrderStatus.average || finalOrderStatus.price || price;
              
              const activationPrice = (order.takeProfit && order.takeProfit > 0) ? order.takeProfit : entryPrice;
              
              if (!activationPrice || activationPrice <= 0) {
                throw new Error('Cannot determine activation price for trailing stop');
              }
              
              console.log(`[Trailing Stop] Activation price: ${activationPrice} (Entry: ${entryPrice}, TP: ${order.takeProfit})`);
              
              const trailingId = await createBitgetTrailingStop({
                ex,
                symbol,
                positionSide: order.positionSide || 'LONG',
                filledSize,
                entryPrice: activationPrice,
                callbackRate,
                marginMode: order.margin_mode || order.marginMode || 'crossed'
              });
              
              console.log(`[Trailing Stop] SUCCESS! Order ID: ${trailingId}`);
              return { id: trailingId };
              
            } catch (error: any) {
              console.error(`[Trailing Stop] ERROR:`, error.message);
              throw error;
            }
          } else if (exchange === 'binance') {
            const isFutures = symbol.includes(':');
            const tsParams: any = {
              positionSide: order.positionSide ? order.positionSide.toUpperCase() : undefined
            };
            if (!order.positionSide || order.positionSide.toUpperCase() === 'BOTH') {
              tsParams.reduceOnly = true;
            }

            if (isFutures) {
              tsParams.callbackRate = callbackRate;
              if (order.triggerPrice) {
                tsParams.activationPrice = parseFloat(ex.priceToPrecision(symbol, order.triggerPrice));
                console.log(`[Binance Trailing] Using activationPrice: ${tsParams.activationPrice}`);
              }
              return await ex.createOrder(symbol, 'TRAILING_STOP_MARKET', oppositeSide, filledSize, undefined, tsParams);
            } else {
              const trailingDelta = Math.round(callbackRate * 100);
              tsParams.trailingDelta = trailingDelta;
              const orderType = oppositeSide === 'sell' ? 'STOP_LOSS' : 'TAKE_PROFIT';
              return await ex.createOrder(symbol, orderType, oppositeSide, filledSize, undefined, tsParams);
            }
          }
        });
      }

      res.json({
        success: true,
        client_order_id: response.id,
        order_id: response.id,
        status: response.status,
        filledQty: filledSize,
        avgPrice: response.average || response.price,
        avg_price: response.average || response.price,
        filled_qty: filledSize,
        exchange,
        symbol: response.symbol,
        slAttached,
        tpAttached,
        protection: {
          sl: slResult?.id || null,
          tp: tpResult?.id || null,
          trailing: trailingResult?.id || null
        }
      });
    } catch (error: any) {
      console.error("[Institutional Formula] Order Error:", error.message);
      res.status(500).json({ success: false, error: error.message });
    }
  });

  app.post('/api/portal/orderbook', async (req, res) => {
    try {
      const { symbol, exchange, keys } = req.body;
      const ex = await getExchangeInstance(exchange, keys || {});
      const resolvedSymbol = resolveSymbol(ex, symbol);
      const orderbook = await ex.fetchOrderBook(resolvedSymbol, 5);
      res.json(orderbook);
    } catch (error: any) {
      console.error("[Server API] Orderbook Error:", error.message);
      res.status(500).json({ error: error.message });
    }
  });

  app.post('/api/portal/order-status', async (req, res) => {
    try {
      const { symbol, orderId, exchange, keys } = req.body;
      
      console.log('[Order Status] Request received:', { 
        symbol, 
        orderId, 
        exchange, 
        hasKeys: !!keys
      });
      
      if (!orderId) {
        throw new Error('No orderId provided');
      }
      
      const ex = await getExchangeInstance(exchange, keys);
      if (!ex) throw new Error("Invalid exchange");

      const resolvedSymbol = resolveSymbol(ex, symbol);
      
      let orderData = null;
      
      if (exchange === 'bitget') {
        try {
          let bitgetSymbol = normalizeSymbol(resolvedSymbol);
          if (bitgetSymbol.includes('/')) {
            bitgetSymbol = bitgetSymbol.replace('/', '');
          }
          if (bitgetSymbol && bitgetSymbol.includes(':')) {
            bitgetSymbol = bitgetSymbol.split(':')[0];
          }
          
          const productType = 'USDT-FUTURES';
          
          console.log(`[Order Status] Bitget: Calling /api/v2/mix/order/detail with:`, {
            symbol: bitgetSymbol,
            orderId: orderId,
            productType: productType
          });
          
          const response = await ex.request('v2/mix/order/detail', 'private', 'GET', {
            symbol: bitgetSymbol,
            orderId: orderId,
            productType: productType
          });
          
          console.log("RAW BITGET ORDER DETAIL RESPONSE:", JSON.stringify(response, null, 2));
          
          if (response && response.code === '00000' && response.data) {
            const data = response.data;
            console.log('[Order Status] Bitget Response:', JSON.stringify(data, null, 2));
            
            orderData = {
              id: data.orderId,
              status: mapBitgetStatus(data.state),
              filled: parseFloat(data.filledSize) || 0,
              remaining: parseFloat(data.size) - parseFloat(data.filledSize) || 0,
              average: parseFloat(data.priceAvg) || parseFloat(data.price),
              price: parseFloat(data.price),
              symbol: resolvedSymbol,
              clientOrderId: data.clientOid
            };
            console.log(`[Order Status] ✅ Success! Status: ${orderData.status}, Filled: ${orderData.filled}`);
          } else {
            throw new Error(response?.msg || 'Direct API failed');
          }
        } catch (err: any) {
          console.error(`[Order Status] Bitget API failed:`, err.message);
          
          try {
            console.log(`[Order Status] Fallback: Trying fetchOrder with ID: ${orderId}`);
            const order = await ex.fetchOrder(orderId, resolvedSymbol);
            orderData = {
              id: order.id,
              status: order.status,
              filled: order.filled,
              remaining: order.remaining,
              average: order.average,
              price: order.price,
              symbol: resolvedSymbol,
              clientOrderId: order.clientOrderId
            };
            console.log(`[Order Status] ✅ Success with fetchOrder fallback`);
          } catch (fetchErr: any) {
            console.error(`[Order Status] All methods failed:`, fetchErr.message);
            throw err;
          }
        }
      } else {
        const order = await ex.fetchOrder(orderId, resolvedSymbol);
        orderData = {
          id: order.id,
          status: order.status,
          filled: order.filled,
          remaining: order.remaining,
          average: order.average,
          price: order.price,
          symbol: resolvedSymbol,
          clientOrderId: order.clientOrderId
        };
      }
      
      if (!orderData) {
        throw new Error('Order not found after all attempts');
      }
      
      console.log('[Order Status] Final Result:', {
        status: orderData.status,
        filled: orderData.filled,
        avgPrice: orderData.average,
        orderId: orderData.id
      });
      
      res.json({
        success: true,
        status: orderData.status,
        avgPrice: orderData.average || orderData.price,
        filledQty: orderData.filled,
        remainingQty: orderData.remaining,
        avg_price: orderData.average || orderData.price,
        filled_qty: orderData.filled,
        orderId: orderData.id,
        clientOrderId: orderData.clientOrderId
      });
    } catch (error: any) {
      console.error("[Server API] Order Status Error:", error.message);
      res.status(500).json({ 
        success: false, 
        error: error.message,
        details: error.stack
      });
    }
  });

  app.post('/api/portal/set-sl-tp', async (req, res) => {
    try {
      const { exchange, keys, params } = req.body;
      const { symbol, positionSide, stopLoss, takeProfit, quantity, isTrailing, callbackRate, triggerPrice } = params || req.body;
      
      const ex = await getExchangeInstance(exchange, keys);
      const resolvedSymbol = resolveSymbol(ex, symbol);
      
      const results: any = { success: true };
      const oppositeSide = positionSide === 'LONG' ? 'sell' : 'buy';
      
      let stepSize = 1.0;
      try {
        const market = ex.market(resolvedSymbol);
        if (market && market.precision && market.precision.amount) {
          stepSize = market.precision.amount;
        }
      } catch (e) {}

      let finalQuantity = quantity;
      let finalCallbackRate = callbackRate;

      if (exchange === 'bitget' && isTrailing) {
        if (callbackRate && (callbackRate < 0.1 || callbackRate > 10)) {
          console.error(`[Set-SL-TP] Invalid callback: ${callbackRate}% (must be 0.1-10)`);
          return res.status(400).json({ 
            success: false, 
            error: `INVALID_CALLBACK: ${callbackRate}% must be between 0.1% and 10%` 
          });
        }
        
        finalQuantity = Math.floor(quantity);
        if (finalQuantity < 1) {
          return res.status(400).json({ 
            success: false, 
            error: `SIZE_TOO_SMALL: Quantity ${quantity} rounded to ${finalQuantity}. Minimum is 1 contract.` 
          });
        }
        
        finalCallbackRate = callbackRate;
        console.log(`[Set-SL-TP] Bitget trailing: Quantity ${quantity} -> ${finalQuantity}, Callback ${callbackRate}%`);
      }

      const formattedQty = finalQuantity.toString();
      
      let effectivePositionSide = positionSide;
      if (exchange === 'binance') {
        let binancePositionMode = 'HEDGE';
        try {
          const fetchDualTuple = await ex.fapiPrivateGetPositionSideDual();
          const dm = fetchDualTuple?.dualSidePosition;
          if (dm === false || dm === 'false') binancePositionMode = 'ONE_WAY';
        } catch (e) {
          console.warn('[Server API] Failed to fetch Binance positionSide dual setting, assuming HEDGE mode');
        }
        effectivePositionSide = binancePositionMode === 'HEDGE' ? (positionSide || 'LONG').toUpperCase() : 'BOTH';
      }

      if (stopLoss) {
        console.log(`[Server API] Setting SL for ${resolvedSymbol} at ${stopLoss} with qty ${formattedQty}`);
        const slPrice = ex.priceToPrecision(resolvedSymbol, stopLoss);
        const slParams: any = {
          stopPrice: slPrice,
          workingType: 'mark'
        };
        if (exchange !== 'binance' || effectivePositionSide === 'BOTH') {
          slParams.reduceOnly = true;
        }
        if (exchange === 'bitget') {
          try {
            const market = ex.market(resolvedSymbol);
            if (market && market.info) {
              slParams.productType = market.info.productType || 'USDT-FUTURES';
              slParams.marginCoin = market.info.marginCoin || 'USDT';
            }
          } catch (e) {}
          slParams.slTriggerType = 'mark';
          slParams.triggerType = 'mark';
          slParams.slOrderType = 'market';
        }
        if (effectivePositionSide) {
          slParams.positionSide = effectivePositionSide.toUpperCase();
        }
        const slRes = await ex.createOrder(resolvedSymbol, 'stop_market', oppositeSide, parseFloat(formattedQty), undefined, slParams);
        results.sl = slRes.id;
      }
      
      if (takeProfit) {
        console.log(`[Server API] Setting TP for ${resolvedSymbol} at ${takeProfit} with qty ${formattedQty}`);
        const tpPrice = ex.priceToPrecision(resolvedSymbol, takeProfit);
        const tpParams: any = {
          stopPrice: tpPrice,
          workingType: 'mark'
        };
        if (exchange !== 'binance' || effectivePositionSide === 'BOTH') {
          tpParams.reduceOnly = true;
        }
        if (exchange === 'bitget') {
          try {
            const market = ex.market(resolvedSymbol);
            if (market && market.info) {
              tpParams.productType = market.info.productType || 'USDT-FUTURES';
              tpParams.marginCoin = market.info.marginCoin || 'USDT';
            }
          } catch (e) {}
          tpParams.tpTriggerType = 'mark';
          tpParams.triggerType = 'mark';
          tpParams.tpOrderType = 'market';
        }
        if (effectivePositionSide) {
          tpParams.positionSide = effectivePositionSide.toUpperCase();
        }
        const tpRes = await ex.createOrder(resolvedSymbol, 'take_profit_market', oppositeSide, parseFloat(formattedQty), undefined, tpParams);
        results.tp = tpRes.id;
      }

      if (isTrailing && quantity > 0) {
        const rate = callbackRate || 1.0;
        console.log(`[Server API] Setting Native Trailing Stop for ${resolvedSymbol} with ${rate}% callback`);
        
        if (exchange === 'binance') {
          if (rate < 0.1 || rate > 10) {
            return res.status(400).json({ 
              success: false, 
              error: `INVALID_CALLBACK: ${rate}% must be between 0.1% and 10%` 
            });
          }
          
          const isFutures = resolvedSymbol.includes(':');
          const tsParams: any = {
            positionSide: effectivePositionSide ? effectivePositionSide.toUpperCase() : undefined
          };
          if (effectivePositionSide === 'BOTH') {
            tsParams.reduceOnly = true;
          }

          if (isFutures) {
            tsParams.callbackRate = rate;
            if (triggerPrice) {
              tsParams.activationPrice = parseFloat(ex.priceToPrecision(resolvedSymbol, triggerPrice));
              console.log(`[Binance Trailing SLTP] Using activationPrice: ${tsParams.activationPrice}`);
            }
            const tsRes = await ex.createOrder(resolvedSymbol, 'TRAILING_STOP_MARKET', oppositeSide, parseFloat(formattedQty), undefined, tsParams);
            results.trailing = tsRes.id;
          } else {
            const trailingDelta = Math.round(rate * 100);
            tsParams.trailingDelta = trailingDelta;
            const orderType = oppositeSide === 'sell' ? 'STOP_LOSS' : 'TAKE_PROFIT';
            const tsRes = await ex.createOrder(resolvedSymbol, orderType, oppositeSide, parseFloat(formattedQty), undefined, tsParams);
            results.trailing = tsRes.id;
          }
        } else if (exchange === 'bitget') {
          try {
            const market = ex.market(resolvedSymbol);
            const entryPrice = triggerPrice || (await fetchBitgetMarkPrice(ex, resolvedSymbol));
            
            const trailingId = await createBitgetTrailingStop({
              ex,
              symbol: resolvedSymbol,
              positionSide,
              filledSize: finalQuantity,
              entryPrice,
              callbackRate: rate,
              marginMode: 'crossed'
            });
            
            results.trailing = trailingId;
          } catch (error: any) {
            console.error(`[Set-SL-TP] Trailing stop error:`, error.message);
            results.trailing_error = error.message;
          }
        }
      }
      
      res.json(results);
    } catch (error: any) {
      console.error("[Server API] Set SL/TP Error:", error.message);
      res.status(500).json({ success: false, error: error.message });
    }
  });

  app.post('/api/portal/trailing-stop', async (req, res) => {
    try {
      const { exchange, keys, params } = req.body;
      const { symbol, quantity, callbackRate, triggerPrice, positionSide, marginMode } = params;
      
      const ex = await getExchangeInstance(exchange, keys);
      if (!ex) throw new Error("Invalid exchange");
      
      const resolvedSymbol = resolveSymbol(ex, symbol);
      
      if (exchange === 'bitget') {
        const trailingId = await createBitgetTrailingStop({
          ex,
          symbol: resolvedSymbol,
          positionSide,
          filledSize: quantity,
          entryPrice: triggerPrice,
          callbackRate,
          marginMode: marginMode || 'crossed'
        });
        
        res.json({
          success: true,
          orderId: trailingId
        });
      } else {
        res.status(400).json({ error: 'Trailing stop only supported for Bitget' });
      }
    } catch (error: any) {
      console.error("[Trailing Stop API] Error:", error.message);
      res.status(500).json({ success: false, error: error.message });
    }
  });

  async function fetchBitgetMarkPrice(ex: any, symbol: string): Promise<number> {
    try {
      const ticker = await ex.fetchTicker(symbol);
      return ticker.mark || ticker.last || ticker.close || 0;
    } catch (e) {
      console.error(`Failed to fetch mark price for ${symbol}:`, e);
      return 0;
    }
  }

  app.post('/api/portal/set-sl', async (req, res) => {
    try {
      const { exchange, keys, symbol, side, sl, qty } = req.body;
      const ex = await getExchangeInstance(exchange, keys);
      if (!ex) throw new Error("Invalid exchange");

      const resolvedSymbol = resolveSymbol(ex, symbol);
      const orderSide = side === 'LONG' ? 'sell' : 'buy';

      console.log(`[Server API] Setting SL for ${resolvedSymbol} at ${sl}`);
      
      try {
        const openOrders = await ex.fetchOpenOrders(resolvedSymbol);
        const slOrders = openOrders.filter((o: any) => o.type === 'stop_market' || o.type === 'STOP_MARKET');
        for (const order of slOrders) {
          await ex.cancelOrder(order.id, resolvedSymbol);
        }
      } catch (cancelErr: any) {
        console.warn(`[Server API] Failed to cancel existing SLs: ${cancelErr.message}`);
      }

      const params: any = {
        stopPrice: sl,
        reduceOnly: true
      };
      if (side) {
        params.positionSide = side.toUpperCase();
      }

      const response = await ex.createOrder(resolvedSymbol, 'stop_market', orderSide, qty, undefined, params);
      
      res.json({
        success: true,
        id: response.id
      });
    } catch (error: any) {
      console.error("[Server API] Set SL Error:", error.message);
      res.status(500).json({ success: false, error: error.message });
    }
  });

  app.post('/api/portal/cancel-all-orders', async (req, res) => {
    try {
      const { exchange, keys, symbol } = req.body;
      const ex = await getExchangeInstance(exchange, keys);
      if (!ex) throw new Error("Invalid exchange");

      const resolvedSymbol = resolveSymbol(ex, symbol);
      console.log(`[Server API] Cancelling ALL open orders for ${resolvedSymbol} on ${exchange}`);
      
      const openOrders = await ex.fetchOpenOrders(resolvedSymbol);
      const results = [];
      for (const order of openOrders) {
        try {
          const cancelRes = await ex.cancelOrder(order.id, resolvedSymbol);
          results.push({ id: order.id, success: true, response: cancelRes });
        } catch (err: any) {
          console.error(`[Server API] Failed to cancel order ${order.id}:`, err.message);
          results.push({ id: order.id, success: false, error: err.message });
        }
      }
      
      res.json({
        success: true,
        cancelledCount: results.filter(r => r.success).length,
        totalCount: openOrders.length,
        details: results
      });
    } catch (error: any) {
      console.error("[Server API] Cancel All Orders Error:", error.message);
      res.status(500).json({ success: false, error: error.message });
    }
  });

  // 🔥 FIXED: Conditional Orders dengan Algo Orders untuk Binance
  app.post('/api/portal/conditional-orders', async (req, res) => {
    try {
      const { binance, bitget, keys } = req.body;
      let exchangeKeys = keys || bitget || binance;
      
      // Handle nested or direct keys
      if (exchangeKeys && !exchangeKeys.apiKey) {
        if (exchangeKeys.bitget?.apiKey) exchangeKeys = exchangeKeys.bitget;
        else if (exchangeKeys.binance?.apiKey) exchangeKeys = exchangeKeys.binance;
      }

      if (!exchangeKeys || !exchangeKeys.apiKey) {
        // Return gracefully to prevent logs/console spam on client empty state
        return res.json([]);
      }

      const exchangeType = (bitget || exchangeKeys === req.body.bitget) ? 'bitget' : (binance ? 'binance' : 'bitget');
      
      const ex = await getExchangeInstance(exchangeType, exchangeKeys);
      if (!ex) throw new Error("Invalid exchange");

      let orders: any[] = [];
      
      if (exchangeType === 'bitget') {
        try {
          const planTypes = ['normal_plan', 'track_plan'];
          
          for (const planType of planTypes) {
            try {
              const response = await ex.request('v2/mix/order/orders-plan-pending', 'private', 'GET', {
                productType: 'USDT-FUTURES',
                planType: planType,
                limit: '100'
              });
              
              if (!response || response?.code !== '00000') {
                continue;
              }
              
              const data = response?.data;
              if (!data) continue;

              let planOrders: any[] = [];
              if (data?.entrustedList && Array.isArray(data.entrustedList)) {
                planOrders = data.entrustedList;
              } else if (data?.entrusted_list && Array.isArray(data.entrusted_list)) {
                planOrders = data.entrusted_list;
              } else if (Array.isArray(data)) {
                planOrders = data;
              }
              
              if (planOrders.length === 0) continue;
              
              const mappedOrders = planOrders
                .map((order: any) => {
                  try {
                    return normalizeBitgetPlanOrder(order, planType);
                  } catch (err) {
                    return null;
                  }
                })
                .filter((order: any) => order !== null && order.symbol && order.symbol !== '');
              
              orders = [...orders, ...mappedOrders];
            } catch (err) {
              continue;
            }
          }
          
          try {
            let openOrders: any[] = [];
            try {
              openOrders = await ex.fetchOpenOrders();
            } catch (e: any) {
              console.warn("[Server API] Bitget fetchOpenOrders failed:", e.message);
            }
            const regularOrders = openOrders
              .filter((order: any) => {
                const symbol = order.symbol || order.info?.symbol || '';
                return symbol && typeof symbol === 'string' && symbol.trim() !== '';
              })
              .map((order: any) => {
                const safeSymbol = (() => {
                  const sym = order.symbol || order.info?.symbol || '';
                  if (!sym || typeof sym !== 'string') return '';
                  try {
                    return normalizeSymbol(sym);
                  } catch {
                    return '';
                  }
                })();
                
                if (!safeSymbol || safeSymbol === '') return null;
                
                const safeStopPrice = (() => {
                  const sp = order.stopPrice || order.info?.stopPrice || order.info?.triggerPrice;
                  if (!sp) return '';
                  if (typeof sp === 'string') return sp;
                  if (typeof sp === 'number') return String(sp);
                  return '';
                })();
                
                return {
                  id: order.id || '',
                  symbol: safeSymbol,
                  type: order.type || '',
                  side: order.side || '',
                  price: order.price ? String(order.price) : '',
                  stopPrice: safeStopPrice,
                  amount: order.amount ? String(order.amount) : '0',
                  status: order.status || 'open',
                  positionSide: order.positionSide || order.info?.positionSide || '',
                  orderType: 'regular',
                  tradeSide: order.info?.reduceOnly === 'true' ? 'close' : 'open'
                };
              })
              .filter((order: any) => order !== null && order.symbol !== '');
            
            orders = [...orders, ...regularOrders];
          } catch (openErr) {
            // Continue with plan orders only
          }
          
        } catch (bitgetError: any) {
          try {
            let openOrders: any[] = [];
            try {
              openOrders = await ex.fetchOpenOrders();
            } catch (e: any) {
              console.warn("[Server API] Bitget fetchOpenOrders 2 failed:", e.message);
            }
            const regularOrders = openOrders
              .filter((order: any) => {
                const symbol = order.symbol || order.info?.symbol || '';
                return symbol && typeof symbol === 'string' && symbol.trim() !== '';
              })
              .map((order: any) => {
                const safeSymbol = (() => {
                  const sym = order.symbol || order.info?.symbol || '';
                  if (!sym || typeof sym !== 'string') return '';
                  try {
                    return normalizeSymbol(sym);
                  } catch {
                    return '';
                  }
                })();
                
                if (!safeSymbol || safeSymbol === '') return null;
                
                return {
                  id: order.id || '',
                  symbol: safeSymbol,
                  type: order.type || '',
                  side: order.side || '',
                  price: order.price ? String(order.price) : '',
                  stopPrice: (order.stopPrice || order.info?.stopPrice) ? String(order.stopPrice || order.info?.stopPrice) : '',
                  amount: order.amount ? String(order.amount) : '0',
                  status: order.status || 'open',
                  positionSide: order.positionSide || order.info?.positionSide || '',
                  orderType: 'regular'
                };
              })
              .filter((order: any) => order !== null);
            orders = regularOrders;
          } catch (e) {
            orders = [];
          }
        }
      } 
      else if (exchangeType === 'binance') {
        try {
          // 1. Regular open orders
          let openOrders: any[] = [];
          try {
            openOrders = await ex.fetchOpenOrders();
          } catch (e: any) {
            console.warn("[Server API] Binance fetchOpenOrders failed:", e.message);
          }
          const regularOrders = openOrders
            .filter((order: any) => order.symbol && order.symbol.trim() !== '')
            .map((order: any) => {
              const rawType = (order.type || order.info?.type || '').toUpperCase();
              const isTrailing = rawType.includes('TRAILING');
              const callbackRate = order.info?.priceRate || order.info?.callbackRate || '';
              const isReduceOnly = order.reduceOnly || order.info?.reduceOnly === 'true' || order.info?.closePosition === 'true';
              const tradeSide = isReduceOnly ? 'close' : 'open';
              
              return {
                id: order.id || '',
                symbol: order.symbol || '',
                type: isTrailing ? 'trailing_stop' : (order.type || ''),
                side: order.side || '',
                price: order.price ? String(order.price) : '',
                stopPrice: (order.stopPrice || order.info?.stopPrice || order.info?.triggerPrice) ? String(order.stopPrice || order.info?.stopPrice || order.info?.triggerPrice) : '',
                amount: order.amount ? String(order.amount) : '0',
                status: order.status || 'open',
                positionSide: order.positionSide || order.info?.positionSide || '',
                orderType: isTrailing ? 'trailing' : 'regular',
                isTrailing: isTrailing,
                callback_rate: callbackRate,
                callbackRatio: callbackRate,
                tradeSide: tradeSide
              };
            });
          
          // 🔥 FIX: Fetch Algo Orders (TRAILING STOP MARKET)
          let algoOrders: any[] = [];
          try {
            console.log('[Binance] Fetching algo orders from /fapi/v1/openAlgoOrders');
            
            const timestamp = Date.now();
            const algoResponse = await ex.request('fapi/v1/openAlgoOrders', 'private', 'GET', {
              timestamp: timestamp,
              recvWindow: 20000
            });
            
            if (algoResponse && Array.isArray(algoResponse)) {
              console.log(`[Binance] Found ${algoResponse.length} algo orders`);
              
              algoOrders = algoResponse.map((order: any) => {
                const isTrailingAlgo = order.type === 'TRAILING_STOP_MARKET';
                const isReduceOnly = order.reduceOnly === true || order.closePosition === true;
                
                return {
                  id: order.algoId?.toString() || '',
                  symbol: order.symbol || '',
                  type: isTrailingAlgo ? 'trailing_stop' : (order.type || '').toLowerCase(),
                  side: order.side || '',
                  price: order.price ? String(order.price) : '',
                  stopPrice: order.triggerPrice ? String(order.triggerPrice) : '',
                  amount: order.quantity ? String(order.quantity) : '0',
                  status: order.algoStatus || 'unknown',
                  positionSide: order.positionSide || '',
                  orderType: isTrailingAlgo ? 'trailing' : 'algo',
                  isTrailing: isTrailingAlgo,
                  callback_rate: order.callbackRate || '',
                  callbackRatio: order.callbackRate || '',
                  tradeSide: isReduceOnly ? 'close' : 'open',
                  source: 'algo'
                };
              });
            } else {
              console.log('[Binance] No algo orders found or response not an array');
            }
          } catch (algoErr: any) {
            console.error('[Binance] Failed to fetch algo orders:', algoErr.message);
            // Jangan gagalkan request jika algo orders gagal, tetap lanjut dengan regular orders
          }
          
          // Gabungkan regular orders dengan algo orders
          orders = [...regularOrders, ...algoOrders];
          console.log(`[Binance] Total orders: ${orders.length} (Regular: ${regularOrders.length}, Algo: ${algoOrders.length})`);
          
        } catch (binanceError: any) {
          console.error("[Server API] Binance Conditional Orders Error:", binanceError.message);
          orders = [];
        }
      }
      
      const sanitizedOrders = orders.map(order => ({
        id: order.id ?? '',
        symbol: order.symbol ?? '',
        type: order.type ?? '',
        side: order.side ?? '',
        positionSide: order.positionSide ?? order.position_side ?? order.posSide ?? '',
        price: order.price ?? '',
        stopPrice: order.stopPrice ?? '',
        amount: order.amount ?? '0',
        status: order.status ?? '',
        orderType: order.orderType ?? '',
        planType: order.planType ?? '',
        triggerType: order.triggerType ?? '',
        executePrice: order.executePrice ?? '',
        cTime: order.cTime ?? '',
        tradeSide: order.tradeSide ?? '',
        callbackRatio: order.callbackRatio ?? '',
        callback_rate: order.callback_rate ?? '',
        isTrailing: order.isTrailing ?? false
      }));
      
      res.json({
        success: true,
        orders: sanitizedOrders,
        total: sanitizedOrders.length
      });
      
      broadcast({ type: 'ORDERS_UPDATED', orders: sanitizedOrders });
      
    } catch (error: any) {
      console.error("[Server API] Conditional Orders Error:", error.message);
      res.status(500).json({ 
        success: false, 
        error: error.message,
        orders: [],
        total: 0
      });
    }
  });

  app.post('/api/portal/purge-trailing', async (req, res) => {
    try {
      const { symbol } = req.body;
      console.log(`[Server API] Purging trailing stop for ${symbol}`);
      
      // Hapus dari memory
      for (const [id, order] of activeTrailingOrders) {
        if (order.symbol === symbol) {
          activeTrailingOrders.delete(id);
          activeAlgoOrders.delete(id);
        }
      }
      
      res.json(true);
    } catch (error: any) {
      res.status(500).json(false);
    }
  });

  app.post('/api/portal/active-trailing', async (req, res) => {
    try {
      const activeOrders = Array.from(activeTrailingOrders.values());
      res.json(activeOrders);
    } catch (error: any) {
      res.status(500).json([]);
    }
  });

  const manualRateLimitMap = new Map<string, { count: number; resetTime: number }>();
  
  app.use('/api', (req, res, next) => {
    const ip = req.ip || req.socket.remoteAddress || 'unknown';
    const now = Date.now();
    
    if (!manualRateLimitMap.has(ip)) {
      manualRateLimitMap.set(ip, { count: 1, resetTime: now + 60000 });
    } else {
      const limit = manualRateLimitMap.get(ip)!;
      if (now > limit.resetTime) {
        limit.count = 1;
        limit.resetTime = now + 60000;
      } else {
        limit.count++;
        // Very high limit to avoid 429
        if (limit.count > 50000) {
          return res.status(429).json({ error: 'Rate limit exceeded. Please slow down.' });
        }
      }
    }
    
    next();
  });

  setInterval(() => {
    const now = Date.now();
    for (const [ip, limit] of manualRateLimitMap.entries()) {
      if (now > limit.resetTime) {
        manualRateLimitMap.delete(ip);
      }
    }
  }, 60000);

  // Proxy for Coinglass API
  app.use('/api/coinglass', createProxyMiddleware({
    target: 'https://open-api-v4.coinglass.com',
    changeOrigin: true,
    secure: false, 
    pathRewrite: { '^/api/coinglass': '' },
    onProxyReq: (proxyReq, req, res) => {
      const key = (req.headers['cg-api-key'] || req.headers['CG-API-KEY'] || req.headers['coinglass-secret']) as string;
      if (key) {
        console.log(`[Server] Coinglass Proxy: Key present (${key.substring(0, 4)}...)`);
        proxyReq.setHeader('CG-API-KEY', key);
      } else {
        console.warn(`[Server] Coinglass Proxy: Key MISSING!`);
      }
      proxyReq.setHeader('Origin', 'https://open-api-v4.coinglass.com');
      proxyReq.setHeader('Referer', 'https://open-api-v4.coinglass.com/');
      proxyReq.removeHeader('sec-fetch-dest');
      proxyReq.removeHeader('sec-fetch-mode');
      proxyReq.removeHeader('sec-fetch-site');
      proxyReq.removeHeader('sec-ch-ua');
      proxyReq.removeHeader('sec-ch-ua-mobile');
      proxyReq.removeHeader('sec-ch-ua-platform');
      proxyReq.setHeader('Host', 'open-api-v4.coinglass.com');
      proxyReq.setHeader('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36');
    },
    onError: (err, req, res) => {
      console.error('[Server] Coinglass Proxy Error:', err.message);
      res.status(502).json({ error: 'Proxy Error', message: err.message });
    }
  }));

  app.use(['/api/datafeed', '/api/cmc', '/api/market-data'], (req, res, next) => {
    const cacheKey = req.url;
    const cached = cmcCache.get(cacheKey);
    if (req.method === 'GET' && cached && (Date.now() - cached.timestamp < CMC_CACHE_TTL)) {
      console.log(`[Server] Returning cached CMC data for ${cacheKey}`);
      return res.json(cached.data);
    }
    next();
  }, createProxyMiddleware({
    target: 'https://pro-api.coinmarketcap.com/v1',
    changeOrigin: true,
    secure: true,
    pathRewrite: (path, req) => {
      return path.replace(/^\/api\/(datafeed|cmc|market-data)/, '');
    },
    onProxyReq: (proxyReq, req, res) => {
      const key = (req.headers['x-cmc_pro_api_key'] || 
                   req.headers['X-CMC_PRO_API_KEY'] || 
                   process.env.CMC_API_KEY || 
                   process.env.VITE_CMC_API_KEY) as string;
                   
      proxyReq.removeHeader('x-cmc_pro_api_key');
      proxyReq.removeHeader('X-CMC_PRO_API_KEY');
      proxyReq.removeHeader('Origin');
      proxyReq.setHeader('Accept', 'application/json');

      if (key) {
        console.log(`[Server] CMC Proxy: Setting X-CMC_PRO_API_KEY header`);
        proxyReq.setHeader('X-CMC_PRO_API_KEY', key);
        
        try {
          const path = proxyReq.path;
          const separator = path.includes('?') ? '&' : '?';
          proxyReq.path = `${path}${separator}CMC_PRO_API_KEY=${key}`;
        } catch (e) {
          console.error('[Server] Failed to append CMC query param:', e);
        }
      } else {
        console.warn(`[Server] CMC Proxy: Key MISSING in request headers and environment!`);
      }
    },
    onProxyRes: (proxyRes, req, res) => {
      // Intentionally intentionally left empty to avoid consuming the stream and causing fetch failures
    },
    onError: (err, req, res) => {
      console.error('[Server] CMC Proxy Error:', err.message);
      res.status(502).json({ error: 'Proxy Error', message: err.message });
    }
  }));

  app.use('/api/cryptocompare', (req, res, next) => {
    const cacheKey = req.url;
    const cached = cryptocompareCache.get(cacheKey);
    if (req.method === 'GET' && cached && (Date.now() - cached.timestamp < CRYPTOCOMPARE_CACHE_TTL)) {
      return res.json(cached.data);
    }
    next();
  }, createProxyMiddleware({
    target: 'https://min-api.cryptocompare.com/data/v2',
    changeOrigin: true,
    secure: false,
    pathRewrite: { '^/api/cryptocompare': '' },
    onProxyReq: (proxyReq) => {
      proxyReq.setHeader('Origin', 'https://min-api.cryptocompare.com');
      proxyReq.setHeader('Referer', 'https://min-api.cryptocompare.com/');
      proxyReq.removeHeader('sec-fetch-dest');
      proxyReq.removeHeader('sec-fetch-mode');
      proxyReq.removeHeader('sec-fetch-site');
      proxyReq.removeHeader('sec-ch-ua');
      proxyReq.removeHeader('sec-ch-ua-mobile');
      proxyReq.removeHeader('sec-ch-ua-platform');
      proxyReq.setHeader('Host', 'min-api.cryptocompare.com');
      proxyReq.setHeader('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36');
    },
    onProxyRes: (proxyRes, req, res) => {
      // Intentionally left empty to avoid consuming the proxy stream
    },
    onError: (err, req, res) => {
      console.error('[Server] CryptoCompare Proxy Error:', err.message);
      res.status(502).json({ error: 'Proxy Error', message: err.message });
    }
  }));

  app.use('/api/fng', createProxyMiddleware({
    target: 'https://api.alternative.me/fng/',
    changeOrigin: true,
    pathRewrite: { '^/api/fng': '' },
    onProxyReq: (proxyReq, req, res) => {
      proxyReq.setHeader('Origin', 'https://api.alternative.me');
      proxyReq.setHeader('Referer', 'https://api.alternative.me/');
      proxyReq.removeHeader('sec-fetch-dest');
      proxyReq.removeHeader('sec-fetch-mode');
      proxyReq.removeHeader('sec-fetch-site');
      proxyReq.removeHeader('sec-ch-ua');
      proxyReq.removeHeader('sec-ch-ua-mobile');
      proxyReq.removeHeader('sec-ch-ua-platform');
      proxyReq.setHeader('Host', 'api.alternative.me');
      proxyReq.setHeader('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36');
    },
    onError: (err, req, res) => {
      console.error('FNG Proxy Error:', err);
      res.status(500).send('Proxy Error');
    }
  }));

  // ===================================
  // DIAGNOSTICS & HEALTH
  // ===================================
  app.get('/api/diag/status', (req, res) => {
    res.json({
      status: 'online',
      timestamp: new Date().toISOString(),
      env: {
        STRIPE_SET: !!process.env.STRIPE_SECRET_KEY,
        STRIPE_WEBHOOK_SET: !!process.env.STRIPE_WEBHOOK_SECRET,
        XENDIT_SET: !!process.env.XENDIT_SECRET_KEY,
        XENDIT_WEBHOOK_SET: !!process.env.XENDIT_WEBHOOK_TOKEN,
        SUPABASE_SET: !!process.env.VITE_SUPABASE_URL,
        SUPABASE_SERVICE_ROLE_SET: !!process.env.SUPABASE_SERVICE_ROLE_KEY
      },
      webhooks: webhookLogs.slice().reverse()
    });
  });

  app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', uptime: process.uptime() });
  });

  app.all(/^\/api\/.*/, (req, res) => {
    console.warn(`[Server] API Route not found: ${req.method} ${req.path}`);
    res.status(404).json({ 
      error: `API route ${req.path} not found`,
      method: req.method,
      path: req.path
    });
  });

  // Serve static files and handle SPA routing
  if (process.env.NODE_ENV !== 'production') {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(__dirname, 'dist');
    app.use(express.static(distPath));
    app.get('*all', (req, res) => {
      const indexPath = path.join(distPath, 'index.html');
      if (fs.existsSync(indexPath)) {
        res.sendFile(indexPath);
      } else {
        res.status(200).send('🚀 Nexus Proxy & API Server is running. (API-only mode, frontend is served by Tauri desktop app)');
      }
    });
  }

  // WebSocket setup
  let wss: WebSocketServer;
  const broadcast = (data: any) => {
    if (!wss) return;
    wss.clients.forEach((client) => {
      if (client.readyState === WebSocket.OPEN) {
        client.send(JSON.stringify(data));
      }
    });
  };

  const server = app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Nexus Proxy Server running on http://localhost:${PORT}`);
  });

  wss = new WebSocketServer({ server, path: '/ws' });
  
  const interval = setInterval(() => {
    wss.clients.forEach((ws: any) => {
      if (ws.isAlive === false) return ws.terminate();
      ws.isAlive = false;
      ws.ping();
    });
  }, 30000);

  wss.on('connection', (ws: any) => {
    ws.isAlive = true;
    console.log('[Server] WebSocket client connected');
    
    ws.on('pong', () => {
      ws.isAlive = true;
    });

    ws.on('message', (message: string) => {
      try {
        const data = JSON.parse(message);
        if (data.type === 'PING') {
          ws.send(JSON.stringify({ type: 'PONG', timestamp: Date.now() }));
        }
      } catch (e) {
        // Ignore non-JSON or malformed messages
      }
    });

    ws.on('close', () => {
      console.log('[Server] WebSocket client disconnected');
    });

    ws.on('error', (err: Error) => {
      console.error('[Server] WebSocket error:', err.message);
    });
  });

  wss.on('close', () => {
    clearInterval(interval);
  });
  
  process.on('unhandledRejection', (reason, promise) => {
    console.error('[Server] Unhandled Rejection at:', promise, 'reason:', reason);
  });

  process.on('uncaughtException', (error) => {
    console.error('[Server] Uncaught Exception:', error);
  });
}

// Start the server
startServer().catch(error => {
  console.error('Failed to start server:', error);
  process.exit(1);
});
