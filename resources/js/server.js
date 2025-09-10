import express from 'express';
import dotenv from 'dotenv';
import multer from 'multer';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import { PDFDocument } from 'pdf-lib';
import mammoth from 'mammoth';
import { createWorker } from 'tesseract.js';
import cors from 'cors';
import axios from 'axios';
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import rateLimit from 'express-rate-limit';
import OpenAI from 'openai';

// ========== INITIALIZATION ==========
const __dirname = path.dirname(fileURLToPath(import.meta.url));
dotenv.config();

const app = express();
const PORT = process.env.PORT || 5502;

// ========== RATE LIMITING ==========
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);

// ========== DATABASE CONNECTION ==========
const connectDB = async () => {
  try {
    if (process.env.MONGO_URI) {
      await mongoose.connect(process.env.MONGO_URI);
      console.log('✅ Connected to MongoDB Atlas');
    } else {
      await mongoose.connect('mongodb://127.0.0.1:27017/ai-mmi');
      console.log('✅ Connected to local MongoDB');
    }
  } catch (error) {
    console.log('❌ MongoDB connection failed:', error.message);
    console.log('💡 Please check your MongoDB connection string in .env file');
    console.log('💡 If using local MongoDB, make sure it\'s running');
    process.exit(1);
  }
};

connectDB();

// ========== USER SCHEMA ==========
const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true
  },
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true
  },
  password: {
    type: String,
    required: true,
    minlength: 7
  },
  tokens: [{
    token: {
      type: String,
      required: true
    }
  }],
  subscription: {
    type: String,
    enum: ['free', 'basic', 'premium', 'platinum', 'vip'],
    default: 'free'
  },
  promptCount: {
    type: Number,
    default: 0
  },
  subscriptionEndDate: Date,
  createdAt: {
    type: Date,
    default: Date.now
  }
});

userSchema.pre('save', async function(next) {
  if (this.isModified('password')) {
    this.password = await bcrypt.hash(this.password, 8);
  }
  next();
});

userSchema.methods.generateAuthToken = async function() {
  const token = jwt.sign({ _id: this._id }, process.env.JWT_SECRET || 'your-secret-key');
  this.tokens = this.tokens.concat({ token });
  await this.save();
  return token;
};

userSchema.methods.toJSON = function() {
  const user = this.toObject();
  delete user.password;
  delete user.tokens;
  return user;
};

const User = mongoose.model('User', userSchema);

// ========== MIDDLEWARE ==========
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Auth middleware
const auth = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) {
      return res.status(401).send({ error: 'Please authenticate.' });
    }
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');
    const user = await User.findOne({ _id: decoded._id, 'tokens.token': token });
    if (!user) {
      return res.status(401).send({ error: 'Please authenticate.' });
    }
    req.token = token;
    req.user = user;
    next();
  } catch (error) {
    res.status(401).send({ error: 'Please authenticate.' });
  }
};

// ========== FILE UPLOAD CONFIG ==========
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

const fileFilter = (req, file, cb) => {
  const validTypes = [
    'application/pdf',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'text/plain',
    'image/jpeg',
    'image/png'
  ];
  cb(null, validTypes.includes(file.mimetype));
};

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, uploadsDir)
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + '-' + file.originalname)
  }
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter
}).array('files', 3);

// ========== TEXT EXTRACTION ==========
async function extractTextFromFile(filePath, mimetype) {
  try {
    if (mimetype === 'application/pdf') {
      const pdfBytes = fs.readFileSync(filePath);
      const pdfDoc = await PDFDocument.load(pdfBytes);
      return await Promise.all(
        Array.from({ length: pdfDoc.getPageCount() }, async (_, i) => {
          const page = pdfDoc.getPage(i);
          const content = await page.getTextContent();
          return content.items.map(item => item.str).join(' ');
        })
      ).then(pages => pages.join('\n\n'));
    }
    else if (mimetype.includes('word')) {
      const result = await mammoth.extractRawText({ path: filePath });
      return result.value;
    }
    else if (mimetype.startsWith('image/')) {
      const worker = await createWorker('eng');
      const { data: { text } } = await worker.recognize(filePath);
      await worker.terminate();
      return text;
    }
    else if (mimetype === 'text/plain') {
      return fs.readFileSync(filePath, 'utf8');
    }
    return '';
  } catch (err) {
    console.error(`File processing error: ${err.message}`);
    throw new Error(`Could not extract text from ${path.basename(filePath)}`);
  }
}

// ========== CONVERSATION HISTORY MANAGEMENT ==========
const conversationHistory = new Map();

function getConversationHistory(userId) {
  if (!conversationHistory.has(userId)) {
    conversationHistory.set(userId, []);
  }
  return conversationHistory.get(userId);
}

function addToHistory(userId, role, content) {
  const history = getConversationHistory(userId);
  history.push({ role, content });
  if (history.length > 6) {
    conversationHistory.set(userId, history.slice(-6));
  }
}

// ========== SERPAPI INTEGRATION ==========
async function searchWithSerpApi(query, country = 'au') {
  const SERPAPI_KEY = process.env.SERPAPI_KEY;
  if (!SERPAPI_KEY) {
    return null;
  }
  try {
    const response = await axios.get('https://serpapi.com/search', {
      params: {
        engine: 'google',
        q: query,
        api_key: SERPAPI_KEY,
        num: 5,
        hl: 'en',
        gl: country,
        google_domain: 'google.com.au'
      },
      timeout: 10000
    });
    if (response.data.organic_results && response.data.organic_results.length > 0) {
      const results = response.data.organic_results.slice(0, 3).map(result => ({
        title: result.title,
        link: result.link,
        snippet: result.snippet
      }));
      return results;
    }
    return null;
  } catch (error) {
    console.error('SerpAPI Error:', error.response?.data?.error || error.message);
    return null;
  }
}

// ========== RESPONSE VALIDATION ==========
function validateResponse(response) {
  if (!response || response.length < 50) return false;
  const badMarkers = [
    "I don't know",
    "I'm not sure",
    "I can't answer that",
    "I cannot provide",
    "I don't have access",
    "I am not able to",
    "I'm not programmed",
    "I don't understand"
  ];
  if (badMarkers.some(marker => response.toLowerCase().includes(marker.toLowerCase()))) {
    return false;
  }
  const goodMarkers = [
    "visa",
    "stream",
    "requirement",
    "document",
    "process",
    "application",
    "eligibility",
    "Australia",
    "migration",
    "immigration",
    "subclass",
    "temporary",
    "permanent"
  ];
  return goodMarkers.some(marker => response.toLowerCase().includes(marker.toLowerCase()));
}

// ========== AI RESPONSE GENERATION WITH OPENROUTER ==========
async function generateAIResponse(userId, prompt, filesContent = '', useSerpApi = false) {
  try {
    const history = getConversationHistory(userId);

    let webSearchResults = '';
    if (useSerpApi) {
      const searchQuery = `site:.gov.au ${prompt}`;
      const results = await searchWithSerpApi(searchQuery, 'au');
      if (results && results.length > 0) {
        webSearchResults = `\n\n[LATEST WEB SEARCH RESULTS]\n` +
          results.map((result, index) =>
            `Source ${index + 1}: ${result.title}\nURL: ${result.link}\nSummary: ${result.snippet}\n`
          ).join('\n');
      }
    }

    const systemPrompt = `
    ROLE: You are a senior immigration consultant with direct access to official government databases and 20+ years of experience.
    CURRENT DATE: ${new Date().toISOString().split('T')[0]}

    CRITICAL GUIDELINES:
    1. You MUST provide accurate, detailed immigration information
    2. You HAVE access to all visa requirements, streams, and processes
    3. Structure responses with clear headings and bullet points
    4. Include official requirements, processing times, costs, and pathways
    5. For document queries, provide thorough analysis
    6. NEVER say "I don't know" - instead provide the most accurate information available
    7. If unsure about specifics, guide users to official government websites
    8. Use the web search results below to enhance your response with current information

    ${webSearchResults}

    ${filesContent ? `USER PROVIDED DOCUMENTS:\n${filesContent}\n\nANALYZE THESE THOROUGHLY:` : ''}

    RESPONSE FORMAT:
    [Comprehensive Answer]
    Detailed response with accurate information...

    [Key Requirements]
    • Requirement 1
    • Requirement 2
    • Requirement 3

    [Processing Details]
    • Timeframe: 
    • Cost: 
    • PR Pathway: 

    [Official Sources]
    • Link to government website
    `;

    // Build conversation history for OpenRouter
    let messages = [
      {
        role: "system",
        content: systemPrompt
      }
    ];

    // Add previous conversation history
    history.forEach(msg => {
      messages.push({
        role: msg.role === 'user' ? 'user' : 'assistant',
        content: msg.content
      });
    });

    // Add current prompt
    messages.push({
      role: "user",
      content: prompt
    });

    // Initialize OpenAI client for OpenRouter
    const OpenRouterClient = new OpenAI({
      baseURL: "https://openrouter.ai/api/v1",
      apiKey: process.env.OPENROUTER_API_KEY,
      defaultHeaders: {
        "HTTP-Referer": process.env.FRONTEND_URL || "http://localhost:3000",
        "X-Title": "AI-MMI Immigration Assistant"
      }
    });

    // Make request to OpenRouter
    const completion = await OpenRouterClient.chat.completions.create({
      model: "google/gemini-2.5-flash",
      messages: messages,
      max_tokens: 4096,
      temperature: 0.3,
      top_p: 0.8
    });

    const aiResponse = completion.choices[0].message.content;

    if (!validateResponse(aiResponse)) {
      return `${aiResponse}\n\n[Note: For the most current information, please visit the official Australian Home Affairs website: https://immi.homeaffairs.gov.au]`;
    }

    return aiResponse;
  } catch (err) {
    console.error('OpenRouter API Error:', err.message);
    return `I encountered a technical issue. For comprehensive information, please visit official government websites:

• Australia: https://immi.homeaffairs.gov.au/visas
• Canada: https://www.canada.ca/en/immigration-refugees-citizenship/services/visit-canada.html
• UK: https://www.gov.uk/browse/visas-immigration
• USA: https://www.uscis.gov/visit-the-united-states

Alternatively, please try rephriring your question.`;
  }
}

// ========== AUTHENTICATION ENDPOINTS ==========
app.post('/api/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) {
      return res.status(400).json({ error: 'Please provide all required fields' });
    }
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }
    const user = new User({ name, email, password });
    await user.save();
    const token = await user.generateAuthToken();
    res.status(201).json({ user, token });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(400).json({ error: error.message });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Please provide email and password' });
    }
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ error: 'Invalid login credentials' });
    }
    const isPasswordMatch = await bcrypt.compare(password, user.password);
    if (!isPasswordMatch) {
      return res.status(400).json({ error: 'Invalid login credentials' });
    }
    const token = await user.generateAuthToken();
    res.json({ user, token });
  } catch (error) {
    console.error('Login error:', error);
    res.status(400).json({ error: error.message });
  }
});

app.post('/api/logout', auth, async (req, res) => {
  try {
    req.user.tokens = req.user.tokens.filter(token => token.token !== req.token);
    await req.user.save();
    res.json({ message: 'Logged out successfully' });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/profile', auth, async (req, res) => {
  res.json({ user: req.user });
});

// ========== CHAT ENDPOINT WITH PROMPT LIMIT ==========
app.post('/api/chat', auth, (req, res) => {
  upload(req, res, async (err) => {
    if (err) {
      console.error('File upload error:', err);
      return res.status(400).json({ error: err.message });
    }
    try {
      const { message, useSerpApi = false } = req.body;
      const user = req.user;
      // ====== REMOVE OR COMMENT OUT THIS BLOCK FOR UNLIMITED QUOTA ======
      // if (user.subscription === 'free' && user.promptCount >= 5) {
      //   return res.status(402).json({
      //     error: 'You have reached your free prompt limit. Please upgrade your subscription to continue.',
      //     requiresUpgrade: true
      //   });
      // }
      // ================================================================
      if (!message && (!req.files || req.files.length === 0)) {
        return res.status(400).json({ error: 'Please provide a message or upload files' });
      }
      let fullPrompt = message || 'Please analyze the uploaded documents';
      let filesContent = '';
      if (req.files?.length > 0) {
        try {
          const fileContents = await Promise.all(
            req.files.map(file => extractTextFromFile(file.path, file.mimetype))
          );
          filesContent = `Uploaded documents content:\n${fileContents.join('\n\n---\n\n')}`;
        } finally {
          req.files.forEach(file => {
            try {
              fs.unlinkSync(file.path);
            } catch (cleanupErr) {
              console.error('File cleanup error:', cleanupErr);
            }
          });
        }
      }
      addToHistory(user._id.toString(), 'user', fullPrompt);
      const aiResponse = await generateAIResponse(user._id.toString(), fullPrompt, filesContent, useSerpApi);
      addToHistory(user._id.toString(), 'model', aiResponse);
      // ====== OPTIONAL: REMOVE THIS FOR TESTING ======
      // if (user.subscription === 'free') {
      //   user.promptCount += 1;
      //   await user.save();
      // }
      // ===============================================
      res.json({
        response: aiResponse,
        promptCount: user.promptCount,
        maxPrompts: user.subscription === 'free' ? 5 : Infinity
      });
    } catch (error) {
      console.error('API Error:', error.message);
      res.status(500).json({
        error: error.message || 'An error occurred while processing your request'
      });
    }
  });
});

// ========== PAYMENT ENDPOINTS ==========
app.get('/api/payment/initiate', auth, async (req, res) => {
  try {
    const { plan } = req.query;
    const validPlans = ['basic', 'premium', 'platinum', 'vip'];
    if (!validPlans.includes(plan)) {
      return res.status(400).json({ error: 'Invalid plan' });
    }
    const planPrices = {
      'basic': 39,
      'premium': 299,
      'platinum': 699,
      'vip': 999
    };
    const price = planPrices[plan];
    const paymentId = `pay_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    res.json({
      paymentId,
      plan,
      price,
      currency: 'AUD',
      description: `AI-MMI ${plan} Plan Subscription`,
      successUrl: `${process.env.FRONTEND_URL}/payment-success?paymentId=${paymentId}&plan=${plan}`,
      cancelUrl: `${process.env.FRONTEND_URL}/payment-cancel`
    });
  } catch (error) {
    console.error('Payment initiation error:', error);
    res.status(400).json({ error: error.message });
  }
});

app.post('/api/payment/verify', auth, async (req, res) => {
  try {
    const { paymentId, plan } = req.body;
    req.user.subscription = plan;
    req.user.promptCount = 0;
    const endDate = new Date();
    endDate.setDate(endDate.getDate() + 30);
    req.user.subscriptionEndDate = endDate;
    await req.user.save();
    res.json({
      success: true,
      message: `Subscription upgraded to ${plan} successfully`,
      user: req.user
    });
  } catch (error) {
    console.error('Payment verification error:', error);
    res.status(400).json({ error: error.message });
  }
});

// ========== SUBSCRIPTION ENDPOINTS ==========
app.post('/api/subscription/upgrade', auth, async (req, res) => {
  try {
    const { plan } = req.body;
    const validPlans = ['basic', 'premium', 'platinum', 'vip'];
    if (!validPlans.includes(plan)) {
      return res.status(400).json({ error: 'Invalid plan' });
    }
    req.user.subscription = plan;
    req.user.promptCount = 0;
    const endDate = new Date();
    endDate.setDate(endDate.getDate() + 30);
    req.user.subscriptionEndDate = endDate;
    await req.user.save();
    res.json({
      message: `Subscription upgraded to ${plan} successfully`,
      user: req.user
    });
  } catch (error) {
    console.error('Subscription upgrade error:', error);
    res.status(400).json({ error: error.message });
  }
});

app.get('/api/subscription/plans', (req, res) => {
  const plans = [
    {
      id: 'free',
      name: 'Free Plan',
      price: 0,
      features: [
        '5 free prompts',
        'Basic document analysis',
        'Limited access to features'
      ],
      maxPrompts: 5
    },
    {
      id: 'basic',
      name: 'Basic Plan',
      price: 39,
      features: [
        'Unlimited prompts for 30 days',
        'Enhanced document analysis',
        'Priority support'
      ]
    },
    {
      id: 'premium',
      name: 'Premium Plan',
      price: 299,
      features: [
        'Everything in Basic plan',
        'Advanced document processing',
        'Dedicated support',
        'Early access to new features'
      ]
    },
    {
      id: 'platinum',
      name: 'Platinum Plan',
      price: 699,
      features: [
        'Everything in Premium plan',
        '24/7 priority support',
        'Custom features',
        'Personalized consultation'
      ]
    },
    {
      id: 'vip',
      name: 'VIP Plan',
      price: 999,
      features: [
        'Everything in Platinum plan',
        'Full visa consultation',
        'Application submission service',
        'AI + agent blended services'
      ]
    }
  ];
  res.json({ plans });
});

// ========== HEALTH CHECK ==========
app.get('/api/health', async (req, res) => {
  try {
    const OpenRouterClient = new OpenAI({
      baseURL: "https://openrouter.ai/api/v1",
      apiKey: process.env.OPENROUTER_API_KEY,
    });
    const testResult = await OpenRouterClient.chat.completions.create({
      model: "google/gemini-2.5-flash",
      messages: [{ role: "user", content: "Health check - respond with OK" }],
      max_tokens: 10
    });
    res.json({
      status: "healthy",
      model: "google/gemini-2.5-flash (via OpenRouter)",
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      memoryUsage: process.memoryUsage(),
      serpapiConfigured: !!process.env.SERPAPI_KEY,
      openrouterConfigured: !!process.env.OPENROUTER_API_KEY
    });
  } catch (err) {
    res.status(503).json({
      status: "unhealthy",
      error: err.message,
      details: "OpenRouter API unavailable"
    });
  }
});

// ========== OTHER ENDPOINTS ==========
app.get('/api/serpapi/status', (req, res) => {
  const SERPAPI_KEY = process.env.SERPAPI_KEY;
  res.json({
    configured: !!SERPAPI_KEY,
    keyPresent: !!SERPAPI_KEY,
    keyLength: SERPAPI_KEY ? SERPAPI_KEY.length : 0,
    status: SERPAPI_KEY ? 'configured' : 'not_configured'
  });
});

app.post('/api/clear-conversation', auth, (req, res) =>{
  const userId = req.user._id.toString();
  conversationHistory.delete(userId);
  res.json({ status: "success", message: "Conversation history cleared" });
});

app.get('/api/test', (req, res) => {
  res.json({
    message: "Backend is working!",
    timestamp: new Date().toISOString(),
    version: "1.0.0"
  });
});

// ========== ERROR HANDLING MIDDLEWARE ==========
app.use((error, req, res, next) => {
  console.error('Unhandled error:', error);
  res.status(500).json({ error: 'Internal server error' });
});

// ========== SERVE STATIC FILES ==========
app.use(express.static(__dirname));

// ========== SERVER START ==========
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Server running on http://0.0.0.0:${PORT}`);
  console.log(`🔌 Health check: http://0.0.0.0:${PORT}/api/health`);
  console.log(`💬 Chat endpoint: POST http://0.0.0.0:${PORT}/api/chat`);
  console.log(`🔐 Auth endpoints: /api/register, /api/login, /api/logout`);
  console.log(`💳 Payment endpoints available`);
}).on('error', (err) => {
  console.error('Server startup error:', err);
});

// ========== ERROR HANDLING ==========
process.on('unhandledRejection', (err) => {
  console.error('Unhandled rejection:', err);
});

process.on('uncaughtException', (err) => {
  console.error('Uncaught exception:', err);
  process.exit(1);
});