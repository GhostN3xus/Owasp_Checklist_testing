import express from 'express';
import fs from 'fs';
import path from 'path';
import multer from 'multer';
import { Low } from 'lowdb';
import { JSONFile } from 'lowdb/node';
import { checklistData } from './data.mjs';

const app = express();
const port = process.env.PORT || 3000;
const stateFilePath = './state.json';
const uploadDir = './uploads';

// Setup lowdb
const adapter = new JSONFile(stateFilePath);
const defaultData = { items: {}, meta: {} };
const db = new Low(adapter, defaultData);
await db.read();

// Create uploads directory
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir);
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, `${uniqueSuffix}-${file.originalname}`);
  },
});

const upload = multer({ storage });

// Middleware to parse JSON bodies
app.use(express.json());

// Serve static files
app.use(express.static('dist'));
app.use('/uploads', express.static(path.resolve(uploadDir)));

// API endpoint to get the checklist data
app.get('/api/data', (req, res) => {
  res.json(checklistData);
});

// API endpoint for uploads
app.post('/api/upload', upload.single('evidence'), (req, res) => {
  if (!req.file) {
    return res.status(400).send('No file uploaded.');
  }
  res.json({ filePath: `/uploads/${req.file.filename}` });
});

// API endpoints for state persistence
app.get('/api/state', (req, res) => {
  res.json(db.data);
});

app.post('/api/state', async (req, res) => {
  db.data = req.body;
  await db.write();
  res.status(200).send('State saved');
});


app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
