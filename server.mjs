import express from 'express';
import fs from 'fs';
import { checklistData } from './data.mjs';

const app = express();
const port = process.env.PORT || 3000;
const stateFilePath = './state.json';

// Middleware to parse JSON bodies
app.use(express.json());

// Load initial state from file
let state = { items: {}, meta: {} };
if (fs.existsSync(stateFilePath)) {
  state = JSON.parse(fs.readFileSync(stateFilePath));
}

// Serve static files from the 'dist' directory
app.use(express.static('dist'));

// API endpoint to get the checklist data
app.get('/api/data', (req, res) => {
  res.json(checklistData);
});

// API endpoints for state persistence
app.get('/api/state', (req, res) => {
  res.json(state);
});

app.post('/api/state', (req, res) => {
  state = req.body;
  fs.writeFileSync(stateFilePath, JSON.stringify(state, null, 2));
  res.status(200).send('State saved');
});


app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
