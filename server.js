const dotenv = require('dotenv');
dotenv.config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const authRoutes = require('./routes/authRoutes'); 
require('./mongooseConnection');

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(bodyParser.json());

app.use('/api', authRoutes); 
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
