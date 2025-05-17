import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';

dotenv.config();

const JWT_SECRET = process.env.JWT_SECRET || 'fallback_secret_key';

console.log('JWT_SECRET:', JWT_SECRET); // Should log the secret key

const payload = { userId: 1, username: 'testuser' };
const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });

console.log('Generated Token:', token);
