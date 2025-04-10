redis = require('redis');
const dotenv = require('dotenv');
dotenv.config();

let client;

const connectClient = async () => {
  const redisClient = redis.createClient({
    // password: process.env.REDIS_CLIENT_PASSWORD,
    socket: {
      host: process.env.REDIS_HOST,
      port: process.env.REDIS_HOST_PORT,
    },
  });

  redisClient.on('error', (err) => {
    console.error('Redis connection error:', err);
  });

  redisClient.on('ready', () => {
    console.log('Redis client connected');
    client = redisClient; 
  });

  await redisClient.connect(); 
};

const getAsync = async (key) => {
  if (!client) throw new Error('Redis client not initialized');
  return client.get(key); 
};

const setAsync = async (key, value, seconds) => {
  if (!client) throw new Error('Redis client not initialized');
  return client.set(key, value,{
    EX:seconds
  });
};

const delAsync = async (key) => {
  if (!client) throw new Error('Redis client not initialized');
  return client.del(key); 
};

module.exports = {
  connectClient,
  getAsync,
  setAsync,
  delAsync,
};
