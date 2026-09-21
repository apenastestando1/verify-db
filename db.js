const { MongoClient } = require('mongodb');

let client;
let db;

async function connect() {
  client = new MongoClient(process.env.MONGODB_URI, {
    serverSelectionTimeoutMS: 10000
  });

  await client.connect();
  db = client.db(process.env.MONGODB_DB || 'bot-verificacao');

  const users = db.collection('users');
  const verifications = db.collection('verifications');

  await users.createIndex({ id: 1 }, { unique: true });
  await verifications.createIndex({ user_id: 1 });
  await verifications.createIndex({ guild_id: 1 });

  return { users, verifications };
}

function close() {
  return client ? client.close() : Promise.resolve();
}

module.exports = { connect, close };
