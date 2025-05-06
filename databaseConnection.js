require('dotenv').config();

const { MongoClient, ServerApiVersion } = require('mongodb');

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database_name = process.env.MONGODB_DATABASE;

if (!mongodb_host || !mongodb_user || !mongodb_password || !mongodb_database_name) {
    console.error("FATAL ERROR DB_CONN: MongoDB connection details missing in .env");
    process.exit(1);
}

const atlasURI = `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/${mongodb_database_name}?retryWrites=true&w=majority`;

const client = new MongoClient(atlasURI, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

let dbConnection;

async function connectToDatabase() {
    if (dbConnection) {
        return dbConnection;
    }
    try {
        await client.connect();
        dbConnection = client.db(mongodb_database_name);
        return dbConnection;
    } catch (err) {
        console.error("DB_CONN: Failed to connect to MongoDB Atlas:", err);
        process.exit(1);
    }
}

module.exports = { connectToDatabase, clientInstance: client };