// databaseConnection.js
require('dotenv').config();

const { MongoClient, ServerApiVersion } = require('mongodb');

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database_name = process.env.MONGODB_DATABASE;

if (!mongodb_host || !mongodb_user || !mongodb_password || !mongodb_database_name) {
    console.error("FATAL ERROR DB_CONN: MongoDB connection details (host, user, password, or database name) missing in .env for databaseConnection.js");
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

let dbConnection; // To store the connected database object

async function connectToDatabase() {
    if (dbConnection) {
        // console.log("DB_CONN: Returning existing database connection.");
        return dbConnection;
    }
    try {
        console.log("DB_CONN: Attempting to connect to MongoDB Atlas (main DB)...");
        await client.connect();
        console.log("DB_CONN: Successfully connected to MongoDB Atlas cluster.");
        dbConnection = client.db(mongodb_database_name);
        console.log(`DB_CONN: Main database set to: ${mongodb_database_name}`);
        return dbConnection;
    } catch (err) {
        console.error("DB_CONN: FATAL ERROR - Failed to connect to MongoDB Atlas (main DB):", err);
        process.exit(1);
    }
}

module.exports = { connectToDatabase, clientInstance: client };