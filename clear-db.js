const mongoose = require('mongoose');

// MongoDB connection
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://raafatsamy109:hQm3tZYWWEjNI2WS@ac-phjothd-shard-00-00.jdjy8pd.mongodb.net:27017,ac-phjothd-shard-00-01.jdjy8pd.mongodb.net:27017,ac-phjothd-shard-00-02.jdjy8pd.mongodb.net:27017/?replicaSet=atlas-12rk7b-shard-0&ssl=true&authSource=admin&retryWrites=true&w=majority&appName=Cluster0';

async function clearDatabase() {
    try {
        console.log('Connecting to MongoDB...');
        await mongoose.connect(MONGODB_URI, {
            useNewUrlParser: true,
            useUnifiedTopology: true,
            serverSelectionTimeoutMS: 5000,
        });
        console.log('Connected to MongoDB Atlas');

        // Get all collections
        const collections = await mongoose.connection.db.listCollections().toArray();
        const collectionNames = collections.map(collection => collection.name);

        console.log('Found collections:', collectionNames);

        // Drop each collection
        for (const collectionName of collectionNames) {
            console.log(`Dropping collection: ${collectionName}`);
            await mongoose.connection.db.collection(collectionName).drop();
            console.log(`Collection ${collectionName} dropped successfully`);
        }

        console.log('All collections have been dropped successfully');
        console.log('Database is now empty and ready for a fresh start');
    } catch (error) {
        console.error('Error clearing database:', error);
    } finally {
        // Close the connection
        await mongoose.connection.close();
        console.log('MongoDB connection closed');
    }
}

// Run the function
clearDatabase(); 