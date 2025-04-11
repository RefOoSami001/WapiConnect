FROM node:18-alpine

# Install required dependencies
RUN apk add --no-cache git python3 make g++

# Create app directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy app source
COPY . .

# Set environment variables
ENV MONGODB_URI=mongodb://raafatsamy109:hQm3tZYWWEjNI2WS@ac-phjothd-shard-00-00.jdjy8pd.mongodb.net:27017,ac-phjothd-shard-00-01.jdjy8pd.mongodb.net:27017,ac-phjothd-shard-00-02.jdjy8pd.mongodb.net:27017/?replicaSet=atlas-12rk7b-shard-0&ssl=true&authSource=admin&retryWrites=true&w=majority&appName=Cluster0
ENV JWT_SECRET=e67b7ebfdee102eb0e1e5448aeae6dff4f4fe4dde2fb72994fed8b647f3c57ed1e4257593d5f95d7d10457e439b10daa6164bf85954da57054beb12d6df05a48

# Expose port
EXPOSE 3000

# Start the app
CMD ["npm", "start"] 