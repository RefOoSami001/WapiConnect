# WhatsApp Bot Web Application

A web application for managing WhatsApp sessions and sending messages using the Baileys library.

## Features

- Create and manage WhatsApp sessions
- Send messages to multiple recipients
- Real-time status updates
- Modern and responsive UI
- Auto-reply rules based on triggers and conditions

## Prerequisites

* Node.js 18.x or higher
* MongoDB database
* npm or yarn package manager

## Local Development

1. Clone the repository
2. Install dependencies: `npm install`
3. Create a `.env` file with the following variables:  
```  
PORT=3000  
NODE_ENV=development  
MONGODB_URI=your_mongodb_connection_string  
JWT_SECRET=your_jwt_secret  
```
4. Start the server: `npm start`
5. Open your browser and navigate to `http://localhost:3000`

## Deployment on Render.com

### Prerequisites

* A [Render.com account](https://render.com)
* Your code pushed to a Git repository (GitHub, GitLab, or Bitbucket)

### Deployment Steps

1. Log in to your Render.com account
2. Click on "New Web Service" 
3. Connect your GitHub repository
4. Configure the build:
   * Name: `whatsapp-bot`
   * Region: Choose the closest to your users
   * Branch: `main`
   * Runtime: `Node`
   * Build Command: `npm install`
   * Start Command: `npm start`
5. Set up the required environment variables:
   * `PORT`: 3000
   * `NODE_ENV`: production
   * `MONGODB_URI`: Your MongoDB connection string
   * `JWT_SECRET`: A strong random string for JWT token generation
6. Click "Create Web Service"

### Alternative Deployment with render.yaml

This repository includes a `render.yaml` file for easier deployment:

1. Fork this repository
2. Go to your Render dashboard
3. Click "New" -> "Blueprint"
4. Connect to the forked repository
5. Configure your environment variables
6. Deploy

## Environment Variables Reference

* `PORT`: Port on which the server will run (default: 3000)
* `NODE_ENV`: Application environment (development/production)
* `MONGODB_URI`: MongoDB connection string
* `JWT_SECRET`: Secret key for JWT token generation

## Docker Support

The application includes Docker support. To build and run using Docker:

```
# Build the Docker image
docker build -t whatsapp-bot .

# Run the container
docker run -p 3000:3000 --env-file .env whatsapp-bot
```

## License

MIT 