# WhatsApp Bot Web Application

A web application for managing WhatsApp sessions and sending messages using the Baileys library.

## Features

- Create and manage WhatsApp sessions
- Send messages to multiple recipients
- Real-time status updates
- Modern and responsive UI
- Auto-reply rules based on triggers and conditions
- Google OAuth authentication
- Points system for user engagement
- User profile management

## Prerequisites

* Node.js 18.x or higher
* MongoDB database
* npm or yarn package manager
* Google OAuth credentials (for authentication)

## Local Development

1. Clone the repository
2. Install dependencies: `npm install`
3. Create a `.env` file with the following variables:  
```  
PORT=3000  
NODE_ENV=development  
MONGODB_URI=your_mongodb_connection_string  
JWT_SECRET=your_jwt_secret  
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
GOOGLE_CALLBACK_URL=http://localhost:3000/auth/google/callback
```
4. Start the server: `npm start`
5. Open your browser and navigate to `http://localhost:3000`

## Authentication

The application supports two authentication methods:
1. Google OAuth (Recommended)
   - Users can sign in with their Google account
   - Profile picture and basic information are automatically synced
2. Email/Password (Legacy)
   - Traditional email and password authentication

## Points System

Users are awarded points for various actions:
- Initial signup: 50 points
- Daily login bonus
- Message sending activities
- Session management tasks

Points can be used for:
- Priority message sending
- Advanced features access
- Session management tools

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
   * `GOOGLE_CLIENT_ID`: Your Google OAuth client ID
   * `GOOGLE_CLIENT_SECRET`: Your Google OAuth client secret
   * `GOOGLE_CALLBACK_URL`: Your production callback URL
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
* `GOOGLE_CLIENT_ID`: Google OAuth client ID
* `GOOGLE_CLIENT_SECRET`: Google OAuth client secret
* `GOOGLE_CALLBACK_URL`: OAuth callback URL

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