const express = require('express');

const app = express();

// Load environment variables first
require('dotenv').config();

// Add CORS headers
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*'); // Allow all domains, or specify your domain
    res.header('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }
    next();
});

// Add crypto polyfill
try {
    global.crypto = require('crypto');
} catch (err) {
    console.error('Failed to load crypto polyfill:', err);
}

const { default: makeWASocket, DisconnectReason } = require('@whiskeysockets/baileys');
const { Boom } = require('@hapi/boom');
const mongoose = require('mongoose');
const QRCode = require('qrcode');
const { createServer } = require('http');
const { Server } = require('socket.io');
const { useMongoDBAuthState } = require('mongo-baileys');
const dotenv = require('dotenv');
const rateLimit = require('express-rate-limit');
const Session = require('./models/Session');
const { router: authRouter, auth } = require('./routes/auth');
const AutoReplyRule = require('./models/AutoReplyRule');

// Set the MongoDB URI from environment variables
const MONGODB_URI = process.env.MONGODB_URI;
if (!MONGODB_URI) {
    console.error('MONGODB_URI is not defined in environment variables');
    process.exit(1);
}

// Ensure JWT_SECRET is set
if (!process.env.JWT_SECRET) {
    console.error('JWT_SECRET is not set in environment variables. Please set it for security.');
    process.exit(1);
}

const server = createServer(app);
const io = new Server(server);

// Increase body parser limit for handling large image payloads
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // limit each IP to 100 requests per windowMs
});

app.use(limiter);
app.use(express.static('public'));

// Auth routes
app.use('/api/auth', authRouter);

// Store active sessions
const sessions = new Map();

// MongoDB connection
mongoose.connect(MONGODB_URI, {
    serverSelectionTimeoutMS: 5000,
})
    .then(() => console.log('Connected to MongoDB Atlas'))
    .catch(err => {
        console.error('MongoDB connection error:', err);
        process.exit(1);
    });

// Function to create a new WhatsApp session
async function createSession(sessionId, userId) {
    try {
        // First, check if session already exists in memory
        if (sessions.has(sessionId)) {
            const existingSession = sessions.get(sessionId);
            if (existingSession?.sock) {
                try {
                    if (typeof existingSession.sock.end === 'function') {
                        existingSession.sock.end();
                    }

                    if (typeof existingSession.sock.removeAllListeners === 'function') {
                        existingSession.sock.removeAllListeners();
                    } else if (existingSession.sock.ev && typeof existingSession.sock.ev.removeAllListeners === 'function') {
                        existingSession.sock.ev.removeAllListeners();
                    }
                } catch (cleanupError) {
                    console.error(`Error cleaning up session ${sessionId}:`, cleanupError);
                }
            }
            sessions.delete(sessionId);
        }

        // Create a new collection for this session's auth state
        const authCollection = mongoose.connection.collection(`authState_${sessionId}`);

        // Create or update session in MongoDB with initial state
        await Session.findOneAndUpdate(
            { sessionId, userId },
            {
                sessionId,
                userId,
                status: 'connecting',
                phoneNumber: null,
                lastActive: new Date()
            },
            { upsert: true }
        );

        // Get MongoDB collection for auth state
        const { state, saveCreds } = await useMongoDBAuthState(authCollection);

        const sock = makeWASocket({
            auth: state,
            printQRInTerminal: true,
            connectTimeoutMs: 60000,
            retryRequestDelayMs: 2000,
            maxRetries: 5,
            browser: ["Chrome (Linux)", "Chrome", "99.0.4844." + sessionId.slice(-4)],
            key: `whatsapp-bot-${sessionId}`,
            logger: {
                info: () => { },
                debug: () => { },
                warn: () => { },
                error: console.error,
                trace: () => { },
                child: () => ({
                    info: () => { },
                    debug: () => { },
                    warn: () => { },
                    error: console.error,
                    trace: () => { }
                })
            }
        });

        // Store session in memory with userId
        sessions.set(sessionId, { sock, userId });

        // Handle connection updates
        sock.ev.on('connection.update', async (update) => {
            const { connection, lastDisconnect, qr } = update;

            if (qr) {
                const qrCode = await QRCode.toDataURL(qr);
                io.emit(`qr-${sessionId}`, qrCode);

                await Session.findOneAndUpdate(
                    { sessionId, userId },
                    { status: 'connecting' }
                );
            }

            if (connection === 'close') {
                const statusCode = (lastDisconnect?.error)?.output?.statusCode;
                const shouldReconnect = statusCode !== DisconnectReason.loggedOut &&
                    statusCode !== DisconnectReason.connectionClosed &&
                    statusCode !== 440;

                console.log(`Connection closed for session ${sessionId}, status code: ${statusCode}, should reconnect: ${shouldReconnect}`);

                if (shouldReconnect) {
                    console.log(`Reconnecting session: ${sessionId}`);
                    setTimeout(() => createSession(sessionId, userId), 5000);
                } else {
                    if (sessions.has(sessionId)) {
                        const session = sessions.get(sessionId);
                        if (session?.sock) {
                            try {
                                if (typeof session.sock.end === 'function') {
                                    session.sock.end();
                                }

                                if (typeof session.sock.removeAllListeners === 'function') {
                                    session.sock.removeAllListeners();
                                } else if (session.sock.ev && typeof session.sock.ev.removeAllListeners === 'function') {
                                    // Try to access event emitter if available
                                    session.sock.ev.removeAllListeners();
                                }
                            } catch (cleanupError) {
                                console.log(`Error cleaning up session ${sessionId}:`, cleanupError);
                            }
                        }
                        sessions.delete(sessionId);
                    }

                    await Session.findOneAndUpdate(
                        { sessionId, userId },
                        {
                            status: 'disconnected',
                            lastActive: new Date()
                        }
                    );

                    try {
                        await authCollection.drop();
                    } catch (error) {
                        console.log(`Error dropping auth collection for session ${sessionId}:`, error);
                    }

                    io.emit(`session-${sessionId}-status`, 'disconnected');
                }
            } else if (connection === 'open') {
                console.log(`Connection opened for session: ${sessionId}`);
                const user = sock.user;
                const phoneNumber = user?.id?.split(':')[0] || 'Unknown';
                console.log(`User phone number for session ${sessionId}: ${phoneNumber}`);

                await Session.findOneAndUpdate(
                    { sessionId, userId },
                    {
                        status: 'connected',
                        phoneNumber,
                        lastActive: new Date()
                    }
                );

                // Update session in memory with phone number
                sessions.set(sessionId, { sock, userId, phoneNumber });
                io.emit(`session-${sessionId}-status`, 'connected');
                io.emit(`session-${sessionId}-phone`, phoneNumber);
            }
        });

        sock.ev.on('creds.update', saveCreds);

        // Handle incoming messages
        sock.ev.on('messages.upsert', async ({ messages, type }) => {
            console.log('Received messages.upsert event:', { type, messageCount: messages.length });

            if (type !== 'notify') {
                console.log('Skipping non-notify message type');
                return;
            }

            for (const message of messages) {
                console.log('Processing message:', {
                    from: message.key.remoteJid,
                    fromMe: message.key.fromMe,
                    hasText: !!message.message?.conversation || !!message.message?.extendedTextMessage?.text,
                    hasCaption: !!message.message?.imageMessage?.caption || !!message.message?.videoMessage?.caption || !!message.message?.documentMessage?.caption
                });

                // Skip messages from groups or status updates
                if (message.key.remoteJid.endsWith('@g.us') || message.key.remoteJid.endsWith('@broadcast')) {
                    console.log('Skipping group/broadcast message');
                    continue;
                }

                // Skip messages from the bot itself
                if (message.key.fromMe) {
                    console.log('Skipping message from bot');
                    continue;
                }

                // Get the session from memory
                const session = sessions.get(sessionId);
                if (!session) {
                    console.error(`Session ${sessionId} not found in memory. Available sessions:`, Array.from(sessions.keys()));
                    continue;
                }

                console.log('Found session:', {
                    sessionId,
                    userId: session.userId,
                    hasSock: !!session.sock
                });

                // Find active auto-reply rules for this session
                const rules = await AutoReplyRule.find({
                    sessionId,
                    userId: session.userId,
                    isActive: true
                });

                console.log(`Found ${rules.length} active auto-reply rules for session ${sessionId}:`, rules.map(r => ({
                    name: r.name,
                    triggerType: r.triggerType,
                    triggerValue: r.triggerValue,
                    isActive: r.isActive
                })));

                if (rules.length === 0) {
                    console.log('No active rules found, skipping');
                    continue;
                }

                // Get the message text
                let messageText = '';
                if (message.message?.conversation) {
                    messageText = message.message.conversation;
                } else if (message.message?.extendedTextMessage?.text) {
                    messageText = message.message.extendedTextMessage.text;
                } else if (message.message?.imageMessage?.caption) {
                    messageText = message.message.imageMessage.caption;
                } else if (message.message?.videoMessage?.caption) {
                    messageText = message.message.videoMessage.caption;
                } else if (message.message?.documentMessage?.caption) {
                    messageText = message.message.documentMessage.caption;
                }

                if (!messageText) {
                    console.log('No text content found in message');
                    continue;
                }

                console.log(`Processing message text: "${messageText}"`);

                // Check each rule
                for (const rule of rules) {
                    let shouldReply = false;
                    console.log(`Checking rule: ${rule.name} (${rule.triggerType}: ${rule.triggerValue})`);

                    // Check trigger conditions
                    switch (rule.triggerType) {
                        case 'keyword':
                            shouldReply = messageText.toLowerCase().includes(rule.triggerValue.toLowerCase());
                            break;
                        case 'regex':
                            try {
                                const regex = new RegExp(rule.triggerValue, 'i');
                                shouldReply = regex.test(messageText);
                            } catch (error) {
                                console.error('Invalid regex in auto-reply rule:', error);
                            }
                            break;
                        case 'exact':
                            shouldReply = messageText.toLowerCase() === rule.triggerValue.toLowerCase();
                            break;
                        case 'contains':
                            shouldReply = messageText.toLowerCase().includes(rule.triggerValue.toLowerCase());
                            break;
                    }

                    console.log(`Trigger check result for rule ${rule.name}: ${shouldReply}`);

                    if (!shouldReply) {
                        console.log('Rule conditions not met, skipping');
                        continue;
                    }

                    // Check time restrictions
                    if (rule.conditions.timeRestricted) {
                        const now = new Date();
                        const currentHour = now.getHours();
                        const currentMinute = now.getMinutes();
                        const currentTime = `${currentHour.toString().padStart(2, '0')}:${currentMinute.toString().padStart(2, '0')}`;
                        const currentDay = now.getDay();

                        console.log(`Time check - Current: ${currentTime}, Start: ${rule.conditions.startTime}, End: ${rule.conditions.endTime}, Day: ${currentDay}`);

                        // Check if current day is in allowed days
                        if (rule.conditions.daysOfWeek && rule.conditions.daysOfWeek.length > 0) {
                            if (!rule.conditions.daysOfWeek.includes(currentDay)) {
                                console.log('Day not in allowed days');
                                continue;
                            }
                        }

                        // Check if current time is within allowed time range
                        if (rule.conditions.startTime && rule.conditions.endTime) {
                            if (currentTime < rule.conditions.startTime || currentTime > rule.conditions.endTime) {
                                console.log('Time not in allowed range');
                                continue;
                            }
                        }
                    }

                    // Check contact restrictions
                    if (rule.conditions.contactRestricted) {
                        const senderJid = message.key.remoteJid;
                        const senderNumber = senderJid.split('@')[0];

                        console.log(`Contact check - Sender: ${senderNumber}`);

                        // Check if sender is in allowed contacts
                        if (rule.conditions.allowedContacts && rule.conditions.allowedContacts.length > 0) {
                            if (!rule.conditions.allowedContacts.includes(senderNumber)) {
                                console.log('Sender not in allowed contacts');
                                continue;
                            }
                        }

                        // Check if sender is in excluded contacts
                        if (rule.conditions.excludedContacts && rule.conditions.excludedContacts.includes(senderNumber)) {
                            console.log('Sender in excluded contacts');
                            continue;
                        }
                    }

                    // If we get here, we should send a reply
                    try {
                        const jid = message.key.remoteJid;
                        console.log(`Sending auto-reply for rule: ${rule.name} to ${jid}`);

                        // Send the appropriate response
                        if (rule.responseType === 'text') {
                            await sock.sendMessage(jid, { text: rule.responseContent });
                        } else if (rule.responseType === 'image' && rule.imageUrl) {
                            await sock.sendMessage(jid, {
                                image: { url: rule.imageUrl },
                                caption: rule.responseContent
                            });
                        } else if (rule.responseType === 'template') {
                            // Handle template messages if needed
                            await sock.sendMessage(jid, { text: rule.responseContent });
                        }

                        console.log(`Auto-reply sent successfully for rule: ${rule.name}`);
                    } catch (error) {
                        console.error(`Error sending auto-reply for rule ${rule.name}:`, error);
                    }
                }
            }
        });

        return sock;
    } catch (error) {
        console.error(`Error creating session ${sessionId}:`, error);
        await Session.findOneAndUpdate(
            { sessionId, userId },
            { status: 'disconnected' }
        );
        throw error;
    }
}

// API endpoints
app.post('/api/create-session', auth, async (req, res) => {
    const sessionId = Date.now().toString();
    await createSession(sessionId, req.user._id);
    res.json({ sessionId });
});

// Add endpoint to check existing sessions
app.get('/api/check-sessions', auth, async (req, res) => {
    console.log('Checking for existing sessions via API...');
    try {
        const existingSessions = await Session.find({ userId: req.user._id });
        console.log(`Found ${existingSessions.length} existing sessions via API`);

        const sessions = existingSessions.map(session => ({
            sessionId: session.sessionId,
            status: session.status,
            phoneNumber: session.phoneNumber
        }));

        res.json({ sessions });
    } catch (error) {
        console.error('Error checking sessions:', error);
        res.status(500).json({ error: error.message });
    }
});

// Add endpoint to get session statuses
app.get('/api/session-statuses', auth, async (req, res) => {
    console.log('Getting session statuses...');
    try {
        const sessionStatuses = {};
        const dbSessions = await Session.find({ userId: req.user._id });

        // Get all active sessions from the sessions Map for this user
        for (const [sessionId, session] of sessions.entries()) {
            if (session.userId.toString() === req.user._id.toString()) {
                sessionStatuses[sessionId] = {
                    status: 'connected',
                    phoneNumber: session.phoneNumber
                };
            }
        }

        // Add sessions from database that aren't in memory
        dbSessions.forEach(session => {
            if (!sessionStatuses[session.sessionId]) {
                sessionStatuses[session.sessionId] = {
                    status: session.status,
                    phoneNumber: session.phoneNumber
                };
            }
        });

        console.log('Session statuses:', sessionStatuses);
        res.json(sessionStatuses);
    } catch (error) {
        console.error('Error getting session statuses:', error);
        res.status(500).json({ error: error.message });
    }
});

// Add endpoint to delete a session
app.delete('/api/delete-session/:sessionId', auth, async (req, res) => {
    const sessionId = req.params.sessionId;
    console.log(`Deleting session: ${sessionId}`);

    try {
        // Remove from active sessions if it belongs to the user
        if (sessions.has(sessionId)) {
            const session = sessions.get(sessionId);
            if (session.userId.toString() === req.user._id.toString()) {
                if (session?.sock) {
                    try {
                        if (typeof session.sock.end === 'function') {
                            session.sock.end();
                        }

                        if (typeof session.sock.removeAllListeners === 'function') {
                            session.sock.removeAllListeners();
                        } else if (session.sock.ev && typeof session.sock.ev.removeAllListeners === 'function') {
                            // Try to access event emitter if available
                            session.sock.ev.removeAllListeners();
                        }
                    } catch (cleanupError) {
                        console.log(`Error cleaning up session ${sessionId}:`, cleanupError);
                    }
                }
                sessions.delete(sessionId);
            }
        }

        // Delete session from MongoDB
        await Session.findOneAndDelete({ sessionId, userId: req.user._id });
        console.log(`Session deleted from database: ${sessionId}`);

        res.json({ success: true });
    } catch (error) {
        console.error(`Error deleting session ${sessionId}:`, error);
        res.status(500).json({ error: error.message });
    }
});

// Add input validation middleware
const validatePhoneNumber = (req, res, next) => {
    const { numbers } = req.body;
    if (!numbers) {
        return res.status(400).json({ error: 'Phone numbers are required' });
    }

    const phoneNumbers = numbers.split('\n').map(num => num.trim()).filter(num => num);
    const validNumbers = phoneNumbers.every(num => /^\d{10,15}$/.test(num.replace(/\D/g, '')));

    if (!validNumbers) {
        return res.status(400).json({ error: 'Invalid phone number format' });
    }

    next();
};

// Add endpoint to send message
app.post('/api/send-message', auth, validatePhoneNumber, async (req, res) => {
    const { sessionId, numbers, message, imageData } = req.body;
    console.log('Received message request:', { sessionId, numbers, message, hasImage: !!imageData });

    const session = sessions.get(sessionId);
    if (!session || session.userId.toString() !== req.user._id.toString()) {
        return res.status(404).json({ error: 'Session not found' });
    }

    try {
        const phoneNumbers = numbers.split('\n').map(num => num.trim()).filter(num => num);
        const results = [];

        await new Promise(resolve => setTimeout(resolve, 1000));

        for (const number of phoneNumbers) {
            try {
                const formattedNumber = number.replace(/\D/g, '');
                const jid = `${formattedNumber}@s.whatsapp.net`;
                console.log('Sending message to JID:', jid);

                if (imageData) {
                    // Handle image sending
                    if (imageData.url) {
                        // Send image from URL
                        await session.sock.sendMessage(jid, {
                            image: { url: imageData.url },
                            caption: message || ''
                        });
                    } else if (typeof imageData === 'string') {
                        // Send image from base64 data
                        const buffer = Buffer.from(imageData, 'base64');
                        await session.sock.sendMessage(jid, {
                            image: buffer,
                            caption: message || ''
                        });
                    }
                } else {
                    // Send text message
                    await session.sock.sendMessage(jid, { text: message });
                }

                console.log('Message sent successfully to:', number);
                results.push({ number, success: true });
            } catch (error) {
                console.error('Error sending message to:', number, error);
                results.push({ number, success: false, error: error.message });
            }
        }

        res.json({ success: true, results });
    } catch (error) {
        console.error('Error sending messages:', error);
        res.status(500).json({ error: error.message });
    }
});

// Check existing sessions on startup
async function checkExistingSessions() {
    try {
        const existingSessions = await Session.find({});
        for (const session of existingSessions) {
            try {
                if (session.status === 'connected') {
                    await createSession(session.sessionId, session.userId);
                } else {
                    await Session.findOneAndUpdate(
                        { sessionId: session.sessionId },
                        { status: 'disconnected' }
                    );
                }
            } catch (error) {
                console.error(`Failed to restore session ${session.sessionId}:`, error);
                await Session.findOneAndUpdate(
                    { sessionId: session.sessionId },
                    { status: 'disconnected' }
                );
            }
        }
    } catch (error) {
        console.error('Error checking existing sessions:', error);
    }
}

// Health check endpoint
app.get('/health', (req, res) => {
    res.status(200).json({ status: 'ok' });
});

// Add cleanup function for stale auth states
async function cleanupStaleAuthStates() {
    try {
        const collections = await mongoose.connection.db.listCollections().toArray();
        const authCollections = collections
            .filter(col => col.name.startsWith('authState_'))
            .map(col => col.name);

        const activeSessions = await Session.find({
            status: { $ne: 'disconnected' },
            lastActive: { $gt: new Date(Date.now() - 24 * 60 * 60 * 1000) }
        });
        const activeSessionIds = new Set(activeSessions.map(session => `authState_${session.sessionId}`));

        for (const collectionName of authCollections) {
            if (!activeSessionIds.has(collectionName)) {
                try {
                    await mongoose.connection.db.dropCollection(collectionName);
                    console.log(`Dropped stale auth collection: ${collectionName}`);
                } catch (error) {
                    console.error(`Error dropping collection ${collectionName}:`, error);
                }
            }
        }
    } catch (error) {
        console.error('Error cleaning up stale auth states:', error);
    }
}

// Add cleanup function for stale sessions
async function cleanupStaleSessions() {
    try {
        const staleTime = new Date(Date.now() - 24 * 60 * 60 * 1000);
        const staleSessions = await Session.find({
            lastActive: { $lt: staleTime },
            status: { $ne: 'disconnected' }
        });

        for (const session of staleSessions) {
            if (sessions.has(session.sessionId)) {
                const activeSession = sessions.get(session.sessionId);
                if (activeSession?.sock) {
                    try {
                        if (typeof activeSession.sock.end === 'function') {
                            activeSession.sock.end();
                        }

                        if (typeof activeSession.sock.removeAllListeners === 'function') {
                            activeSession.sock.removeAllListeners();
                        } else if (activeSession.sock.ev && typeof activeSession.sock.ev.removeAllListeners === 'function') {
                            // Try to access event emitter if available
                            activeSession.sock.ev.removeAllListeners();
                        }
                    } catch (cleanupError) {
                        console.log(`Error cleaning up stale session ${session.sessionId}:`, cleanupError);
                    }
                }
                sessions.delete(session.sessionId);
            }

            await Session.findOneAndUpdate(
                { sessionId: session.sessionId },
                { status: 'disconnected' }
            );

            try {
                await mongoose.connection.db.dropCollection(`authState_${session.sessionId}`);
            } catch (error) {
                console.log(`Error dropping auth collection for session ${session.sessionId}:`, error);
            }
        }
    } catch (error) {
        console.error('Error cleaning up stale sessions:', error);
    }
}

// Run cleanup every hour
setInterval(cleanupStaleSessions, 60 * 60 * 1000);
setInterval(cleanupStaleAuthStates, 60 * 60 * 1000);

// Add endpoint to get contacts
app.post('/api/get-contacts', auth, async (req, res) => {
    const { sessionId, source, options } = req.body;
    console.log(`Getting ${source} for session: ${sessionId}`);

    const session = sessions.get(sessionId);
    if (!session || session.userId.toString() !== req.user._id.toString()) {
        return res.status(404).json({ error: 'Session not found' });
    }

    try {
        if (source === 'contacts') {
            // For contacts, we'll use a different approach since direct contact fetching is unreliable
            // We'll get contacts from groups and deduplicate them
            const formattedContacts = [];
            const uniqueContacts = new Map(); // To deduplicate contacts

            try {
                // Get all groups the user is part of
                const groups = await session.sock.groupFetchAllParticipating();

                // Extract contacts from group participants
                for (const [groupId, group] of Object.entries(groups)) {
                    if (group.participants) {
                        for (const participant of group.participants) {
                            const jid = participant.id;

                            // Skip if not a valid contact JID
                            if (!jid.includes('@s.whatsapp.net') || jid.includes('@g.us') || jid.includes('@broadcast')) {
                                continue;
                            }

                            const phoneNumber = jid.split('@')[0];

                            // Skip if we've already processed this contact
                            if (uniqueContacts.has(phoneNumber)) {
                                continue;
                            }

                            // Add to unique contacts
                            uniqueContacts.set(phoneNumber, {
                                phone: phoneNumber,
                                name: options.includeName ? (participant.name || 'Unknown') : null,
                                status: options.includeStatus ? 'No status' : null
                            });
                        }
                    }
                }

                // Convert map to array
                for (const contact of uniqueContacts.values()) {
                    formattedContacts.push(contact);
                }

                // If we couldn't get any contacts from groups, return a message
                if (formattedContacts.length === 0) {
                    return res.json({
                        contacts: [],
                        message: "No contacts found. This could be because you're not part of any groups or the WhatsApp API doesn't provide direct access to contacts."
                    });
                }
            } catch (err) {
                console.error('Error fetching contacts from groups:', err);
                // Continue with empty contacts list
            }

            res.json({ contacts: formattedContacts });
        } else if (source === 'groups') {
            // Get groups from WhatsApp
            const formattedGroups = [];

            try {
                // Use groupFetchAllParticipating which we know works
                const groups = await session.sock.groupFetchAllParticipating();

                for (const [jid, group] of Object.entries(groups)) {
                    const groupId = jid.split('@')[0];
                    const formattedGroup = {
                        groupId: groupId,
                        groupName: options.includeGroupName ? group.subject || 'Unnamed Group' : null,
                        memberCount: group.participants ? group.participants.length : 0
                    };

                    formattedGroups.push(formattedGroup);
                }
            } catch (err) {
                console.error('Error fetching groups:', err);
            }

            res.json({ contacts: formattedGroups });
        } else {
            res.status(400).json({ error: 'Invalid source specified' });
        }
    } catch (error) {
        console.error(`Error getting ${source}:`, error);
        res.status(500).json({ error: error.message });
    }
});

// Add endpoint to get group members
app.post('/api/get-group-members', auth, async (req, res) => {
    const { sessionId, groupId } = req.body;
    console.log(`Getting members for group: ${groupId} in session: ${sessionId}`);

    const session = sessions.get(sessionId);
    if (!session || session.userId.toString() !== req.user._id.toString()) {
        return res.status(404).json({ error: 'Session not found' });
    }

    try {
        // Get group metadata
        const groupJid = `${groupId}@g.us`;
        const groupMetadata = await session.sock.groupMetadata(groupJid);

        if (!groupMetadata) {
            return res.status(404).json({ error: 'Group not found' });
        }

        // Get participants
        const participants = groupMetadata.participants || [];
        const formattedMembers = [];

        for (const participant of participants) {
            const memberJid = participant.id;
            const phoneNumber = memberJid.split('@')[0];

            // For group members, we'll just use the phone number and admin status
            // since getName is not available
            const formattedMember = {
                phone: phoneNumber,
                name: 'Unknown', // We can't reliably get names
                isAdmin: participant.admin === 'admin' || participant.admin === 'superadmin'
            };

            formattedMembers.push(formattedMember);
        }

        res.json({ members: formattedMembers });
    } catch (error) {
        console.error('Error getting group members:', error);
        res.status(500).json({ error: error.message });
    }
});

// Auto-reply rules API endpoints
app.get('/api/auto-reply-rules', auth, async (req, res) => {
    try {
        const rules = await AutoReplyRule.find({ userId: req.user._id });
        res.json({ rules });
    } catch (error) {
        console.error('Error fetching auto-reply rules:', error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/auto-reply-rules', auth, async (req, res) => {
    try {
        const {
            sessionId,
            name,
            triggerType,
            triggerValue,
            responseType,
            responseContent,
            imageUrl,
            conditions
        } = req.body;

        // Validate session exists and belongs to user
        const session = await Session.findOne({ sessionId, userId: req.user._id });
        if (!session) {
            return res.status(404).json({ error: 'Session not found' });
        }

        const rule = new AutoReplyRule({
            userId: req.user._id,
            sessionId,
            name,
            triggerType,
            triggerValue,
            responseType,
            responseContent,
            imageUrl,
            conditions: conditions || {}
        });

        await rule.save();
        res.status(201).json({ rule });
    } catch (error) {
        console.error('Error creating auto-reply rule:', error);
        res.status(500).json({ error: error.message });
    }
});

app.put('/api/auto-reply-rules/:ruleId', auth, async (req, res) => {
    try {
        const { ruleId } = req.params;
        const updateData = req.body;

        const rule = await AutoReplyRule.findOne({ _id: ruleId, userId: req.user._id });
        if (!rule) {
            return res.status(404).json({ error: 'Rule not found' });
        }

        // Update the rule
        Object.keys(updateData).forEach(key => {
            if (key !== '_id' && key !== 'userId') {
                rule[key] = updateData[key];
            }
        });

        await rule.save();
        res.json({ rule });
    } catch (error) {
        console.error('Error updating auto-reply rule:', error);
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/auto-reply-rules/:ruleId', auth, async (req, res) => {
    try {
        const { ruleId } = req.params;

        const result = await AutoReplyRule.findOneAndDelete({ _id: ruleId, userId: req.user._id });
        if (!result) {
            return res.status(404).json({ error: 'Rule not found' });
        }

        res.json({ success: true });
    } catch (error) {
        console.error('Error deleting auto-reply rule:', error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/auto-reply-rules/:ruleId/toggle', auth, async (req, res) => {
    try {
        const { ruleId } = req.params;

        const rule = await AutoReplyRule.findOne({ _id: ruleId, userId: req.user._id });
        if (!rule) {
            return res.status(404).json({ error: 'Rule not found' });
        }

        rule.isActive = !rule.isActive;
        await rule.save();

        res.json({ rule });
    } catch (error) {
        console.error('Error toggling auto-reply rule:', error);
        res.status(500).json({ error: error.message });
    }
});

// Start server
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    checkExistingSessions();
});
