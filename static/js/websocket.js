// WebSocket Connection Manager
class WebSocketManager {
    constructor() {
        this.ws = null;
        this.isConnected = false;
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 5;
        this.reconnectDelay = 1000;
        this.messageHandlers = new Map();
        this.connectionHandlers = [];
        this.disconnectionHandlers = [];
    }

    // Connect to WebSocket server
    connect(url = null) {
        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
            console.log('WebSocket already connected');
            return;
        }

        const wsUrl = url || this.getWebSocketUrl();
        console.log('Connecting to WebSocket:', wsUrl);

        try {
            this.ws = new WebSocket(wsUrl);
            this.setupEventHandlers();
        } catch (error) {
            console.error('Failed to create WebSocket connection:', error);
            this.handleConnectionError();
        }
    }

    // Disconnect from WebSocket server
    disconnect() {
        if (this.ws) {
            this.ws.close();
            this.ws = null;
        }
        this.isConnected = false;
        this.reconnectAttempts = 0;
    }

    // Get WebSocket URL based on current location
    getWebSocketUrl() {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const host = window.location.host;
        return `${protocol}//${host}/ws`;
    }

    // Setup WebSocket event handlers
    setupEventHandlers() {
        this.ws.onopen = () => {
            console.log('WebSocket connected');
            this.isConnected = true;
            this.reconnectAttempts = 0;
            this.notifyConnectionHandlers(true);
        };

        this.ws.onmessage = (event) => {
            try {
                const message = JSON.parse(event.data);
                this.handleMessage(message);
            } catch (error) {
                console.error('Failed to parse WebSocket message:', error, event.data);
            }
        };

        this.ws.onclose = (event) => {
            console.log('WebSocket disconnected:', event.code, event.reason);
            this.isConnected = false;
            this.notifyConnectionHandlers(false);
            
            if (event.code !== 1000) { // Not a normal closure
                this.handleConnectionError();
            }
        };

        this.ws.onerror = (error) => {
            console.error('WebSocket error:', error);
            this.handleConnectionError();
        };
    }

    // Handle incoming messages
    handleMessage(message) {
        console.log('WebSocket message received:', message);
        
        const { type, data } = message;
        
        if (this.messageHandlers.has(type)) {
            const handlers = this.messageHandlers.get(type);
            handlers.forEach(handler => {
                try {
                    handler(data);
                } catch (error) {
                    console.error(`Error in message handler for type ${type}:`, error);
                }
            });
        } else {
            console.warn('No handler registered for message type:', type);
        }
    }

    // Handle connection errors and reconnection
    handleConnectionError() {
        if (this.reconnectAttempts < this.maxReconnectAttempts) {
            this.reconnectAttempts++;
            const delay = this.reconnectDelay * Math.pow(2, this.reconnectAttempts - 1);
            
            console.log(`Reconnecting in ${delay}ms (attempt ${this.reconnectAttempts}/${this.maxReconnectAttempts})`);
            
            setTimeout(() => {
                this.connect();
            }, delay);
        } else {
            console.error('Max reconnection attempts reached');
            this.notifyDisconnectionHandlers();
        }
    }

    // Send message to server
    send(type, data = null) {
        if (!this.isConnected || !this.ws) {
            console.warn('WebSocket not connected, cannot send message');
            return false;
        }

        try {
            const message = { type, data };
            this.ws.send(JSON.stringify(message));
            return true;
        } catch (error) {
            console.error('Failed to send WebSocket message:', error);
            return false;
        }
    }

    // Register message handler
    on(type, handler) {
        if (!this.messageHandlers.has(type)) {
            this.messageHandlers.set(type, []);
        }
        this.messageHandlers.get(type).push(handler);
    }

    // Unregister message handler
    off(type, handler) {
        if (this.messageHandlers.has(type)) {
            const handlers = this.messageHandlers.get(type);
            const index = handlers.indexOf(handler);
            if (index > -1) {
                handlers.splice(index, 1);
            }
        }
    }

    // Register connection handler
    onConnection(handler) {
        this.connectionHandlers.push(handler);
    }

    // Register disconnection handler
    onDisconnection(handler) {
        this.disconnectionHandlers.push(handler);
    }

    // Notify connection handlers
    notifyConnectionHandlers(connected) {
        this.connectionHandlers.forEach(handler => {
            try {
                handler(connected);
            } catch (error) {
                console.error('Error in connection handler:', error);
            }
        });
    }

    // Notify disconnection handlers
    notifyDisconnectionHandlers() {
        this.disconnectionHandlers.forEach(handler => {
            try {
                handler();
            } catch (error) {
                console.error('Error in disconnection handler:', error);
            }
        });
    }

    // Get connection status
    getConnectionStatus() {
        return {
            connected: this.isConnected,
            reconnectAttempts: this.reconnectAttempts,
            maxReconnectAttempts: this.maxReconnectAttempts
        };
    }
}

// Export singleton instance
window.wsManager = new WebSocketManager(); 