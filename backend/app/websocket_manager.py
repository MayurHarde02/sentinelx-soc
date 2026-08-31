import json
import asyncio
from typing import List, Dict, Any
from fastapi import WebSocket

class WebSocketManager:
    """Manages real-time WebSocket client connections and telemetry broadcasting."""

    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message_type: str, payload: Dict[str, Any]):
        if not self.active_connections:
            return

        data = {
            "type": message_type,
            "data": payload
        }
        msg_str = json.dumps(data, default=str)

        # Broadcast to all connected clients concurrently
        disconnected_clients = []
        for connection in self.active_connections:
            try:
                await connection.send_text(msg_str)
            except Exception:
                disconnected_clients.append(connection)

        for conn in disconnected_clients:
            self.disconnect(conn)

    def broadcast_sync(self, message_type: str, payload: Dict[str, Any]):
        """Safe non-blocking broadcast dispatch that gracefully ignores synchronous execution contexts."""
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(self.broadcast(message_type, payload))
        except RuntimeError:
            # No active running asyncio event loop (e.g., synchronous tests or CLI jobs)
            pass

ws_manager = WebSocketManager()
