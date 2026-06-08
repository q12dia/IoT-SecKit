/**
 * WSClient — unified WebSocket manager for all seven IoT SecKit modules.
 *
 * Usage:
 *   const ws = new WSClient("scanner", sessionId, {
 *     log:      (data, ts) => ...,
 *     result:   (data, ts) => ...,
 *     alert:    (data, ts) => ...,
 *     progress: (data, ts) => ...,
 *     done:     (data, ts) => ...,
 *     error:    (data, ts) => ...,
 *     suggestions: (data, ts) => ...,   // scanner cross-module hint
 *   });
 *   ws.connect();
 */
class WSClient {
  constructor(module, sessionId, handlers = {}) {
    this.module         = module;
    this.sessionId      = sessionId;
    this.handlers       = handlers;
    this.url            = `ws://${location.host}/ws/${module}/${sessionId}`;
    this.ws             = null;
    this.reconnectDelay = 1000;
    this._reconnectTimer = null;
    this._closed        = false;   // set true on explicit disconnect()
  }

  connect() {
    if (this._closed) return;

    this.ws = new WebSocket(this.url);

    this.ws.onopen = () => {
      console.info(`[WSClient] connected: ${this.url}`);
      this.reconnectDelay = 1000;   // reset backoff on success
    };

    this.ws.onmessage = (event) => {
      let msg;
      try {
        msg = JSON.parse(event.data);
      } catch (err) {
        console.warn("[WSClient] invalid JSON:", event.data);
        return;
      }
      const handler = this.handlers[msg.type];
      if (typeof handler === "function") {
        handler(msg.data, msg.ts);
      }
    };

    this.ws.onclose = (event) => {
      if (this._closed) return;
      console.warn(
        `[WSClient] disconnected (code ${event.code}), reconnecting in ${this.reconnectDelay}ms…`
      );
      this._reconnectTimer = setTimeout(() => {
        this.reconnectDelay = Math.min(this.reconnectDelay * 2, 30_000);
        this.connect();
      }, this.reconnectDelay);
    };

    this.ws.onerror = (err) => {
      console.error(`[WSClient] error on ${this.url}`, err);
      // onclose fires automatically after onerror; reconnect is handled there
    };
  }

  /** Send an arbitrary JSON payload to the server. */
  send(data) {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(data));
    } else {
      console.warn("[WSClient] send() called while socket is not open");
    }
  }

  /** Permanently close the connection (no reconnect). */
  disconnect() {
    this._closed = true;
    clearTimeout(this._reconnectTimer);
    this.ws?.close();
  }

  /** Replace handler map at runtime (e.g. when re-using a connection). */
  setHandlers(handlers) {
    this.handlers = handlers;
  }

  get readyState() {
    return this.ws ? this.ws.readyState : WebSocket.CLOSED;
  }

  get isOpen() {
    return this.readyState === WebSocket.OPEN;
  }
}
