"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.StatefulStrictAction = exports.StatefulStandardAction = exports.StatelessStandardAction = void 0;
/**
 * The actions to take on a packet that matches one of the stateless rule definition's match attributes.
 */
var StatelessStandardAction;
(function (StatelessStandardAction) {
    /**
     * Discontinues stateless inspection of the packet and forwards it to the stateful rule engine for inspection.
     */
    StatelessStandardAction["FORWARD"] = "aws:forward_to_sfe";
    /**
     * Discontinues all inspection of the packet and permits it to go to its intended destination
     */
    StatelessStandardAction["PASS"] = "aws:pass";
    /**
     * Discontinues all inspection of the packet and blocks it from going to its intended destination.
     */
    StatelessStandardAction["DROP"] = "aws:drop";
})(StatelessStandardAction || (exports.StatelessStandardAction = StatelessStandardAction = {}));
/**
 * Defines what Network Firewall should do with the packets in a traffic flow when the flow matches the stateful rule criteria
 */
var StatefulStandardAction;
(function (StatefulStandardAction) {
    /**
     * Permits the packets to go to the intended destination.
     */
    StatefulStandardAction["PASS"] = "PASS";
    /**
     * Blocks the packets from going to the intended destination and sends an alert log message, if alert logging is configured in the firewall.
     */
    StatefulStandardAction["DROP"] = "DROP";
    /**
     * Permits the packets to go to the intended destination and sends an alert log message, if alert logging is configured in the firewall.
     */
    StatefulStandardAction["ALERT"] = "ALERT";
})(StatefulStandardAction || (exports.StatefulStandardAction = StatefulStandardAction = {}));
/**
 * The default actions to take on a packet that doesn't match any stateful rules
 */
var StatefulStrictAction;
(function (StatefulStrictAction) {
    /**
     * Drops all packets.
     */
    StatefulStrictAction["DROP_STRICT"] = "aws:drop_strict";
    /**
     * Drops only the packets that are in established connections.
     * This allows the layer 3 and 4 connection establishment packets that are needed for the upper-layer connections to be established, while dropping the packets for connections that are already established.
     * This allows application-layer pass rules to be written in a default-deny setup without the need to write additional rules to allow the lower-layer handshaking parts of the underlying protocols.
     */
    StatefulStrictAction["DROP_ESTABLISHED"] = "aws:drop_established";
    /**
     * Logs an ALERT message on all packets.
     * This does not drop packets, but alerts you to what would be dropped if you were to choose Drop all.
     */
    StatefulStrictAction["ALERT_STRICT"] = "aws:alert_strict";
    /**
     * Logs an ALERT message on only the packets that are in established connections.
     * This does not drop packets, but alerts you to what would be dropped if you were to choose Drop established.
     */
    StatefulStrictAction["ALERT_ESTABLISHED"] = "aws:alert_established";
})(StatefulStrictAction || (exports.StatefulStrictAction = StatefulStrictAction = {}));
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiYWN0aW9ucy5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbImFjdGlvbnMudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7O0FBQUE7O0dBRUc7QUFDSCxJQUFZLHVCQWVYO0FBZkQsV0FBWSx1QkFBdUI7SUFDakM7O09BRUc7SUFDSCx5REFBOEIsQ0FBQTtJQUU5Qjs7T0FFRztJQUNILDRDQUFpQixDQUFBO0lBRWpCOztPQUVHO0lBQ0gsNENBQWlCLENBQUE7QUFDbkIsQ0FBQyxFQWZXLHVCQUF1Qix1Q0FBdkIsdUJBQXVCLFFBZWxDO0FBRUQ7O0dBRUc7QUFDSCxJQUFZLHNCQWVYO0FBZkQsV0FBWSxzQkFBc0I7SUFDaEM7O09BRUc7SUFDSCx1Q0FBYSxDQUFBO0lBRWI7O09BRUc7SUFDSCx1Q0FBYSxDQUFBO0lBRWI7O09BRUc7SUFDSCx5Q0FBZSxDQUFBO0FBQ2pCLENBQUMsRUFmVyxzQkFBc0Isc0NBQXRCLHNCQUFzQixRQWVqQztBQUVEOztHQUVHO0FBQ0gsSUFBWSxvQkF5Qlg7QUF6QkQsV0FBWSxvQkFBb0I7SUFFOUI7O09BRUc7SUFDSCx1REFBK0IsQ0FBQTtJQUUvQjs7OztPQUlHO0lBQ0gsaUVBQXlDLENBQUE7SUFFekM7OztPQUdHO0lBQ0gseURBQWlDLENBQUE7SUFFakM7OztPQUdHO0lBQ0gsbUVBQTJDLENBQUE7QUFDN0MsQ0FBQyxFQXpCVyxvQkFBb0Isb0NBQXBCLG9CQUFvQixRQXlCL0IiLCJzb3VyY2VzQ29udGVudCI6WyIvKipcbiAqIFRoZSBhY3Rpb25zIHRvIHRha2Ugb24gYSBwYWNrZXQgdGhhdCBtYXRjaGVzIG9uZSBvZiB0aGUgc3RhdGVsZXNzIHJ1bGUgZGVmaW5pdGlvbidzIG1hdGNoIGF0dHJpYnV0ZXMuXG4gKi9cbmV4cG9ydCBlbnVtIFN0YXRlbGVzc1N0YW5kYXJkQWN0aW9uIHtcbiAgLyoqXG4gICAqIERpc2NvbnRpbnVlcyBzdGF0ZWxlc3MgaW5zcGVjdGlvbiBvZiB0aGUgcGFja2V0IGFuZCBmb3J3YXJkcyBpdCB0byB0aGUgc3RhdGVmdWwgcnVsZSBlbmdpbmUgZm9yIGluc3BlY3Rpb24uXG4gICAqL1xuICBGT1JXQVJEID0gJ2F3czpmb3J3YXJkX3RvX3NmZScsXG5cbiAgLyoqXG4gICAqIERpc2NvbnRpbnVlcyBhbGwgaW5zcGVjdGlvbiBvZiB0aGUgcGFja2V0IGFuZCBwZXJtaXRzIGl0IHRvIGdvIHRvIGl0cyBpbnRlbmRlZCBkZXN0aW5hdGlvblxuICAgKi9cbiAgUEFTUyA9ICdhd3M6cGFzcycsXG5cbiAgLyoqXG4gICAqIERpc2NvbnRpbnVlcyBhbGwgaW5zcGVjdGlvbiBvZiB0aGUgcGFja2V0IGFuZCBibG9ja3MgaXQgZnJvbSBnb2luZyB0byBpdHMgaW50ZW5kZWQgZGVzdGluYXRpb24uXG4gICAqL1xuICBEUk9QID0gJ2F3czpkcm9wJyxcbn1cblxuLyoqXG4gKiBEZWZpbmVzIHdoYXQgTmV0d29yayBGaXJld2FsbCBzaG91bGQgZG8gd2l0aCB0aGUgcGFja2V0cyBpbiBhIHRyYWZmaWMgZmxvdyB3aGVuIHRoZSBmbG93IG1hdGNoZXMgdGhlIHN0YXRlZnVsIHJ1bGUgY3JpdGVyaWFcbiAqL1xuZXhwb3J0IGVudW0gU3RhdGVmdWxTdGFuZGFyZEFjdGlvbiB7XG4gIC8qKlxuICAgKiBQZXJtaXRzIHRoZSBwYWNrZXRzIHRvIGdvIHRvIHRoZSBpbnRlbmRlZCBkZXN0aW5hdGlvbi5cbiAgICovXG4gIFBBU1MgPSAnUEFTUycsXG5cbiAgLyoqXG4gICAqIEJsb2NrcyB0aGUgcGFja2V0cyBmcm9tIGdvaW5nIHRvIHRoZSBpbnRlbmRlZCBkZXN0aW5hdGlvbiBhbmQgc2VuZHMgYW4gYWxlcnQgbG9nIG1lc3NhZ2UsIGlmIGFsZXJ0IGxvZ2dpbmcgaXMgY29uZmlndXJlZCBpbiB0aGUgZmlyZXdhbGwuXG4gICAqL1xuICBEUk9QID0gJ0RST1AnLFxuXG4gIC8qKlxuICAgKiBQZXJtaXRzIHRoZSBwYWNrZXRzIHRvIGdvIHRvIHRoZSBpbnRlbmRlZCBkZXN0aW5hdGlvbiBhbmQgc2VuZHMgYW4gYWxlcnQgbG9nIG1lc3NhZ2UsIGlmIGFsZXJ0IGxvZ2dpbmcgaXMgY29uZmlndXJlZCBpbiB0aGUgZmlyZXdhbGwuXG4gICAqL1xuICBBTEVSVCA9ICdBTEVSVCcsXG59XG5cbi8qKlxuICogVGhlIGRlZmF1bHQgYWN0aW9ucyB0byB0YWtlIG9uIGEgcGFja2V0IHRoYXQgZG9lc24ndCBtYXRjaCBhbnkgc3RhdGVmdWwgcnVsZXNcbiAqL1xuZXhwb3J0IGVudW0gU3RhdGVmdWxTdHJpY3RBY3Rpb24ge1xuXG4gIC8qKlxuICAgKiBEcm9wcyBhbGwgcGFja2V0cy5cbiAgICovXG4gIERST1BfU1RSSUNUID0gJ2F3czpkcm9wX3N0cmljdCcsXG5cbiAgLyoqXG4gICAqIERyb3BzIG9ubHkgdGhlIHBhY2tldHMgdGhhdCBhcmUgaW4gZXN0YWJsaXNoZWQgY29ubmVjdGlvbnMuXG4gICAqIFRoaXMgYWxsb3dzIHRoZSBsYXllciAzIGFuZCA0IGNvbm5lY3Rpb24gZXN0YWJsaXNobWVudCBwYWNrZXRzIHRoYXQgYXJlIG5lZWRlZCBmb3IgdGhlIHVwcGVyLWxheWVyIGNvbm5lY3Rpb25zIHRvIGJlIGVzdGFibGlzaGVkLCB3aGlsZSBkcm9wcGluZyB0aGUgcGFja2V0cyBmb3IgY29ubmVjdGlvbnMgdGhhdCBhcmUgYWxyZWFkeSBlc3RhYmxpc2hlZC5cbiAgICogVGhpcyBhbGxvd3MgYXBwbGljYXRpb24tbGF5ZXIgcGFzcyBydWxlcyB0byBiZSB3cml0dGVuIGluIGEgZGVmYXVsdC1kZW55IHNldHVwIHdpdGhvdXQgdGhlIG5lZWQgdG8gd3JpdGUgYWRkaXRpb25hbCBydWxlcyB0byBhbGxvdyB0aGUgbG93ZXItbGF5ZXIgaGFuZHNoYWtpbmcgcGFydHMgb2YgdGhlIHVuZGVybHlpbmcgcHJvdG9jb2xzLlxuICAgKi9cbiAgRFJPUF9FU1RBQkxJU0hFRCA9ICdhd3M6ZHJvcF9lc3RhYmxpc2hlZCcsXG5cbiAgLyoqXG4gICAqIExvZ3MgYW4gQUxFUlQgbWVzc2FnZSBvbiBhbGwgcGFja2V0cy5cbiAgICogVGhpcyBkb2VzIG5vdCBkcm9wIHBhY2tldHMsIGJ1dCBhbGVydHMgeW91IHRvIHdoYXQgd291bGQgYmUgZHJvcHBlZCBpZiB5b3Ugd2VyZSB0byBjaG9vc2UgRHJvcCBhbGwuXG4gICAqL1xuICBBTEVSVF9TVFJJQ1QgPSAnYXdzOmFsZXJ0X3N0cmljdCcsXG5cbiAgLyoqXG4gICAqIExvZ3MgYW4gQUxFUlQgbWVzc2FnZSBvbiBvbmx5IHRoZSBwYWNrZXRzIHRoYXQgYXJlIGluIGVzdGFibGlzaGVkIGNvbm5lY3Rpb25zLlxuICAgKiBUaGlzIGRvZXMgbm90IGRyb3AgcGFja2V0cywgYnV0IGFsZXJ0cyB5b3UgdG8gd2hhdCB3b3VsZCBiZSBkcm9wcGVkIGlmIHlvdSB3ZXJlIHRvIGNob29zZSBEcm9wIGVzdGFibGlzaGVkLlxuICAgKi9cbiAgQUxFUlRfRVNUQUJMSVNIRUQgPSAnYXdzOmFsZXJ0X2VzdGFibGlzaGVkJ1xufSJdfQ==