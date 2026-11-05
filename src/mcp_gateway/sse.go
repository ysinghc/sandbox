// SPDX-License-Identifier: GPL-2.0-only
package main

import (
	"fmt"
	"net/http"
)

// writeSSE sends each payload as one `message` event and returns; the handler
// closes the stream after the response. This is the request/response shape of
// Streamable HTTP, not a held-open server push channel (a stateless server has
// no session to push over).
func writeSSE(w http.ResponseWriter, payloads ...[]byte) {
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	h.Set("Connection", "keep-alive")
	h.Set("X-Accel-Buffering", "no")
	for _, p := range payloads {
		fmt.Fprintf(w, "event: message\ndata: %s\n\n", p)
	}
}
