// package oats

// import (
// 	"fmt"
// 	"io"
// 	"net"
// 	"net/http"
// 	"strings"
// 	"testing"
// 	"time"

// 	"github.com/stretchr/testify/assert"
// 	"github.com/stretchr/testify/require"
// )

// // TestJSONRPC tests JSON-RPC protocol instrumentation
// func TestJSONRPC(t *testing.T) {
// 	// Start a simple TCP server that responds to JSON-RPC requests
// 	jsonRPCServer := startJSONRPCServer(t, 8085)
// 	defer jsonRPCServer.Close()

// 	// Start Beyla with the appropriate configuration
// 	agentCfg := Config{
// 		Watch:           []string{},
// 		DisableHTTP:     true, // Disable HTTP instrumentation to focus on JSON-RPC
// 		DisableGRPC:     true, // Disable GRPC instrumentation to focus on JSON-RPC
// 		OATS:            true, // Enable OpenTelemetry test server
// 		AutoInstrument:  true,
// 		InstrumentNet:   true, // Required to capture TCP traffic
// 		ApplicationPath: "/bin/echo",
// 	}
// 	testAgentWithServer(t, agentCfg, "jsonrpc", func(otelServer *OTelTestServer, agentURL string) {
// 		// Send JSON-RPC request to the server
// 		sendJSONRPCRequest(t, "127.0.0.1:8085", "subtract", []int{42, 23}, 1)
// 		sendJSONRPCRequest(t, "127.0.0.1:8085", "echo", "hello world", 2)
// 		sendJSONRPCRequest(t, "127.0.0.1:8085", "database.query", map[string]string{"table": "users", "id": "123"}, 3)
// 		sendJSONRPCErrorRequest(t, "127.0.0.1:8085", "unknownMethod", nil, 4)

// 		// Allow time for spans to be collected
// 		time.Sleep(2 * time.Second)

// 		// Verify spans were created correctly
// 		spans := otelServer.GetSpans()
// 		require.NotEmpty(t, spans, "Expected spans to be collected")

// 		// Count JSON-RPC spans
// 		jsonRPCSpans := 0
// 		var subtractSpan, echoSpan, databaseSpan, errorSpan *TestSpan

// 		for _, span := range spans {
// 			if span.Name == "subtract" || span.Name == "echo" ||
// 				span.Name == "database.query" || span.Name == "unknownMethod" {
// 				jsonRPCSpans++

// 				// Check common attributes on all JSON-RPC spans
// 				assert.Equal(t, "jsonrpc", span.Attrs["rpc.system"], "Expected rpc.system=jsonrpc")
// 				assert.Equal(t, "2.0", span.Attrs["rpc.jsonrpc.version"], "Expected jsonrpc version 2.0")

// 				// Store specific spans for detailed checks
// 				switch span.Name {
// 				case "subtract":
// 					subtractSpan = span
// 				case "echo":
// 					echoSpan = span
// 				case "database.query":
// 					databaseSpan = span
// 				case "unknownMethod":
// 					errorSpan = span
// 				}
// 			}
// 		}

// 		// We should have at least 4 JSON-RPC spans
// 		assert.GreaterOrEqual(t, jsonRPCSpans, 4, "Expected at least 4 JSON-RPC spans")

// 		// Verify subtract span
// 		if subtractSpan != nil {
// 			assert.Equal(t, "subtract", subtractSpan.Attrs["rpc.method"], "Expected correct method")
// 			assert.Equal(t, "1", subtractSpan.Attrs["rpc.jsonrpc.request_id"], "Expected correct request ID")
// 			assert.Equal(t, "OK", subtractSpan.Status.Code, "Expected success status")
// 		}

// 		// Verify echo span
// 		if echoSpan != nil {
// 			assert.Equal(t, "echo", echoSpan.Attrs["rpc.method"], "Expected correct method")
// 			assert.Equal(t, "2", echoSpan.Attrs["rpc.jsonrpc.request_id"], "Expected correct request ID")
// 			assert.Equal(t, "OK", echoSpan.Status.Code, "Expected success status")
// 		}

// 		// Verify database.query span
// 		if databaseSpan != nil {
// 			assert.Equal(t, "database.query", databaseSpan.Attrs["rpc.method"], "Expected correct method")
// 			assert.Equal(t, "database", databaseSpan.Attrs["rpc.service"], "Expected service extracted from method")
// 			assert.Equal(t, "3", databaseSpan.Attrs["rpc.jsonrpc.request_id"], "Expected correct request ID")
// 			assert.Equal(t, "OK", databaseSpan.Status.Code, "Expected success status")
// 		}

// 		// Verify error span
// 		if errorSpan != nil {
// 			assert.Equal(t, "unknownMethod", errorSpan.Attrs["rpc.method"], "Expected correct method")
// 			assert.Equal(t, "4", errorSpan.Attrs["rpc.jsonrpc.request_id"], "Expected correct request ID")
// 			assert.Equal(t, "ERROR", errorSpan.Status.Code, "Expected error status")
// 			assert.Equal(t, "-32601", errorSpan.Attrs["rpc.jsonrpc.error_code"], "Expected method not found error code")
// 		}
// 	})
// }

// // startJSONRPCServer starts a simple TCP server that can handle JSON-RPC requests
// func startJSONRPCServer(t *testing.T, port int) net.Listener {
// 	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
// 	require.NoError(t, err, "Failed to create TCP listener")

// 	go func() {
// 		for {
// 			conn, err := listener.Accept()
// 			if err != nil {
// 				// Server closed, exit gracefully
// 				return
// 			}

// 			go handleJSONRPCConnection(conn)
// 		}
// 	}()

// 	return listener
// }

// // handleJSONRPCConnection handles a single JSON-RPC connection
// func handleJSONRPCConnection(conn net.Conn) {
// 	defer conn.Close()

// 	// Read the request
// 	buf := make([]byte, 4096)
// 	n, err := conn.Read(buf)
// 	if err != nil {
// 		return
// 	}

// 	request := string(buf[:n])
// 	var response string

// 	// Basic parsing to identify method and response
// 	if strings.Contains(request, "\"method\":\"subtract\"") {
// 		response = `{"jsonrpc":"2.0","result":19,"id":1}`
// 	} else if strings.Contains(request, "\"method\":\"echo\"") {
// 		response = `{"jsonrpc":"2.0","result":"hello world","id":2}`
// 	} else if strings.Contains(request, "\"method\":\"database.query\"") {
// 		response = `{"jsonrpc":"2.0","result":{"user":{"id":"123","name":"John Doe"}},"id":3}`
// 	} else if strings.Contains(request, "\"method\":\"unknownMethod\"") {
// 		response = `{"jsonrpc":"2.0","error":{"code":-32601,"message":"Method not found"},"id":4}`
// 	} else {
// 		response = `{"jsonrpc":"2.0","error":{"code":-32700,"message":"Parse error"},"id":null}`
// 	}

// 	// Send response
// 	_, _ = conn.Write([]byte(response))
// }

// // sendJSONRPCRequest sends a JSON-RPC request to the specified server
// func sendJSONRPCRequest(t *testing.T, serverAddr, method string, params interface{}, id int) {
// 	// Create the JSON-RPC request
// 	var paramsJSON string
// 	switch p := params.(type) {
// 	case []int:
// 		paramsJSON = fmt.Sprintf("[%d,%d]", p[0], p[1])
// 	case string:
// 		paramsJSON = fmt.Sprintf("\"%s\"", p)
// 	case map[string]string:
// 		pairs := []string{}
// 		for k, v := range p {
// 			pairs = append(pairs, fmt.Sprintf("\"%s\":\"%s\"", k, v))
// 		}
// 		paramsJSON = fmt.Sprintf("{%s}", strings.Join(pairs, ","))
// 	case nil:
// 		paramsJSON = "null"
// 	}

// 	jsonRequest := fmt.Sprintf(`{"jsonrpc":"2.0","method":"%s","params":%s,"id":%d}`,
// 		method, paramsJSON, id)

// 	// Connect to the server
// 	conn, err := net.Dial("tcp", serverAddr)
// 	require.NoError(t, err, "Failed to connect to JSON-RPC server")
// 	defer conn.Close()

// 	// Send the request
// 	_, err = conn.Write([]byte(jsonRequest))
// 	require.NoError(t, err, "Failed to send JSON-RPC request")

// 	// Read the response
// 	response, err := io.ReadAll(conn)
// 	require.NoError(t, err, "Failed to read JSON-RPC response")
// 	require.NotEmpty(t, response, "Expected non-empty response")
// }

// // sendJSONRPCErrorRequest sends a JSON-RPC request expected to return an error
// func sendJSONRPCErrorRequest(t *testing.T, serverAddr, method string, params interface{}, id int) {
// 	sendJSONRPCRequest(t, serverAddr, method, params, id)
// }

// // TestJSONRPCHTTP tests JSON-RPC over HTTP instrumentation
// func TestJSONRPCHTTP(t *testing.T) {
// 	// Start a simple HTTP server that handles JSON-RPC requests
// 	server := http.Server{Addr: ":8086"}
// 	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
// 		if r.Method != http.MethodPost {
// 			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
// 			return
// 		}

// 		body, err := io.ReadAll(r.Body)
// 		if err != nil {
// 			http.Error(w, "Failed to read request", http.StatusBadRequest)
// 			return
// 		}

// 		request := string(body)
// 		var response string

// 		// Basic parsing to identify method and response
// 		if strings.Contains(request, "\"method\":\"subtract\"") {
// 			response = `{"jsonrpc":"2.0","result":19,"id":1}`
// 		} else if strings.Contains(request, "\"method\":\"echo\"") {
// 			response = `{"jsonrpc":"2.0","result":"hello world","id":2}`
// 		} else if strings.Contains(request, "\"method\":\"database.query\"") {
// 			response = `{"jsonrpc":"2.0","result":{"user":{"id":"123","name":"John Doe"}},"id":3}`
// 		} else if strings.Contains(request, "\"method\":\"unknownMethod\"") {
// 			response = `{"jsonrpc":"2.0","error":{"code":-32601,"message":"Method not found"},"id":4}`
// 		} else {
// 			response = `{"jsonrpc":"2.0","error":{"code":-32700,"message":"Parse error"},"id":null}`
// 		}

// 		w.Header().Set("Content-Type", "application/json")
// 		w.WriteHeader(http.StatusOK)
// 		_, _ = w.Write([]byte(response))
// 	})

// 	go func() {
// 		_ = server.ListenAndServe()
// 	}()
// 	defer server.Close()

// 	// Allow server to start
// 	time.Sleep(500 * time.Millisecond)

// 	// Start Beyla with configuration for both HTTP and TCP
// 	agentCfg := Config{
// 		Watch:           []string{},
// 		OATS:            true,
// 		AutoInstrument:  true,
// 		InstrumentNet:   true,
// 		ApplicationPath: "/bin/echo",
// 	}

// 	testAgentWithServer(t, agentCfg, "jsonrpc-http", func(otelServer *OTelTestServer, agentURL string) {
// 		// Send JSON-RPC over HTTP requests
// 		sendHTTPJSONRPCRequest(t, "http://localhost:8086", "subtract", []int{42, 23}, 1)
// 		sendHTTPJSONRPCRequest(t, "http://localhost:8086", "database.query", map[string]string{"table": "users"}, 3)

// 		// Allow time for spans to be collected
// 		time.Sleep(2 * time.Second)

// 		// Verify HTTP spans for JSON-RPC were created
// 		spans := otelServer.GetSpans()
// 		require.NotEmpty(t, spans, "Expected spans to be collected")

// 		// Look for HTTP spans with POST method
// 		var postSpans []*TestSpan
// 		for _, span := range spans {
// 			// Check for HTTP POST spans that might contain JSON-RPC requests
// 			if span.Attrs["http.method"] == "POST" {
// 				postSpans = append(postSpans, span)
// 			}
// 		}

// 		assert.NotEmpty(t, postSpans, "Expected HTTP POST spans for JSON-RPC")
// 	})
// }

// // sendHTTPJSONRPCRequest sends a JSON-RPC request over HTTP
// func sendHTTPJSONRPCRequest(t *testing.T, serverURL, method string, params interface{}, id int) {
// 	// Create the JSON-RPC request
// 	var paramsJSON string
// 	switch p := params.(type) {
// 	case []int:
// 		paramsJSON = fmt.Sprintf("[%d,%d]", p[0], p[1])
// 	case string:
// 		paramsJSON = fmt.Sprintf("\"%s\"", p)
// 	case map[string]string:
// 		pairs := []string{}
// 		for k, v := range p {
// 			pairs = append(pairs, fmt.Sprintf("\"%s\":\"%s\"", k, v))
// 		}
// 		paramsJSON = fmt.Sprintf("{%s}", strings.Join(pairs, ","))
// 	case nil:
// 		paramsJSON = "null"
// 	}

// 	jsonRequest := fmt.Sprintf(`{"jsonrpc":"2.0","method":"%s","params":%s,"id":%d}`,
// 		method, paramsJSON, id)

// 	// Send HTTP POST request
// 	resp, err := http.Post(serverURL, "application/json", strings.NewReader(jsonRequest))
// 	require.NoError(t, err, "Failed to send HTTP request")
// 	defer resp.Body.Close()

// 	// Read and validate response
// 	body, err := io.ReadAll(resp.Body)
// 	require.NoError(t, err, "Failed to read HTTP response")
// 	require.NotEmpty(t, body, "Expected non-empty response")
// }
