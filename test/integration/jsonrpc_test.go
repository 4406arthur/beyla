// package integration

// import (
// 	"bytes"
// 	"encoding/json"
// 	"net/http"
// 	"testing"
// 	"time"

// 	"github.com/stretchr/testify/assert"
// 	"github.com/stretchr/testify/require"

// 	"github.com/grafana/beyla/test/integration/oats"
// )

// func TestJSONRPC(t *testing.T) {
// 	if testing.Short() {
// 		t.Skip("Skipping integration test in short mode")
// 	}

// 	// Setup a simple JSON-RPC server
// 	go startJSONRPCServer(t)

// 	// Wait for the server to start
// 	time.Sleep(2 * time.Second)

// 	// Configure and start Beyla
// 	cfg := oats.DefaultTestConfig()
// 	cfg.EnvVars["BEYLA_AUTO_INSTRUMENT_JSON_RPC"] = "true"

// 	beyla, err := oats.NewBeyla(cfg)
// 	require.NoError(t, err)

// 	err = beyla.Start()
// 	require.NoError(t, err)
// 	defer beyla.Stop()

// 	// Wait for Beyla to initialize
// 	time.Sleep(5 * time.Second)

// 	// Make JSON-RPC calls
// 	makeJSONRPCRequest(t, "add", []int{10, 20})
// 	makeJSONRPCRequest(t, "subtract", []int{30, 20})
// 	makeJSONRPCRequest(t, "multiply", []int{5, 7})
// 	makeJSONRPCRequest(t, "unknown", []int{1, 2}) // Should cause error

// 	// Wait for metrics to be collected
// 	time.Sleep(5 * time.Second)

// 	// Verify traces
// 	traces, err := beyla.GetTraces()
// 	require.NoError(t, err)

// 	found := make(map[string]bool)
// 	for _, trace := range traces {
// 		for _, span := range trace.Spans {
// 			// Check for JSON-RPC spans
// 			if span.Attributes["rpc.system"] == "jsonrpc" {
// 				method := span.Attributes["rpc.method"]
// 				found[method] = true

// 				// Verify expected attributes
// 				assert.Equal(t, "jsonrpc", span.Attributes["rpc.system"])
// 				assert.Contains(t, span.Attributes, "rpc.jsonrpc.version")
// 				assert.Contains(t, span.Attributes, "rpc.jsonrpc.request_id")

// 				if method == "unknown" {
// 					assert.Contains(t, span.Attributes, "rpc.jsonrpc.error_code")
// 					assert.Contains(t, span.Attributes, "rpc.jsonrpc.error_message")
// 				}
// 			}
// 		}
// 	}

// 	// Verify we found traces for all methods
// 	assert.True(t, found["add"], "Should have trace for 'add' method")
// 	assert.True(t, found["subtract"], "Should have trace for 'subtract' method")
// 	assert.True(t, found["multiply"], "Should have trace for 'multiply' method")
// 	assert.True(t, found["unknown"], "Should have trace for 'unknown' method")

// 	// Verify metrics
// 	metrics, err := beyla.GetMetrics()
// 	require.NoError(t, err)

// 	// Check for JSON-RPC metrics
// 	foundMetrics := make(map[string]bool)
// 	for _, metric := range metrics {
// 		if metric.Name == "beyla_jsonrpc_requests_total" ||
// 			metric.Name == "beyla_jsonrpc_request_duration_seconds" ||
// 			metric.Name == "beyla_jsonrpc_errors_total" {
// 			foundMetrics[metric.Name] = true
// 		}
// 	}

// 	assert.True(t, foundMetrics["beyla_jsonrpc_requests_total"], "Should have JSON-RPC requests metric")
// 	assert.True(t, foundMetrics["beyla_jsonrpc_request_duration_seconds"], "Should have JSON-RPC duration metric")
// 	assert.True(t, foundMetrics["beyla_jsonrpc_errors_total"], "Should have JSON-RPC errors metric")
// }

// // Helper functions for the test
// func startJSONRPCServer(t *testing.T) {
// 	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
// 		var request map[string]interface{}

// 		err := json.NewDecoder(r.Body).Decode(&request)
// 		if err != nil {
// 			http.Error(w, "Invalid JSON", http.StatusBadRequest)
// 			return
// 		}

// 		id := request["id"]
// 		method, _ := request["method"].(string)
// 		params, _ := request["params"].([]interface{})

// 		response := map[string]interface{}{
// 			"jsonrpc": "2.0",
// 			"id":      id,
// 		}

// 		switch method {
// 		case "add":
// 			if len(params) >= 2 {
// 				a, _ := params[0].(float64)
// 				b, _ := params[1].(float64)
// 				response["result"] = a + b
// 			}
// 		case "subtract":
// 			if len(params) >= 2 {
// 				a, _ := params[0].(float64)
// 				b, _ := params[1].(float64)
// 				response["result"] = a - b
// 			}
// 		case "multiply":
// 			if len(params) >= 2 {
// 				a, _ := params[0].(float64)
// 				b, _ := params[1].(float64)
// 				response["result"] = a * b
// 			}
// 		default:
// 			response["error"] = map[string]interface{}{
// 				"code":    -32601,
// 				"message": "Method not found",
// 			}
// 		}

// 		w.Header().Set("Content-Type", "application/json")
// 		json.NewEncoder(w).Encode(response)
// 	})

// 	err := http.ListenAndServe(":8545", nil)
// 	if err != nil {
// 		t.Logf("JSON-RPC server error: %v", err)
// 	}
// }

// func makeJSONRPCRequest(t *testing.T, method string, params []int) {
// 	// Create JSON-RPC request
// 	request := map[string]interface{}{
// 		"jsonrpc": "2.0",
// 		"method":  method,
// 		"params":  params,
// 		"id":      1,
// 	}

// 	requestJSON, err := json.Marshal(request)
// 	require.NoError(t, err)

// 	// Send request
// 	resp, err := http.Post("http://localhost:8545", "application/json", bytes.NewReader(requestJSON))
// 	require.NoError(t, err)
// 	defer resp.Body.Close()

// 	// Parse response
// 	var response map[string]interface{}
// 	err = json.NewDecoder(resp.Body).Decode(&response)
// 	require.NoError(t, err)

// 	t.Logf("JSON-RPC %s response: %v", method, response)
// }
