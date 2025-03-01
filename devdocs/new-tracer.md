# Add new TCP based BPF tracer

This document the steps required to add a new TCP protocol based BPF tracer to Beyla.

## Investigate the protocol

First, you need to understand the protocol used by the application you want to trace. Beyla captures TCP packets and you need to add the logic to identify the packets that belong to the protocol you want to trace. The are basically two cases:

- The package comes in plain text, like SQL. In this case, you can just search for the SQL keywords in the packets.
- The package comes in binary format, like Kafka. In this case, you need to figure out how to identify the start and end of the packets and where the relevant information is.


## Add the new protocol to the BPF program

In [pkg/internal/ebpf/common/tcp_detect_transform.go](https://github.com/grafana/beyla/blob/main/pkg/internal/ebpf/common/tcp_detect_transform.go) any TCP packet captured from BPF passes through the `ReadTCPRequestIntoSpan` function, and depending what's in the bytes, you can identify if the packet is SQL, Redis, etc. You need to add a new case to this function to identify the new protocol.

Once you have this done (the hard part!), you have to create a new `EventType` in [pkg/internal/request/span.go](https://github.com/grafana/beyla/blob/main/pkg/internal/request/span.go#L4). Look how other `EventTypes` are handled, and you probably need to edit every single file where the data is flowing. For example, to add a new OTEL trace you have to edit `traceAttributes` in [pkg/export/otel/traces.go](https://github.com/grafana/beyla/blob/main/pkg/export/otel/traces.go#L4)

Take a look at this PR for an example of how to add a new Kafka protocol: https://github.com/grafana/beyla/pull/890

## Other considerations

- Add always definitions for Prometheus metrics and OpenTelemetry traces and metrics.
- Look for already defined semantic conventions defined in OpenTelemetry spec for those attributes.
   - If there's nothing defined, you can create your own attributes, and if they are useful, propose them to the OpenTelemetry community.
- Add always tests, both unit and OATS integration tests.
- Add always documentation of the newly introduced metrics and traces for this protocol.

## Example: Adding JSON-RPC Protocol Support

### Understanding JSON-RPC

[JSON-RPC](https://www.jsonrpc.org/specification) is a stateless, light-weight remote procedure call (RPC) protocol that uses JSON for data formatting. Key characteristics:

- Request objects contain:
  - `jsonrpc`: A string specifying the version of the JSON-RPC protocol (must be "2.0")
  - `method`: A string containing the name of the method to be invoked
  - `params`: An optional array or object of parameter values
  - `id`: A client-established identifier that must contain a string, number, or NULL value

- Response objects contain:
  - `jsonrpc`: A string specifying the version ("2.0")
  - `result`: The value returned by the invoked method (only for successful responses)
  - `error`: An object describing the error (only for error responses)
  - `id`: The same value as the request id

### Implementing JSON-RPC Detection

To detect JSON-RPC traffic:

1. Look for JSON formatted packets that match the JSON-RPC structure
2. Parse the JSON and check for the presence of required fields like "jsonrpc", "method", and "id" for requests
3. Distinguish between requests and responses by checking for "result" or "error" fields (responses) vs "method" field (requests)

```go
// Example detection code (simplified)
func isJSONRPC(data []byte) bool {
    // Quick check for JSON format
    if !bytes.Contains(data, []byte("{")) || !bytes.Contains(data, []byte("}")) {
        return false
    }

    // Try to parse as JSON
    var jsonData map[string]interface{}
    if err := json.Unmarshal(data, &jsonData); err != nil {
        return false
    }

    // Check for JSON-RPC version field
    if jsonrpcVersion, ok := jsonData["jsonrpc"].(string); ok {
        // Version "2.0" is required by specification
        if jsonrpcVersion == "2.0" {
            // Check for either method (request) or result/error (response)
            _, hasMethod := jsonData["method"]
            _, hasResult := jsonData["result"]
            _, hasError := jsonData["error"]
            
            return hasMethod || hasResult || hasError
        }
    }
    
    return false
}
```

### OpenTelemetry Attributes

For JSON-RPC, consider the following attributes:

- `rpc.system`: Set to "jsonrpc"
- `rpc.method`: The method name from the request
- `rpc.jsonrpc.version`: The JSON-RPC version ("2.0")
- `rpc.jsonrpc.request_id`: The request ID
- `rpc.jsonrpc.error_code`: For error responses, the error code
- `rpc.jsonrpc.error_message`: For error responses, the error message

### Implementation Steps

1. Update `pkg/internal/request/span.go` to add a new `EventType` for JSON-RPC
2. Modify `ReadTCPRequestIntoSpan` in `tcp_detect_transform.go` to detect JSON-RPC packets
3. Extract relevant information to populate span attributes
4. Update OpenTelemetry exporters to include JSON-RPC specific attributes
5. Add metrics for:
   - Total JSON-RPC requests
   - JSON-RPC request duration
   - JSON-RPC errors count by error code
   - Method-specific metrics

### Testing Considerations

- Create unit tests with sample JSON-RPC request and response packets
- Test parsing of both successful responses and error responses
- Verify correct extraction of method names and parameters
- Test integration with a real JSON-RPC service like Ethereum nodes (which use JSON-RPC)