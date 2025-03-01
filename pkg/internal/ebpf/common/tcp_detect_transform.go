package ebpfcommon

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"unsafe"

	"github.com/cilium/ebpf/ringbuf"
	trace2 "go.opentelemetry.io/otel/trace"

	"github.com/grafana/beyla/v2/pkg/config"
	"github.com/grafana/beyla/v2/pkg/internal/request"
)

// nolint:cyclop
func ReadTCPRequestIntoSpan(cfg *config.EBPFTracer, record *ringbuf.Record, filter ServiceFilter) (request.Span, bool, error) {
	var event TCPRequestInfo

	err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event)
	if err != nil {
		return request.Span{}, true, err
	}

	if !filter.ValidPID(event.Pid.UserPid, event.Pid.Ns, PIDTypeKProbes) {
		return request.Span{}, true, nil
	}

	l := int(event.Len)
	if l < 0 || len(event.Buf) < l {
		l = len(event.Buf)
	}

	rl := int(event.RespLen)
	if rl < 0 || len(event.Rbuf) < rl {
		rl = len(event.Rbuf)
	}

	b := event.Buf[:l]

	if cfg.ProtocolDebug {
		fmt.Printf("[>] %v\n", b)
		fmt.Printf("[<] %v\n", event.Rbuf[:rl])
	}

	// Check if we have a SQL statement
	op, table, sql, kind := detectSQLPayload(cfg.HeuristicSQLDetect, b)
	if validSQL(op, table, kind) {
		return TCPToSQLToSpan(&event, op, table, sql, kind), false, nil
	} else {
		op, table, sql, kind = detectSQLPayload(cfg.HeuristicSQLDetect, event.Rbuf[:rl])
		if validSQL(op, table, kind) {
			reverseTCPEvent(&event)

			return TCPToSQLToSpan(&event, op, table, sql, kind), false, nil
		}
	}

	if maybeFastCGI(b) {
		op, uri, status := detectFastCGI(b, event.Rbuf[:rl])
		if status >= 0 {
			return TCPToFastCGIToSpan(&event, op, uri, status), false, nil
		}
	}

	// Try to detect JSON-RPC
	if jsonRPCSpan := tryDetectJSONRPC(&event, b, event.Rbuf[:rl]); jsonRPCSpan != nil {
		return *jsonRPCSpan, false, nil
	}

	switch {
	case isRedis(b) && isRedis(event.Rbuf[:rl]):
		op, text, ok := parseRedisRequest(string(b))

		if ok {
			var status int
			if op == "" {
				op, text, ok = parseRedisRequest(string(event.Rbuf[:rl]))
				if !ok || op == "" {
					return request.Span{}, true, nil // ignore if we couldn't parse it
				}
				// We've caught the event reversed in the middle of communication, let's
				// reverse the event
				reverseTCPEvent(&event)
				status = redisStatus(b)
			} else {
				status = redisStatus(event.Rbuf[:rl])
			}

			return TCPToRedisToSpan(&event, op, text, status), false, nil
		}
	default:
		// Kafka and gRPC can look very similar in terms of bytes. We can mistake one for another.
		// We try gRPC first because it's more reliable in detecting false gRPC sequences.
		if isHTTP2(b, int(event.Len)) || isHTTP2(event.Rbuf[:rl], int(event.RespLen)) {
			MisclassifiedEvents <- MisclassifiedEvent{EventType: EventTypeKHTTP2, TCPInfo: &event}
		} else {
			k, err := ProcessPossibleKafkaEvent(&event, b, event.Rbuf[:rl])
			if err == nil {
				return TCPToKafkaToSpan(&event, k), false, nil
			}
		}
	}

	return request.Span{}, true, nil // ignore if we couldn't parse it
}

// tryDetectJSONRPC attempts to detect and parse both request and response for JSON-RPC
// Returns a pointer to a span if successful, nil otherwise
func tryDetectJSONRPC(event *TCPRequestInfo, reqData []byte, respData []byte) *request.Span {
	// Try parsing request first
	if jsonLen, method, id := parseJSONRPC(reqData); jsonLen > 0 {
		// Create a span for the JSON-RPC request
		span := TCPToJSONRPCToSpan(event, method, id, 0)

		// Try parsing response to get status
		if respLen, _, respId, errorCode := parseJSONRPCResponse(respData); respLen > 0 && respId == id {
			span.Status = errorCode
		}

		return span
	}

	// If request parsing failed, try parsing as a response
	// This handles cases where we might have caught only the response side of the communication
	if jsonLen, _, id, errorCode := parseJSONRPCResponse(respData); jsonLen > 0 {
		// In this case, we need to reverse the TCP direction since we caught the response
		reverseTCPEvent(event)
		// Method will be empty since we only have the response
		span := TCPToJSONRPCToSpan(event, "", id, errorCode)
		return span
	}

	return nil
}

// parseJSONRPC attempts to parse the input as a JSON-RPC request
// Returns the length of the JSON-RPC message, method name and request ID if successful
func parseJSONRPC(data []byte) (int, string, string) {
	// Quick check for JSON format
	if len(data) < 2 || data[0] != '{' {
		return 0, "", ""
	}

	// Find the end of the JSON object
	depth := 0
	endPos := 0
	for i, b := range data {
		if b == '{' {
			depth++
		} else if b == '}' {
			depth--
			if depth == 0 {
				endPos = i + 1
				break
			}
		}
	}

	if endPos == 0 || endPos > len(data) {
		return 0, "", ""
	}

	jsonData := data[:endPos]

	// Try to parse as JSON
	var jsonObj map[string]interface{}
	if err := json.Unmarshal(jsonData, &jsonObj); err != nil {
		return 0, "", ""
	}

	// Check if it's a JSON-RPC request
	jsonrpcVersion, hasVersion := jsonObj["jsonrpc"].(string)
	if !hasVersion || jsonrpcVersion != "2.0" {
		return 0, "", ""
	}

	// Extract method if present
	method, hasMethod := jsonObj["method"].(string)
	if !hasMethod {
		return 0, "", ""
	}

	// Extract ID if present
	var idStr string
	if id, hasID := jsonObj["id"]; hasID {
		switch v := id.(type) {
		case string:
			idStr = v
		case float64:
			idStr = fmt.Sprintf("%v", v)
		}
	}

	return endPos, method, idStr
}

// parseJSONRPCResponse attempts to parse the input as a JSON-RPC response
// Returns the length of the JSON-RPC message, success indicator, request ID and error code if present
func parseJSONRPCResponse(data []byte) (int, bool, string, int) {
	// Quick check for JSON format
	if len(data) < 2 || data[0] != '{' {
		return 0, false, "", 0
	}

	// Find the end of the JSON object
	depth := 0
	endPos := 0
	for i, b := range data {
		if b == '{' {
			depth++
		} else if b == '}' {
			depth--
			if depth == 0 {
				endPos = i + 1
				break
			}
		}
	}

	if endPos == 0 || endPos > len(data) {
		return 0, false, "", 0
	}

	jsonData := data[:endPos]

	// Try to parse as JSON
	var jsonObj map[string]interface{}
	if err := json.Unmarshal(jsonData, &jsonObj); err != nil {
		return 0, false, "", 0
	}

	// Check if it's a JSON-RPC response
	jsonrpcVersion, hasVersion := jsonObj["jsonrpc"].(string)
	if !hasVersion || jsonrpcVersion != "2.0" {
		return 0, false, "", 0
	}

	// Extract ID if present
	var idStr string
	if id, hasID := jsonObj["id"]; hasID {
		switch v := id.(type) {
		case string:
			idStr = v
		case float64:
			idStr = fmt.Sprintf("%v", v)
		}
	}

	// Check if it's a success or error response
	isSuccess := false
	errorCode := 0

	if _, hasResult := jsonObj["result"]; hasResult {
		isSuccess = true
	} else if errorObj, hasError := jsonObj["error"].(map[string]interface{}); hasError {
		if code, hasCode := errorObj["code"].(float64); hasCode {
			errorCode = int(code)
		}
	} else {
		return 0, false, "", 0 // Neither result nor error, not a valid JSON-RPC response
	}

	return endPos, isSuccess, idStr, errorCode
}

// TCPToJSONRPCToSpan converts a TCP request to a JSON-RPC span
func TCPToJSONRPCToSpan(req *TCPRequestInfo, method string, id string, errorCode int) *request.Span {
	span := TCPBaseSpan(req, 0)
	span.Type = request.EventTypeJSONRPC

	// Set method and path (used for RPC method name and request ID)
	span.Method = method
	span.Path = id

	// Set status code
	span.Status = errorCode

	return span
}

// TCPBaseSpan creates a basic span with common TCP connection information
func TCPBaseSpan(trace *TCPRequestInfo, status int) *request.Span {
	peer := ""
	peerPort := 0
	hostname := ""
	hostPort := 0
	
	if trace.ConnInfo.S_port != 0 || trace.ConnInfo.D_port != 0 {
		peer, hostname = (*BPFConnInfo)(unsafe.Pointer(&trace.ConnInfo)).reqHostInfo()
		peerPort = int(trace.ConnInfo.S_port)
		hostPort = int(trace.ConnInfo.D_port)
	}
	
	return &request.Span{
		Peer:          peer,
		PeerPort:      peerPort,
		Host:          hostname,
		HostPort:      hostPort,
		ContentLength: int64(trace.Len),
		RequestStart:  int64(trace.StartMonotimeNs),
		Start:         int64(trace.StartMonotimeNs),
		End:           int64(trace.EndMonotimeNs),
		Status:        status,
		TraceID:       trace2.TraceID(trace.Tp.TraceId),
		SpanID:        trace2.SpanID(trace.Tp.SpanId),
		ParentSpanID:  trace2.SpanID(trace.Tp.ParentId),
		Flags:         trace.Tp.Flags,
		Pid: request.PidInfo{
			HostPID:   trace.Pid.HostPid,
			UserPID:   trace.Pid.UserPid,
			Namespace: trace.Pid.Ns,
		},
	}
}

func reverseTCPEvent(trace *TCPRequestInfo) {
	if trace.Direction == 0 {
		trace.Direction = 1
	} else {
		trace.Direction = 0
	}

	port := trace.ConnInfo.S_port
	addr := trace.ConnInfo.S_addr
	trace.ConnInfo.S_addr = trace.ConnInfo.D_addr
	trace.ConnInfo.S_port = trace.ConnInfo.D_port
	trace.ConnInfo.D_addr = addr
	trace.ConnInfo.D_port = port
}
