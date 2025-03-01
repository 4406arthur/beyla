package ebpfcommon

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/rand"
	"strings"
	"testing"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/grafana/beyla/v2/pkg/config"
	"github.com/grafana/beyla/v2/pkg/internal/request"
	"github.com/grafana/beyla/v2/pkg/internal/svc"
)

const (
	tcpSend = 1
	tcpRecv = 0
)

func TestTCPReqSQLParsing(t *testing.T) {
	sql := randomStringWithSub("SELECT * FROM accounts ")
	r := makeTCPReq(sql, tcpSend, 343534, 8080, 2000)
	op, table, sql := detectSQL(sql)
	assert.Equal(t, op, "SELECT")
	assert.Equal(t, table, "accounts")
	s := TCPToSQLToSpan(&r, op, table, sql, request.DBGeneric)
	assert.NotNil(t, s)
	assert.NotEmpty(t, s.Host)
	assert.NotEmpty(t, s.Peer)
	assert.Equal(t, s.HostPort, 8080)
	assert.Greater(t, s.End, s.Start)
	assert.True(t, strings.Contains(s.Statement, "SELECT * FROM accounts "))
	assert.Equal(t, "SELECT", s.Method)
	assert.Equal(t, "accounts", s.Path)
	assert.Equal(t, request.EventTypeSQLClient, s.Type)
}

func TestTCPReqParsing(t *testing.T) {
	sql := "Not a sql or any known protocol"
	r := makeTCPReq(sql, tcpSend, 343534, 8080, 2000)
	op, table, _ := detectSQL(sql)
	assert.Empty(t, op)
	assert.Empty(t, table)
	assert.NotNil(t, r)
}

func TestSQLDetection(t *testing.T) {
	for _, s := range []string{"SELECT * from accounts", "SELECT/*My comment*/ * from accounts", "--UPDATE accounts SET", "DELETE++ from accounts ", "INSERT into accounts ", "CREATE table accounts ", "DROP table accounts ", "ALTER table accounts"} {
		surrounded := randomStringWithSub(s)
		op, table, _ := detectSQL(s)
		assert.NotEmpty(t, op)
		assert.NotEmpty(t, table)
		op, table, _ = detectSQL(surrounded)
		assert.NotEmpty(t, op)
		assert.NotEmpty(t, table)
	}
}

func TestSQLDetectionFails(t *testing.T) {
	for _, s := range []string{"SELECT", "UPDATES{}", "DELETE {} ", "INSERT// into accounts "} {
		op, table, _ := detectSQL(s)
		assert.False(t, validSQL(op, table, request.DBGeneric))
		surrounded := randomStringWithSub(s)
		op, table, _ = detectSQL(surrounded)
		assert.False(t, validSQL(op, table, request.DBGeneric))
	}
}

func TestSQLDetectionDoesntFailForDetectedKind(t *testing.T) {
	for _, s := range []string{"SELECT", "DELETE {} "} {
		op, table, _ := detectSQL(s)
		assert.True(t, validSQL(op, table, request.DBPostgres))
	}
}

// Test making sure that issue https://github.com/grafana/beyla/issues/854 is fixed
func TestReadTCPRequestIntoSpan_Overflow(t *testing.T) {
	fltr := TestPidsFilter{services: map[uint32]svc.Attrs{}}

	tri := TCPRequestInfo{
		Len: 340,
		// this byte array contains select * from foo
		// rest of the array is invalid UTF-8 and would cause that strings.ToUpper
		// returns a string longer than 256. That's why we are providing
		// our own asciiToUpper implementation in detectSQL function
		Buf: [256]byte{
			74, 39, 133, 207, 240, 83, 124, 225, 227, 163, 3, 23, 253, 254, 18, 12, 77, 143, 198, 122,
			123, 67, 221, 225, 10, 233, 220, 36, 65, 35, 25, 251, 88, 197, 107, 99, 25, 247, 195, 216,
			245, 107, 26, 144, 75, 78, 24, 70, 136, 173, 198, 79, 148, 232, 19, 253, 185, 169, 213, 97,
			85, 119, 210, 114, 92, 26, 226, 241, 33, 16, 199, 78, 88, 108, 8, 211, 76, 188, 8, 170, 68,
			128, 108, 194, 67, 240, 144, 132, 50, 191, 136, 130, 52, 210, 166, 212, 17, 179, 144, 138,
			101, 98, 119, 16, 125, 99, 161, 176, 9, 25, 218, 236, 219, 22, 144, 91, 158, 146, 14, 243,
			177, 58, 40, 139, 158, 33, 3, 91, 63, 70, 85, 20, 222, 206, 211, 152, 216, 53, 177, 125, 204,
			219, 157, 151, 222, 184, 241, 193, 111, 22, 242, 185, 126, 159, 53, 181,
			's', 'e', 'l', 'e', 'c', 't', ' ', '*', ' ', 'f', 'r', 'o', 'm', ' ', 'f', 'o', 'o',
			0, 17, 111, 111, 133, 13, 221,
			135, 126, 159, 234, 95, 233, 172, 96, 241, 140, 96, 71, 100, 223, 73, 74, 117, 239, 170, 154,
			148, 167, 122, 215, 170, 51, 236, 146, 5, 61, 208, 74, 230, 243, 106, 222, 52, 138, 202, 39,
			122, 180, 232, 43, 217, 86, 220, 38, 106, 141, 188, 27, 133, 156, 96, 107, 180, 178, 20, 62,
			169, 193, 172, 206, 225, 219, 112, 52, 115, 32, 147, 192, 127, 211, 129, 241,
		},
	}

	cfg := config.EBPFTracer{HeuristicSQLDetect: true}

	binaryRecord := bytes.Buffer{}
	require.NoError(t, binary.Write(&binaryRecord, binary.LittleEndian, tri))
	span, ignore, err := ReadTCPRequestIntoSpan(&cfg, &ringbuf.Record{RawSample: binaryRecord.Bytes()}, &fltr)
	require.NoError(t, err)
	require.False(t, ignore)

	assert.Equal(t, request.EventTypeSQLClient, span.Type)
	assert.Equal(t, "SELECT", span.Method)
	assert.Equal(t, "foo", span.Path)
}

func TestRedisDetection(t *testing.T) {
	for _, s := range []string{
		`*2|$3|GET|$5|beyla|`,
		`*2|$7|HGETALL|$16|users_sessions`,
		`*8|$4|name|$4|John|`,
		`+OK|`,
		"-ERR ",
		":123|",
		"-WRONGTYPE ",
		"-MOVED ",
	} {
		lines := strings.Split(s, "|")
		test := strings.Join(lines, "\r\n")
		assert.True(t, isRedis([]uint8(test)))
		assert.True(t, isRedisOp([]uint8(test)))
	}

	for _, s := range []string{
		"",
		`*2`,
		`*$7`,
		`+OK`,
		"-ERR",
		"-WRONGTYPE",
	} {
		lines := strings.Split(s, "|")
		test := strings.Join(lines, "\r\n")
		assert.False(t, isRedis([]uint8(test)))
		assert.False(t, isRedisOp([]uint8(test)))
	}
}

func TestTCPReqKafkaParsing(t *testing.T) {
	// kafka message
	b := []byte{0, 0, 0, 94, 0, 1, 0, 11, 0, 0, 0, 224, 0, 6, 115, 97, 114, 97, 109, 97, 255, 255, 255, 255, 0, 0, 1, 244, 0, 0, 0, 1, 6, 64, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 0, 0, 0, 1, 0, 9, 105, 109, 112, 111, 114, 116, 97, 110, 116, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 0}
	r := makeTCPReq(string(b), tcpSend, 343534, 8080, 2000)
	k, err := ProcessKafkaRequest(b)
	assert.NoError(t, err)
	s := TCPToKafkaToSpan(&r, k)
	assert.NotNil(t, s)
	assert.NotEmpty(t, s.Host)
	assert.NotEmpty(t, s.Peer)
	assert.Equal(t, s.HostPort, 8080)
	assert.Greater(t, s.End, s.Start)
	assert.Equal(t, "process", s.Method)
	assert.Equal(t, "important", s.Path)
	assert.Equal(t, "sarama", s.Statement)
	assert.Equal(t, request.EventTypeKafkaClient, s.Type)
}

func TestTryParseJSONRPC(t *testing.T) {
	tests := []struct {
		name         string
		input        []byte
		wantLen      int
		wantMethod   string
		wantStatus   string
		wantMetaKeys []string
	}{
		{
			name:         "Valid JSON-RPC request",
			input:        []byte(`{"jsonrpc": "2.0", "method": "subtract", "params": [42, 23], "id": 1}`),
			wantLen:      61,
			wantMethod:   "subtract",
			wantStatus:   "",
			wantMetaKeys: []string{"jsonrpc.version", "jsonrpc.request_id", "jsonrpc.params"},
		},
		{
			name:         "Valid JSON-RPC response success",
			input:        []byte(`{"jsonrpc": "2.0", "result": 19, "id": 1}`),
			wantLen:      39,
			wantMethod:   "",
			wantStatus:   "OK",
			wantMetaKeys: []string{"jsonrpc.version", "jsonrpc.request_id"},
		},
		{
			name:         "Valid JSON-RPC response error",
			input:        []byte(`{"jsonrpc": "2.0", "error": {"code": -32601, "message": "Method not found"}, "id": 1}`),
			wantLen:      80,
			wantMethod:   "",
			wantStatus:   "ERROR",
			wantMetaKeys: []string{"jsonrpc.version", "jsonrpc.request_id", "jsonrpc.error_code", "jsonrpc.error_message"},
		},
		{
			name:         "Not JSON",
			input:        []byte(`not json`),
			wantLen:      0,
			wantMethod:   "",
			wantStatus:   "",
			wantMetaKeys: nil,
		},
		{
			name:         "Invalid JSON-RPC (no version)",
			input:        []byte(`{"method": "subtract", "params": [42, 23], "id": 1}`),
			wantLen:      0,
			wantMethod:   "",
			wantStatus:   "",
			wantMetaKeys: nil,
		},
		{
			name:         "Invalid JSON-RPC (wrong version)",
			input:        []byte(`{"jsonrpc": "1.0", "method": "subtract", "params": [42, 23], "id": 1}`),
			wantLen:      0,
			wantMethod:   "",
			wantStatus:   "",
			wantMetaKeys: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			span := &request.Span{Meta: make(map[string]string)}
			gotLen, _ := tryParseJSONRPC(tt.input, span)

			if gotLen != tt.wantLen {
				t.Errorf("tryParseJSONRPC() gotLen = %v, want %v", gotLen, tt.wantLen)
			}

			if gotLen > 0 {
				if span.Method != tt.wantMethod {
					t.Errorf("tryParseJSONRPC() Method = %v, want %v", span.Method, tt.wantMethod)
				}

				if span.Status != tt.wantStatus {
					t.Errorf("tryParseJSONRPC() Status = %v, want %v", span.Status, tt.wantStatus)
				}

				for _, key := range tt.wantMetaKeys {
					if _, ok := span.Meta[key]; !ok {
						t.Errorf("tryParseJSONRPC() Meta missing key = %v", key)
					}
				}
			}
		})
	}
}

func TestJSONRPCDetection(t *testing.T) {
	testCases := []struct {
		name           string
		requestData    []byte
		responseData   []byte
		expectDetected bool
		expectMethod   string
		expectID       string
		expectStatus   int
	}{
		{
			name:           "Valid JSON-RPC request and success response",
			requestData:    []byte(`{"jsonrpc": "2.0", "method": "subtract", "params": [42, 23], "id": 1}`),
			responseData:   []byte(`{"jsonrpc": "2.0", "result": 19, "id": 1}`),
			expectDetected: true,
			expectMethod:   "subtract",
			expectID:       "1",
			expectStatus:   0,
		},
		{
			name:           "Valid JSON-RPC request with error response",
			requestData:    []byte(`{"jsonrpc": "2.0", "method": "unknown_method", "id": 2}`),
			responseData:   []byte(`{"jsonrpc": "2.0", "error": {"code": -32601, "message": "Method not found"}, "id": 2}`),
			expectDetected: true,
			expectMethod:   "unknown_method",
			expectID:       "2",
			expectStatus:   -32601,
		},
		{
			name:           "Invalid JSON",
			requestData:    []byte(`not json`),
			responseData:   []byte(`also not json`),
			expectDetected: false,
		},
		{
			name:           "Valid JSON but not JSON-RPC",
			requestData:    []byte(`{"foo": "bar"}`),
			responseData:   []byte(`{"result": "ok"}`),
			expectDetected: false,
		},
		{
			name:           "Valid JSON-RPC but wrong version",
			requestData:    []byte(`{"jsonrpc": "1.0", "method": "subtract", "params": [42, 23], "id": 1}`),
			responseData:   []byte(`{"jsonrpc": "1.0", "result": 19, "id": 1}`),
			expectDetected: false,
		},
		{
			name:           "Only response available",
			requestData:    []byte(``),
			responseData:   []byte(`{"jsonrpc": "2.0", "result": 19, "id": 1}`),
			expectDetected: true,
			expectMethod:   "",
			expectID:       "1",
			expectStatus:   0,
		},
		{
			name:           "Only error response available",
			requestData:    []byte(``),
			responseData:   []byte(`{"jsonrpc": "2.0", "error": {"code": -32700, "message": "Parse error"}, "id": null}`),
			expectDetected: true,
			expectMethod:   "",
			expectID:       "",
			expectStatus:   -32700,
		},
		{
			name:           "Notification request (no id)",
			requestData:    []byte(`{"jsonrpc": "2.0", "method": "update", "params": [1,2,3,4,5]}`),
			responseData:   []byte(``),
			expectDetected: true,
			expectMethod:   "update",
			expectID:       "",
			expectStatus:   0,
		},
		{
			name:           "Method with namespace",
			requestData:    []byte(`{"jsonrpc": "2.0", "method": "eth.getBalance", "params": ["0x1234"], "id": "abc"}`),
			responseData:   []byte(`{"jsonrpc": "2.0", "result": "0x5678", "id": "abc"}`),
			expectDetected: true,
			expectMethod:   "eth.getBalance",
			expectID:       "abc",
			expectStatus:   0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := makeTCPReq(string(tc.requestData), tcpSend, 34343, 8080, 1000)

			// Make a copy of the request for the response
			resp := req
			copy(resp.Buf[:], tc.responseData)
			resp.Len = uint32(len(tc.responseData))

			// Test detection
			span := tryDetectJSONRPC(&req, req.Buf[:req.Len], resp.Buf[:resp.Len])

			if tc.expectDetected {
				require.NotNil(t, span, "Expected JSON-RPC to be detected")
				assert.Equal(t, request.EventTypeJSONRPC, span.Type, "Expected correct event type")
				assert.Equal(t, tc.expectMethod, span.Method, "Expected correct method")
				assert.Equal(t, tc.expectID, span.Path, "Expected correct ID in Path field")
				assert.Equal(t, tc.expectStatus, span.Status, "Expected correct status")
				assert.Greater(t, span.End, span.Start, "Expected valid timestamps")
			} else {
				assert.Nil(t, span, "Expected no JSON-RPC detection")
			}
		})
	}
}

func TestJSONRPCParsing(t *testing.T) {
	testCases := []struct {
		name         string
		input        []byte
		expectLen    int
		expectMethod string
		expectID     string
	}{
		{
			name:         "Valid request with numeric ID",
			input:        []byte(`{"jsonrpc": "2.0", "method": "subtract", "params": [42, 23], "id": 1}`),
			expectLen:    61,
			expectMethod: "subtract",
			expectID:     "1",
		},
		{
			name:         "Valid request with string ID",
			input:        []byte(`{"jsonrpc": "2.0", "method": "echo", "params": {"message": "Hello"}, "id": "abc123"}`),
			expectLen:    75,
			expectMethod: "echo",
			expectID:     "abc123",
		},
		{
			name:         "Notification (no ID)",
			input:        []byte(`{"jsonrpc": "2.0", "method": "update", "params": [1,2,3,4,5]}`),
			expectLen:    55,
			expectMethod: "update",
			expectID:     "",
		},
		{
			name:         "Not JSON",
			input:        []byte(`not json`),
			expectLen:    0,
			expectMethod: "",
			expectID:     "",
		},
		{
			name:         "Not JSON-RPC",
			input:        []byte(`{"method": "test", "id": 1}`),
			expectLen:    0,
			expectMethod: "",
			expectID:     "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			length, method, id := parseJSONRPC(tc.input)
			assert.Equal(t, tc.expectLen, length, "Expected correct length")
			assert.Equal(t, tc.expectMethod, method, "Expected correct method")
			assert.Equal(t, tc.expectID, id, "Expected correct ID")
		})
	}
}

func TestJSONRPCResponseParsing(t *testing.T) {
	testCases := []struct {
		name          string
		input         []byte
		expectLen     int
		expectSuccess bool
		expectID      string
		expectCode    int
	}{
		{
			name:          "Success response",
			input:         []byte(`{"jsonrpc": "2.0", "result": 19, "id": 1}`),
			expectLen:     39,
			expectSuccess: true,
			expectID:      "1",
			expectCode:    0,
		},
		{
			name:          "Error response",
			input:         []byte(`{"jsonrpc": "2.0", "error": {"code": -32601, "message": "Method not found"}, "id": 2}`),
			expectLen:     80,
			expectSuccess: false,
			expectID:      "2",
			expectCode:    -32601,
		},
		{
			name:          "Error response with string ID",
			input:         []byte(`{"jsonrpc": "2.0", "error": {"code": -32700, "message": "Parse error"}, "id": "abc"}`),
			expectLen:     78,
			expectSuccess: false,
			expectID:      "abc",
			expectCode:    -32700,
		},
		{
			name:          "Not JSON",
			input:         []byte(`not json`),
			expectLen:     0,
			expectSuccess: false,
			expectID:      "",
			expectCode:    0,
		},
		{
			name:          "Not JSON-RPC response",
			input:         []byte(`{"result": "ok", "id": 1}`),
			expectLen:     0,
			expectSuccess: false,
			expectID:      "",
			expectCode:    0,
		},
		{
			name:          "Invalid JSON-RPC response (no result or error)",
			input:         []byte(`{"jsonrpc": "2.0", "id": 1}`),
			expectLen:     0,
			expectSuccess: false,
			expectID:      "",
			expectCode:    0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			length, success, id, code := parseJSONRPCResponse(tc.input)
			assert.Equal(t, tc.expectLen, length, "Expected correct length")
			assert.Equal(t, tc.expectSuccess, success, "Expected correct success flag")
			assert.Equal(t, tc.expectID, id, "Expected correct ID")
			assert.Equal(t, tc.expectCode, code, "Expected correct error code")
		})
	}
}

const charset = "\\0\\1\\2abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func randomString(length int) string {
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

func randomStringWithSub(sub string) string {
	return fmt.Sprintf("%s%s%s", randomString(rand.Intn(10)), sub, randomString(rand.Intn(20)))
}

func makeTCPReq(buf string, direction int, peerPort, hostPort uint32, durationMs uint64) TCPRequestInfo {
	i := TCPRequestInfo{
		StartMonotimeNs: durationMs * 1000000,
		EndMonotimeNs:   durationMs * 2 * 1000000,
		Len:             uint32(len(buf)),
		Direction:       uint8(direction),
	}

	copy(i.Buf[:], buf)
	i.ConnInfo.S_addr[0] = 1
	i.ConnInfo.S_addr[1] = 0
	i.ConnInfo.S_addr[2] = 0
	i.ConnInfo.S_addr[3] = 127
	i.ConnInfo.S_port = uint16(peerPort)
	i.ConnInfo.D_addr[0] = 1
	i.ConnInfo.D_addr[1] = 0
	i.ConnInfo.D_addr[2] = 0
	i.ConnInfo.D_addr[3] = 127
	i.ConnInfo.D_port = uint16(hostPort)

	return i
}
