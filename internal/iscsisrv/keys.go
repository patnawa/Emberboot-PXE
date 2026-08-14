package iscsisrv

import (
	"sort"
	"strings"
)

// iSCSI text keys are key=value pairs separated by NUL bytes.

func parseKeys(data []byte) map[string]string {
	out := map[string]string{}
	for _, kv := range strings.Split(string(data), "\x00") {
		if kv == "" {
			continue
		}
		if i := strings.IndexByte(kv, '='); i > 0 {
			out[kv[:i]] = kv[i+1:]
		}
	}
	return out
}

func encodeKeys(keys map[string]string) []byte {
	// Deterministic order keeps tests and packet captures stable.
	names := make([]string, 0, len(keys))
	for k := range keys {
		names = append(names, k)
	}
	sort.Strings(names)
	var b strings.Builder
	for _, k := range names {
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(keys[k])
		b.WriteByte(0)
	}
	return []byte(b.String())
}

// negotiate answers the operational keys an initiator proposes. We are a
// deliberately simple target: no digests, single connection, no recovery,
// and (being read-only) the write-direction keys are echoes of whatever the
// initiator wants.
func negotiate(proposed map[string]string) map[string]string {
	resp := map[string]string{}
	for k, v := range proposed {
		switch k {
		case "HeaderDigest", "DataDigest":
			resp[k] = "None"
		case "MaxConnections":
			resp[k] = "1"
		case "InitialR2T":
			resp[k] = "Yes"
		case "ImmediateData":
			resp[k] = "No"
		case "MaxRecvDataSegmentLength":
			// Declarative in each direction; ours is sent separately.
		case "MaxBurstLength", "FirstBurstLength":
			resp[k] = v // reads are bounded by our Data-In size anyway
		case "DefaultTime2Wait":
			resp[k] = "2"
		case "DefaultTime2Retain":
			resp[k] = "0"
		case "MaxOutstandingR2T":
			resp[k] = "1"
		case "DataPDUInOrder", "DataSequenceInOrder":
			resp[k] = "Yes"
		case "ErrorRecoveryLevel":
			resp[k] = "0"
		case "IFMarker", "OFMarker":
			resp[k] = "No"
		case "InitiatorName", "InitiatorAlias", "SessionType", "TargetName":
			// Consumed by the login handler, not negotiated back.
		default:
			// Unknown keys must be answered or the initiator may stall.
			resp[k] = "NotUnderstood"
		}
	}
	return resp
}
