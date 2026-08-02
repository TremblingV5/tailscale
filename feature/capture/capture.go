// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package capture formats packet logging into a debug pcap stream.
package capture

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"

	"tailscale.com/feature"
	"tailscale.com/ipn/localapi"
	"tailscale.com/net/packet"
	"tailscale.com/util/set"
)

func init() {
	feature.Register("capture")
	localapi.Register("debug-capture", serveLocalAPIDebugCapture)
}

func serveLocalAPIDebugCapture(h *localapi.Handler, w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if !h.PermitWrite {
		http.Error(w, "debug access denied", http.StatusForbidden)
		return
	}
	if r.Method != "POST" {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.(http.Flusher).Flush()

	b := h.LocalBackend()
	s := b.GetOrSetCaptureSink(newSink)
	if sink, ok := s.(*Sink); ok {
		sink.setSnaplen(snaplenFromRequest(r))
	}

	unregister := s.RegisterOutput(w)

	select {
	case <-ctx.Done():
	case <-s.WaitCh():
	}
	unregister()

	b.ClearCaptureSink()
}

// snaplenFromRequest parses the optional "snaplen" query parameter from the
// capture request. A value of 0 (the default when the parameter is absent or
// unparseable) means "no limit": the full packet is captured, preserving the
// historical behaviour. A positive value caps the number of packet bytes
// written per record, like tcpdump(1)'s -s flag.
func snaplenFromRequest(r *http.Request) int {
	if sl := r.URL.Query().Get("snaplen"); sl != "" {
		if n, err := strconv.Atoi(sl); err == nil && n > 0 {
			return n
		}
	}
	return 0
}

var bufferPool = sync.Pool{
	New: func() any {
		return new(bytes.Buffer)
	},
}

const flushPeriod = 100 * time.Millisecond

// pcapSnaplenUnlimited is the snapshot length advertised in the pcap global
// header when no limit is requested. It is large enough to hold any packet
// Tailscale handles, and matches the value historically written there.
const pcapSnaplenUnlimited = 65535

func writePcapHeader(w io.Writer, snaplen int) {
	if snaplen <= 0 {
		snaplen = pcapSnaplenUnlimited
	}
	binary.Write(w, binary.LittleEndian, uint32(0xA1B2C3D4)) // pcap magic number
	binary.Write(w, binary.LittleEndian, uint16(2))          // version major
	binary.Write(w, binary.LittleEndian, uint16(4))          // version minor
	binary.Write(w, binary.LittleEndian, uint32(0))          // this zone
	binary.Write(w, binary.LittleEndian, uint32(0))          // zone significant figures
	binary.Write(w, binary.LittleEndian, uint32(snaplen))    // max packet len (snaplen)
	binary.Write(w, binary.LittleEndian, uint32(147))        // link-layer ID - USER0
}

func writePktHeader(w *bytes.Buffer, when time.Time, caplen, origlen int) {
	s := when.Unix()
	us := when.UnixMicro() - (s * 1000000)

	binary.Write(w, binary.LittleEndian, uint32(s))       // timestamp in seconds
	binary.Write(w, binary.LittleEndian, uint32(us))      // timestamp microseconds
	binary.Write(w, binary.LittleEndian, uint32(caplen))  // captured length (incl_len)
	binary.Write(w, binary.LittleEndian, uint32(origlen)) // original length (orig_len)
}

// newSink creates a new capture sink.
func newSink() packet.CaptureSink {
	ctx, c := context.WithCancel(context.Background())
	return &Sink{
		ctx:       ctx,
		ctxCancel: c,
	}
}

// Type Sink handles callbacks with packets to be logged,
// formatting them into a pcap stream which is mirrored to
// all registered outputs.
type Sink struct {
	ctx       context.Context
	ctxCancel context.CancelFunc

	mu         sync.Mutex
	outputs    set.HandleSet[io.Writer]
	flushTimer *time.Timer // or nil if none running
	snaplen    int         // max packet bytes to capture per record; 0 = unlimited
}

// setSnaplen sets the maximum number of packet bytes to capture per record.
// A value of 0 or less means no limit (the full packet is captured). This is
// a sink-wide setting: the snapshot length applies to every registered output.
func (s *Sink) setSnaplen(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.snaplen = n
}

// RegisterOutput connects an output to this sink, which
// will be written to with a pcap stream as packets are logged.
// A function is returned which unregisters the output when
// called.
//
// If w implements io.Closer, it will be closed upon error
// or when the sink is closed. If w implements http.Flusher,
// it will be flushed periodically.
func (s *Sink) RegisterOutput(w io.Writer) (unregister func()) {
	select {
	case <-s.ctx.Done():
		return func() {}
	default:
	}

	s.mu.Lock()
	snaplen := s.snaplen
	s.mu.Unlock()

	// Write the pcap global header before this output is visible to
	// LogPacket, so the header is always the first thing written.
	writePcapHeader(w, snaplen)

	s.mu.Lock()
	hnd := s.outputs.Add(w)
	s.mu.Unlock()

	return func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		delete(s.outputs, hnd)
	}
}

func (s *Sink) CaptureCallback() packet.CaptureCallback {
	return s.LogPacket
}

// NumOutputs returns the number of outputs registered with the sink.
func (s *Sink) NumOutputs() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.outputs)
}

// Close shuts down the sink. Future calls to LogPacket
// are ignored, and any registered output that implements
// io.Closer is closed.
func (s *Sink) Close() error {
	s.ctxCancel()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.flushTimer != nil {
		s.flushTimer.Stop()
		s.flushTimer = nil
	}

	for _, o := range s.outputs {
		if o, ok := o.(io.Closer); ok {
			o.Close()
		}
	}
	s.outputs = nil
	return nil
}

// WaitCh returns a channel which blocks until
// the sink is closed.
func (s *Sink) WaitCh() <-chan struct{} {
	return s.ctx.Done()
}

func customDataLen(meta packet.CaptureMeta) int {
	length := 4
	if meta.DidSNAT {
		length += meta.OriginalSrc.Addr().BitLen() / 8
	}
	if meta.DidDNAT {
		length += meta.OriginalDst.Addr().BitLen() / 8
	}
	return length
}

// LogPacket is called to insert a packet into the capture.
//
// This function does not take ownership of the provided data slice.
func (s *Sink) LogPacket(path packet.CapturePath, when time.Time, data []byte, meta packet.CaptureMeta) {
	select {
	case <-s.ctx.Done():
		return
	default:
	}

	extraLen := customDataLen(meta)

	s.mu.Lock()
	snaplen := s.snaplen
	s.mu.Unlock()

	// The snapshot length caps only the packet bytes, never the Tailscale
	// metadata prefix (cutting into it would break the dissector). The pcap
	// record header therefore reports the truncated length as the captured
	// length and the true length as the original length, which is what makes
	// tools like Wireshark mark truncated packets.
	origLen := len(data) + extraLen
	dataLen := len(data)
	if snaplen > 0 && dataLen > snaplen {
		dataLen = snaplen
	}
	capLen := dataLen + extraLen

	b := bufferPool.Get().(*bytes.Buffer)
	b.Reset()
	b.Grow(16 + extraLen + dataLen) // 16b pcap header + len(metadata) + len(payload)
	defer bufferPool.Put(b)

	writePktHeader(b, when, capLen, origLen)

	// Custom tailscale debugging data
	binary.Write(b, binary.LittleEndian, uint16(path))
	if meta.DidSNAT {
		binary.Write(b, binary.LittleEndian, uint8(meta.OriginalSrc.Addr().BitLen()/8))
		b.Write(meta.OriginalSrc.Addr().AsSlice())
	} else {
		binary.Write(b, binary.LittleEndian, uint8(0)) // SNAT addr len == 0
	}
	if meta.DidDNAT {
		binary.Write(b, binary.LittleEndian, uint8(meta.OriginalDst.Addr().BitLen()/8))
		b.Write(meta.OriginalDst.Addr().AsSlice())
	} else {
		binary.Write(b, binary.LittleEndian, uint8(0)) // DNAT addr len == 0
	}

	b.Write(data[:dataLen])

	s.mu.Lock()
	defer s.mu.Unlock()

	var hadError []set.Handle
	for hnd, o := range s.outputs {
		if _, err := o.Write(b.Bytes()); err != nil {
			hadError = append(hadError, hnd)
			continue
		}
	}
	for _, hnd := range hadError {
		if o, ok := s.outputs[hnd].(io.Closer); ok {
			o.Close()
		}
		delete(s.outputs, hnd)
	}

	if s.flushTimer == nil {
		s.flushTimer = time.AfterFunc(flushPeriod, func() {
			s.mu.Lock()
			defer s.mu.Unlock()
			for _, o := range s.outputs {
				if f, ok := o.(http.Flusher); ok {
					f.Flush()
				}
			}
			s.flushTimer = nil
		})
	}
}
