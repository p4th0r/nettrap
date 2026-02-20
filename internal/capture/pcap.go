package capture

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/p4th0r/nettrap/internal/logging"
	"golang.org/x/sys/unix"
)

// Capture handles packet capture on the host-side veth interface
// and writes packets to a pcapng file.
type Capture struct {
	iface    string
	filePath string
	logger   *logging.StderrLogger
	comment  string

	fd     int
	file   *os.File
	writer *pcapgo.NgWriter
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	count  atomic.Int64
}

// CaptureConfig holds configuration for creating a Capture.
type CaptureConfig struct {
	Interface string // e.g., "veth-host-a3f8"
	FilePath  string // output pcapng file path
	Logger    *logging.StderrLogger
	Comment   string // pcapng section comment
}

// New creates a new Capture instance.
func New(cfg CaptureConfig) *Capture {
	ctx, cancel := context.WithCancel(context.Background())
	return &Capture{
		iface:    cfg.Interface,
		filePath: cfg.FilePath,
		logger:   cfg.Logger,
		comment:  cfg.Comment,
		fd:       -1,
		ctx:      ctx,
		cancel:   cancel,
	}
}

// Start opens the capture file and begins capturing packets.
func (c *Capture) Start() error {
	// Open raw AF_PACKET socket
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return fmt.Errorf("creating raw socket: %w", err)
	}
	c.fd = fd

	// Get interface index
	iface, err := net.InterfaceByName(c.iface)
	if err != nil {
		unix.Close(fd)
		c.fd = -1
		return fmt.Errorf("getting interface %s: %w", c.iface, err)
	}

	// Bind to the specific interface
	sa := unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ALL),
		Ifindex:  iface.Index,
	}
	if err := unix.Bind(fd, &sa); err != nil {
		unix.Close(fd)
		c.fd = -1
		return fmt.Errorf("binding to interface %s: %w", c.iface, err)
	}

	// Set promiscuous mode
	mreq := unix.PacketMreq{
		Ifindex: int32(iface.Index),
		Type:    unix.PACKET_MR_PROMISC,
	}
	if err := unix.SetsockoptPacketMreq(fd, unix.SOL_PACKET, unix.PACKET_ADD_MEMBERSHIP, &mreq); err != nil {
		c.logger.Debug("Warning: could not set promiscuous mode on %s: %v", c.iface, err)
	}

	// Set read timeout so we can check context cancellation periodically
	tv := unix.Timeval{Sec: 1}
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		c.logger.Debug("Warning: could not set socket timeout: %v", err)
	}

	// Open output file
	f, err := os.Create(c.filePath)
	if err != nil {
		unix.Close(fd)
		c.fd = -1
		return fmt.Errorf("creating pcap file %s: %w", c.filePath, err)
	}
	c.file = f

	// Create pcapng writer with interface and section metadata
	intf := pcapgo.NgInterface{
		Name:       c.iface,
		LinkType:   layers.LinkTypeEthernet,
		SnapLength: 65535,
	}
	opts := pcapgo.NgWriterOptions{
		SectionInfo: pcapgo.NgSectionInfo{
			Application: "nettrap",
			Comment:     c.comment,
		},
	}
	w, err := pcapgo.NewNgWriterInterface(f, intf, opts)
	if err != nil {
		unix.Close(fd)
		c.fd = -1
		f.Close()
		os.Remove(c.filePath)
		return fmt.Errorf("creating pcapng writer: %w", err)
	}
	c.writer = w

	c.logger.Debug("PCAP capture started on %s -> %s", c.iface, c.filePath)

	c.wg.Add(1)
	go c.captureLoop()

	return nil
}

// captureLoop reads packets from the raw socket and writes them to the pcapng file.
func (c *Capture) captureLoop() {
	defer c.wg.Done()

	buf := make([]byte, 65536)

	for {
		if c.ctx.Err() != nil {
			return
		}

		n, _, err := unix.Recvfrom(c.fd, buf, 0)
		if err != nil {
			if c.ctx.Err() != nil {
				return
			}
			if isTimeout(err) {
				continue
			}
			c.logger.Debug("PCAP read error: %v", err)
			continue
		}

		if n == 0 {
			continue
		}

		ci := gopacket.CaptureInfo{
			Timestamp:      time.Now(),
			CaptureLength:  n,
			Length:         n,
			InterfaceIndex: 0,
		}

		if err := c.writer.WritePacket(ci, buf[:n]); err != nil {
			c.logger.Debug("PCAP write error: %v", err)
		}
		c.count.Add(1)
	}
}

// Stop stops the capture, flushes the pcapng file, and reports stats.
func (c *Capture) Stop() error {
	c.cancel()
	c.wg.Wait()

	var firstErr error

	if c.fd >= 0 {
		unix.Close(c.fd)
		c.fd = -1
	}

	if c.writer != nil {
		if err := c.writer.Flush(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("flushing pcapng: %w", err)
		}
	}

	if c.file != nil {
		if err := c.file.Close(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("closing pcap file: %w", err)
		}
	}

	// Report file stats
	count := c.count.Load()
	if info, err := os.Stat(c.filePath); err == nil {
		c.logger.Info("PCAP saved: %s (%s, %d packets)", c.filePath, formatSize(info.Size()), count)
	} else {
		c.logger.Info("PCAP saved: %s (%d packets)", c.filePath, count)
	}

	return firstErr
}

// htons converts a uint16 from host byte order to network byte order.
func htons(v uint16) uint16 {
	return (v << 8) | (v >> 8)
}

// isTimeout checks if an error is a socket timeout.
func isTimeout(err error) bool {
	return err == unix.EAGAIN || err == unix.EWOULDBLOCK
}

// formatSize returns a human-readable file size string.
func formatSize(bytes int64) string {
	const (
		kb = 1024
		mb = kb * 1024
	)
	switch {
	case bytes >= mb:
		return fmt.Sprintf("%.1f MB", float64(bytes)/float64(mb))
	case bytes >= kb:
		return fmt.Sprintf("%.1f KB", float64(bytes)/float64(kb))
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}
