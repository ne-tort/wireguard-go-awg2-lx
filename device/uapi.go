/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/wireguard-go/ipc"
)

type IPCError struct {
	code int64 // error code
	err  error // underlying/wrapped error
}

func (s IPCError) Error() string {
	return fmt.Sprintf("IPC error %d: %v", s.code, s.err)
}

func (s IPCError) Unwrap() error {
	return s.err
}

func (s IPCError) ErrorCode() int64 {
	return s.code
}

func ipcErrorf(code int64, msg string, args ...any) *IPCError {
	return &IPCError{code: code, err: fmt.Errorf(msg, args...)}
}

var byteBufferPool = &sync.Pool{
	New: func() any { return new(bytes.Buffer) },
}

// IpcGetOperation implements the WireGuard configuration protocol "get" operation.
// See https://www.wireguard.com/xplatform/#configuration-protocol for details.
func (device *Device) IpcGetOperation(w io.Writer) error {
	device.ipcMutex.RLock()
	defer device.ipcMutex.RUnlock()

	buf := byteBufferPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer byteBufferPool.Put(buf)
	sendf := func(format string, args ...any) {
		fmt.Fprintf(buf, format, args...)
		buf.WriteByte('\n')
	}
	keyf := func(prefix string, key *[32]byte) {
		buf.Grow(len(key)*2 + 2 + len(prefix))
		buf.WriteString(prefix)
		buf.WriteByte('=')
		const hex = "0123456789abcdef"
		for i := 0; i < len(key); i++ {
			buf.WriteByte(hex[key[i]>>4])
			buf.WriteByte(hex[key[i]&0xf])
		}
		buf.WriteByte('\n')
	}
	boolf := func(prefix string, val bool) {
		buf.Grow(3 + len(prefix))
		buf.WriteString(prefix)
		buf.WriteByte('=')
		if val {
			buf.WriteByte('1')
		} else {
			buf.WriteByte('0')
		}
		buf.WriteByte('\n')
	}

	func() {
		// lock required resources

		device.net.RLock()
		defer device.net.RUnlock()

		device.staticIdentity.RLock()
		defer device.staticIdentity.RUnlock()

		device.peers.RLock()
		defer device.peers.RUnlock()

		// serialize device related values

		if !device.staticIdentity.privateKey.IsZero() {
			keyf("private_key", (*[32]byte)(&device.staticIdentity.privateKey))
		}

		if device.net.port != 0 {
			sendf("listen_port=%d", device.net.port)
		}

		if device.net.fwmark != 0 {
			sendf("fwmark=%d", device.net.fwmark)
		}

		// lx:begin pathology
		if device.pathologyEnabled() {
			sendf("pathology=true")
			device.pathology.mu.RLock()
			cfg := device.pathology.cfg
			hasKey := device.pathology.hasKey
			device.pathology.mu.RUnlock()
			if hasKey {
				sendf("pathology_key=set")
			}
			if cfg.Persona != "" {
				sendf("pathology_persona=%s", cfg.Persona)
			}
			sendf("pathology_pad_budget=%d", cfg.PadBudget)
			if cfg.Strategy != "" && cfg.Strategy != "auto" {
				sendf("pathology_pad_strategy=%s", cfg.Strategy)
			}
			if cfg.IdlePersona != "" {
				sendf("pathology_idle_persona=%s", cfg.IdlePersona)
			}
			if cfg.StartCover > 0 {
				sendf("pathology_start_cover=%d", cfg.StartCover)
			}
			if cfg.StartGapMin != 0 || cfg.StartGapMax != 0 {
				if cfg.StartGapMin == cfg.StartGapMax {
					sendf("pathology_start_gap_ms=%d", cfg.StartGapMin)
				} else {
					sendf("pathology_start_gap_ms=%d-%d", cfg.StartGapMin, cfg.StartGapMax)
				}
			}
			if cfg.CoverEveryMs > 0 {
				sendf("pathology_cover_interval_ms=%d", cfg.CoverEveryMs)
			}
			if cfg.LowEntropy {
				sendf("pathology_low_entropy=true")
			}
			if prof := formatPathologyPadProfile(cfg.PadProfile); prof != "" {
				sendf("pathology_pad_profile=%s", prof)
			}
			if cfg.Frame != "" && cfg.Frame != pathologyFrameNone {
				sendf("pathology_frame=%s", cfg.Frame)
			}
			if cfg.FrameDCIDLen > 0 {
				sendf("pathology_frame_dcid_len=%d", cfg.FrameDCIDLen)
			}
			if cfg.StartDecoy != "" && cfg.StartDecoy != "none" {
				sendf("pathology_start_decoy=%s", cfg.StartDecoy)
			}
			if cfg.Cipher != "" && cfg.Cipher != pathologyCipherAEAD {
				sendf("pathology_cipher=%s", cfg.Cipher)
			}
			if cfg.Preset != "" && cfg.Preset != pathologyPresetCustom {
				sendf("pathology_preset=%s", cfg.Preset)
			}
			if cfg.RotateSec != pathologyDefaultRotateSec {
				sendf("pathology_rotate_sec=%d", cfg.RotateSec)
			}
			if cfg.Intensity != 0 && cfg.Intensity != pathologyDefaultIntensity {
				sendf("pathology_intensity=%d", cfg.Intensity)
			}
			if cfg.Mode != "" {
				sendf("pathology_mode=%s", cfg.Mode)
			}
			if cfg.Dialog != "" && cfg.Dialog != pathologyDialogAuto {
				sendf("pathology_dialog=%s", cfg.Dialog)
			}
			if cfg.Auto {
				sendf("pathology_auto=true")
			}
		}
		// lx:end pathology

		if count := device.junk.count.Load(); count != 0 {
			sendf("jc=%d", count)
		}

		if min := device.junk.min.Load(); min != 0 {
			sendf("jmin=%d", min)
		}

		if max := device.junk.max.Load(); max != 0 {
			sendf("jmax=%d", max)
		}

		if padding := device.paddings.init.Load(); padding != 0 {
			sendf("s1=%d", padding)
		}

		if padding := device.paddings.response.Load(); padding != 0 {
			sendf("s2=%d", padding)
		}

		if padding := device.paddings.cookie.Load(); padding != 0 {
			sendf("s3=%d", padding)
		}

		if padding := device.paddings.transport.Load(); padding != 0 {
			sendf("s4=%d", padding)
		}

		if header := device.headers.init.Load(); !header.IsZero() {
			sendf("h1=%s", header.ToString())
		}

		if header := device.headers.response.Load(); !header.IsZero() {
			sendf("h2=%s", header.ToString())
		}

		if header := device.headers.cookie.Load(); !header.IsZero() {
			sendf("h3=%s", header.ToString())
		}

		if header := device.headers.transport.Load(); !header.IsZero() {
			sendf("h4=%s", header.ToString())
		}

		for i, ipacket := range device.ipackets {
			if ipacket != nil {
				sendf("i%d=%s", i+1, ipacket.Spec)
			}
		}

		if !device.headerProtection.key.IsZero() {
			keyf("header_protection_key", (*[32]byte)(&device.headerProtection.key))
		}

		if addition := device.contentPaddingAddition.Load(); !addition.IsZero() {
			sendf("content_padding_addition=%s", addition.ToString())
		}

		if timing := device.timings.rekeyAfterTimeSec.Load(); !timing.IsZero() {
			sendf("rekey_after_time=%s", timing.ToString())
		}
		if timing := device.timings.rekeyTimeoutSec.Load(); !timing.IsZero() {
			sendf("rekey_timeout=%s", timing.ToString())
		}
		if timing := device.timings.rejectAfterTimeSec.Load(); !timing.IsZero() {
			sendf("reject_after_time=%s", timing.ToString())
		}
		if timing := device.timings.keepaliveTimeoutSec.Load(); !timing.IsZero() {
			sendf("keepalive_timeout=%s", timing.ToString())
		}
		if timing := device.timings.maxHandshakeAttemps.Load(); !timing.IsZero() {
			sendf("max_handshake_attempts=%s", timing.ToString())
		}
		boolf("random_trailers", device.randomTrailers.Load())
		boolf("disable_cookies", device.disableCookies.Load())

		if mbps := device.bandwidth.UpMbps(); mbps != 0 {
			sendf("up_mbps=%d", mbps)
		}
		if mbps := device.bandwidth.DownMbps(); mbps != 0 {
			sendf("down_mbps=%d", mbps)
		}

		for _, peer := range device.peers.keyMap {
			// Serialize peer state.
			peer.handshake.mutex.RLock()
			keyf("public_key", (*[32]byte)(&peer.handshake.remoteStatic))
			keyf("preshared_key", (*[32]byte)(&peer.handshake.presharedKey))
			peer.handshake.mutex.RUnlock()
			sendf("protocol_version=1")
			peer.endpoint.Lock()
			if peer.endpoint.val != nil {
				sendf("endpoint=%s", peer.endpoint.val.DstToString())
			}
			peer.endpoint.Unlock()

			nano := peer.lastHandshakeNano.Load()
			secs := nano / time.Second.Nanoseconds()
			nano %= time.Second.Nanoseconds()

			sendf("last_handshake_time_sec=%d", secs)
			sendf("last_handshake_time_nsec=%d", nano)
			sendf("tx_bytes=%d", peer.txBytes.Load())
			sendf("rx_bytes=%d", peer.rxBytes.Load())
			if keepalive := peer.persistentKeepaliveInterval.Load(); !keepalive.IsZero() {
				sendf("persistent_keepalive_interval=%s", keepalive.ToString())
			}
			if mbps := peer.bandwidth.UpMbps(); mbps != 0 {
				sendf("up_mbps=%d", mbps)
			}
			if mbps := peer.bandwidth.DownMbps(); mbps != 0 {
				sendf("down_mbps=%d", mbps)
			}

			device.allowedips.EntriesForPeer(peer, func(prefix netip.Prefix) bool {
				sendf("allowed_ip=%s", prefix.String())
				return true
			})
		}
	}()

	// send lines (does not require resource locks)
	if _, err := w.Write(buf.Bytes()); err != nil {
		return ipcErrorf(ipc.IpcErrorIO, "failed to write output: %w", err)
	}

	return nil
}

// IpcSetOperation implements the WireGuard configuration protocol "set" operation.
// See https://www.wireguard.com/xplatform/#configuration-protocol for details.
func (device *Device) IpcSetOperation(r io.Reader) (err error) {
	device.ipcMutex.Lock()
	defer device.ipcMutex.Unlock()

	defer func() {
		if err != nil {
			device.log.Errorf("%v", err)
		}
	}()

	ipcDev := new(ipcSetDevice)
	ipcDev.fromDevice(device)
	peer := new(ipcSetPeer)
	deviceConfig := true

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			// Blank line means terminate operation.
			err := ipcDev.mergeWithDevice(device)
			if err != nil {
				return ipcErrorf(ipc.IpcErrorInvalid, "failed to merge with device: %w", err)
			}
			peer.handlePostConfig()
			return nil
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return ipcErrorf(
				ipc.IpcErrorProtocol,
				"failed to parse line %q",
				line,
			)
		}

		if key == "public_key" {
			if deviceConfig {
				deviceConfig = false
			}
			peer.handlePostConfig()
			// Load/create the peer we are now configuring.
			err := device.handlePublicKeyLine(peer, value)
			if err != nil {
				return err
			}
			continue
		}

		var err error
		if deviceConfig {
			err = device.handleDeviceLine(ipcDev, key, value)
		} else {
			err = device.handlePeerLine(peer, key, value)
		}
		if err != nil {
			return err
		}
	}
	err = ipcDev.mergeWithDevice(device)
	if err != nil {
		return ipcErrorf(ipc.IpcErrorInvalid, "failed to merge with device: %w", err)
	}
	peer.handlePostConfig()

	if err := scanner.Err(); err != nil {
		return ipcErrorf(ipc.IpcErrorIO, "failed to read input: %w", err)
	}
	return nil
}

func (device *Device) handleDeviceLine(ipcDev *ipcSetDevice, key, value string) error {
	switch key {
	case "private_key":
		var sk NoisePrivateKey
		err := sk.FromMaybeZeroHex(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to set private_key: %w", err)
		}
		device.log.Verbosef("UAPI: Updating private key")
		device.SetPrivateKey(sk)

	case "listen_port":
		port, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse listen_port: %w", err)
		}

		// update port and rebind
		device.log.Verbosef("UAPI: Updating listen port")

		device.net.Lock()
		device.net.port = uint16(port)
		device.net.Unlock()

		if err := device.BindUpdate(); err != nil {
			return ipcErrorf(ipc.IpcErrorPortInUse, "failed to set listen_port: %w", err)
		}

	case "fwmark":
		mark, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "invalid fwmark: %w", err)
		}

		device.log.Verbosef("UAPI: Updating fwmark")
		if err := device.BindSetMark(uint32(mark)); err != nil {
			return ipcErrorf(ipc.IpcErrorPortInUse, "failed to update fwmark: %w", err)
		}

	case "replace_peers":
		if value != "true" {
			return ipcErrorf(
				ipc.IpcErrorInvalid,
				"failed to set replace_peers, invalid value: %v",
				value,
			)
		}
		device.log.Verbosef("UAPI: Removing all peers")
		device.RemoveAllPeers()

	// lx:begin pathology
	case "pathology":
		on, err := parsePathologyUAPI(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse pathology: %w", err)
		}
		ipcDev.pathologyPresent = true
		ipcDev.pathologyValue = on

	case "pathology_key":
		key, err := parsePathologyKeyUAPI(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse pathology_key: %w", err)
		}
		ipcDev.pathologyKey = key
		ipcDev.pathologyKeyPresent = true

	case "pathology_persona":
		persona, err := normalizePathologyPersona(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "%w", err)
		}
		ipcDev.pathologyPersona = persona
		ipcDev.pathologyPersonaPresent = true

	case "pathology_pad_budget":
		n, err := strconv.ParseUint(value, 10, 8)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse pathology_pad_budget: %w", err)
		}
		ipcDev.pathologyPadBudget = int(n)
		ipcDev.pathologyPadBudgetPresent = true

	case "pathology_pad_strategy":
		s, err := normalizePathologyStrategy(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "%w", err)
		}
		ipcDev.pathologyStrategy = s
		ipcDev.pathologyStrategyPresent = true

	case "pathology_idle_persona":
		persona, err := normalizePathologyPersona(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "%w", err)
		}
		ipcDev.pathologyIdlePersona = persona
		ipcDev.pathologyIdlePersonaPresent = true

	case "pathology_pad_profile":
		prof, err := parsePathologyPadProfile(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse pathology_pad_profile: %w", err)
		}
		ipcDev.pathologyPadProfile = prof
		ipcDev.pathologyPadProfilePresent = true

	case "pathology_start_cover":
		n, err := strconv.ParseUint(value, 10, 8)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse pathology_start_cover: %w", err)
		}
		ipcDev.pathologyStartCover = int(n)
		ipcDev.pathologyStartCoverPresent = true

	case "pathology_start_gap_ms":
		min, max, err := parsePathologyGapMs(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse pathology_start_gap_ms: %w", err)
		}
		ipcDev.pathologyStartGapMin = min
		ipcDev.pathologyStartGapMax = max
		ipcDev.pathologyStartGapPresent = true

	case "pathology_cover_interval_ms":
		n, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse pathology_cover_interval_ms: %w", err)
		}
		ipcDev.pathologyCoverEveryMs = int(n)
		ipcDev.pathologyCoverEveryPresent = true

	case "pathology_low_entropy":
		on, err := parsePathologyUAPI(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse pathology_low_entropy: %w", err)
		}
		ipcDev.pathologyLowEntropy = on
		ipcDev.pathologyLowEntropyPresent = true

	case "pathology_frame":
		f, err := normalizePathologyFrame(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "%w", err)
		}
		ipcDev.pathologyFrame = f
		ipcDev.pathologyFramePresent = true

	case "pathology_frame_dcid_len":
		n, err := strconv.ParseUint(value, 10, 8)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse pathology_frame_dcid_len: %w", err)
		}
		if n > 20 {
			return ipcErrorf(ipc.IpcErrorInvalid, "pathology_frame_dcid_len must be 0..20")
		}
		ipcDev.pathologyFrameDCIDLen = int(n)
		ipcDev.pathologyFrameDCIDPresent = true

	case "pathology_start_decoy":
		dcy, err := normalizePathologyStartDecoy(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "%w", err)
		}
		ipcDev.pathologyStartDecoy = dcy
		ipcDev.pathologyStartDecoyPresent = true

	case "pathology_cipher":
		ciph, err := normalizePathologyCipher(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "%w", err)
		}
		ipcDev.pathologyCipher = ciph
		ipcDev.pathologyCipherPresent = true

	case "pathology_preset":
		pre, err := normalizePathologyPreset(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "%w", err)
		}
		ipcDev.pathologyPreset = pre
		ipcDev.pathologyPresetPresent = true

	case "pathology_rotate_sec":
		n, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse pathology_rotate_sec: %w", err)
		}
		ipcDev.pathologyRotateSec = int(n)
		ipcDev.pathologyRotateSecPresent = true

	case "pathology_intensity":
		n, err := strconv.ParseUint(value, 10, 8)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse pathology_intensity: %w", err)
		}
		if n < 1 || n > 5 {
			return ipcErrorf(ipc.IpcErrorInvalid, "pathology_intensity must be 1..5")
		}
		ipcDev.pathologyIntensity = int(n)
		ipcDev.pathologyIntensityPresent = true

	case "pathology_mode":
		mode, err := normalizePathologyMode(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "%w", err)
		}
		ipcDev.pathologyMode = mode
		ipcDev.pathologyModePresent = true

	case "pathology_dialog":
		d, err := normalizePathologyDialog(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "%w", err)
		}
		ipcDev.pathologyDialog = d
		ipcDev.pathologyDialogPresent = true

	case "pathology_auto":
		on, err := parsePathologyUAPI(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse pathology_auto: %w", err)
		}
		ipcDev.pathologyAuto = on
		ipcDev.pathologyAutoPresent = true
	// lx:end pathology

	case "jc":
		if err := device.errIfPathologyBlocksAWG("jc"); err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "%w", err)
		}
		jc, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse jc: %w", err)
		}

		device.log.Verbosef("UAPI: Updating junk count")
		device.junk.count.Store(uint32(jc))

	case "jmin":
		if err := device.errIfPathologyBlocksAWG("jmin"); err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "%w", err)
		}
		jmin, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse jmin: %w", err)
		}

		device.log.Verbosef("UAPI: Updating junk min")
		device.junk.min.Store(uint32(jmin))

	case "jmax":
		if err := device.errIfPathologyBlocksAWG("jmax"); err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "%w", err)
		}
		jmax, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse jmax: %w", err)
		}

		device.log.Verbosef("UAPI: Updating junk max")
		device.junk.max.Store(uint32(jmax))

	case "s1":
		if err := device.errIfPathologyBlocksAWG("s1"); err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "%w", err)
		}
		padding, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse s1: %w", err)
		}
		ipcDev.paddings.init = uint32(padding)

	case "s2":
		if err := device.errIfPathologyBlocksAWG("s2"); err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "%w", err)
		}
		padding, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse s2: %w", err)
		}
		ipcDev.paddings.response = uint32(padding)

	case "s3":
		if err := device.errIfPathologyBlocksAWG("s3"); err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "%w", err)
		}
		padding, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse s3: %w", err)
		}
		ipcDev.paddings.cookie = uint32(padding)

	case "s4":
		if err := device.errIfPathologyBlocksAWG("s4"); err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "%w", err)
		}
		padding, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse s4: %w", err)
		}
		ipcDev.paddings.transport = uint32(padding)

	case "h1":
		var rang UintRange
		if err := rang.FromString(value); err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse H1: %w", err)
		}
		ipcDev.headers.init = rang

	case "h2":
		var rang UintRange
		if err := rang.FromString(value); err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse H2: %w", err)
		}
		ipcDev.headers.response = rang

	case "h3":
		var rang UintRange
		if err := rang.FromString(value); err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse H3: %w", err)
		}
		ipcDev.headers.cookie = rang

	case "h4":
		var rang UintRange
		if err := rang.FromString(value); err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse H4: %w", err)
		}
		ipcDev.headers.transport = rang

	case "i1":
		if err := device.errIfPathologyBlocksAWG("i1"); err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "%w", err)
		}
		chain, err := newObfChain(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse I1: %w", err)
		}
		device.ipackets[0] = chain

	case "i2":
		if err := device.errIfPathologyBlocksAWG("i2"); err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "%w", err)
		}
		chain, err := newObfChain(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse I2: %w", err)
		}
		device.ipackets[1] = chain

	case "i3":
		if err := device.errIfPathologyBlocksAWG("i3"); err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "%w", err)
		}
		chain, err := newObfChain(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse I3: %w", err)
		}
		device.ipackets[2] = chain

	case "i4":
		if err := device.errIfPathologyBlocksAWG("i4"); err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "%w", err)
		}
		chain, err := newObfChain(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse I4: %w", err)
		}
		device.ipackets[3] = chain

	case "i5":
		if err := device.errIfPathologyBlocksAWG("i5"); err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "%w", err)
		}
		chain, err := newObfChain(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse I5: %w", err)
		}
		device.ipackets[4] = chain

	case "header_protection_key":
		if err := device.errIfPathologyBlocksAWG("header_protection_key"); err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "%w", err)
		}
		var key HeaderCipherKey
		err := key.FromHex(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to set header_protection_key: %w", err)
		}
		ipcDev.headerProtectionKey = key

	case "content_padding_addition":
		if err := device.errIfPathologyBlocksAWG("content_padding_addition"); err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "%w", err)
		}
		var rang UintRange
		if err := rang.FromString(value); err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse content_padding_addition: %w", err)
		}

		device.log.Verbosef("UAPI: Updating content padding addition")
		device.contentPaddingAddition.Store(rang)

	case "rekey_after_time":
		var rang UintRange
		if err := rang.FromString(value); err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse rekey after time: %w", err)
		}
		device.log.Verbosef("UAPI: Updating rekey after time")
		device.timings.rekeyAfterTimeSec.Store(rang)

	case "rekey_timeout":
		var rang UintRange
		if err := rang.FromString(value); err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse rekey timeout: %w", err)
		}
		device.log.Verbosef("UAPI: Updating rekey timeout")
		device.timings.rekeyTimeoutSec.Store(rang)

	case "reject_after_time":
		var rang UintRange
		if err := rang.FromString(value); err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse reject after time: %w", err)
		}
		device.log.Verbosef("UAPI: Updating reject after time")
		device.timings.rejectAfterTimeSec.Store(rang)

	case "keepalive_timeout":
		var rang UintRange
		if err := rang.FromString(value); err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse keepalive timeout: %w", err)
		}
		device.log.Verbosef("UAPI: Updating keepalive timeout")
		device.timings.keepaliveTimeoutSec.Store(rang)

	case "max_handshake_attempts":
		var rang UintRange
		if err := rang.FromString(value); err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse max handshake attempts: %w", err)
		}
		device.log.Verbosef("UAPI: Updating max handshake attempts")
		device.timings.maxHandshakeAttemps.Store(rang)

	case "random_trailers":
		val, err := strconv.ParseBool(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse random trailers: %w", err)
		}
		device.log.Verbosef("UAPI: Updating random trailers")
		device.randomTrailers.Store(val)

	case "disable_cookies":
		val, err := strconv.ParseBool(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse disable cookies: %w", err)
		}
		device.log.Verbosef("UAPI: Updating disable cookies")
		device.disableCookies.Store(val)

	case "up_mbps":
		mbps, err := parseMbpsUAPI(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse up_mbps: %w", err)
		}
		device.log.Verbosef("UAPI: Updating device up_mbps")
		device.bandwidth.SetUpMbps(mbps)

	case "down_mbps":
		mbps, err := parseMbpsUAPI(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse down_mbps: %w", err)
		}
		device.log.Verbosef("UAPI: Updating device down_mbps")
		device.bandwidth.SetDownMbps(mbps)

	default:
		return ipcErrorf(ipc.IpcErrorInvalid, "invalid UAPI device key: %v", key)
	}

	return nil
}

// An ipcSetPeer is the current state of an IPC set operation on a peer.
type ipcSetPeer struct {
	*Peer        // Peer is the current peer being operated on
	dummy   bool // dummy reports whether this peer is a temporary, placeholder peer
	created bool // new reports whether this is a newly created peer
	pkaOn   bool // pkaOn reports whether the peer had the persistent keepalive turn on
}

func (peer *ipcSetPeer) handlePostConfig() {
	if peer.Peer == nil || peer.dummy {
		return
	}
	if peer.created {
		peer.endpoint.disableRoaming = peer.device.net.brokenRoaming && peer.endpoint.val != nil
	}
	if peer.device.isUp() {
		peer.Start()
		if peer.pkaOn {
			peer.SendKeepalive()
		}
		peer.SendStagedPackets()
	}
}

func (device *Device) handlePublicKeyLine(
	peer *ipcSetPeer,
	value string,
) error {
	// Load/create the peer we are configuring.
	var publicKey NoisePublicKey
	err := publicKey.FromHex(value)
	if err != nil {
		return ipcErrorf(ipc.IpcErrorInvalid, "failed to get peer by public key: %w", err)
	}

	// Ignore peer with the same public key as this device.
	device.staticIdentity.RLock()
	peer.dummy = device.staticIdentity.publicKey.Equals(publicKey)
	device.staticIdentity.RUnlock()

	if peer.dummy {
		peer.Peer = &Peer{}
	} else {
		peer.Peer = device.LookupPeer(publicKey)
	}

	peer.created = peer.Peer == nil
	if peer.created {
		peer.Peer, err = device.NewPeer(publicKey)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to create new peer: %w", err)
		}
		device.log.Verbosef("%v - UAPI: Created", peer.Peer)
	}
	return nil
}

func (device *Device) handlePeerLine(
	peer *ipcSetPeer,
	key, value string,
) error {
	switch key {
	case "update_only":
		// allow disabling of creation
		if value != "true" {
			return ipcErrorf(
				ipc.IpcErrorInvalid,
				"failed to set update only, invalid value: %v",
				value,
			)
		}
		if peer.created && !peer.dummy {
			device.RemovePeer(peer.handshake.remoteStatic)
			peer.Peer = &Peer{}
			peer.dummy = true
		}

	case "remove":
		// remove currently selected peer from device
		if value != "true" {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to set remove, invalid value: %v", value)
		}
		if !peer.dummy {
			device.log.Verbosef("%v - UAPI: Removing", peer.Peer)
			device.RemovePeer(peer.handshake.remoteStatic)
		}
		peer.Peer = &Peer{}
		peer.dummy = true

	case "preshared_key":
		device.log.Verbosef("%v - UAPI: Updating preshared key", peer.Peer)

		peer.handshake.mutex.Lock()
		err := peer.handshake.presharedKey.FromHex(value)
		peer.handshake.mutex.Unlock()

		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to set preshared key: %w", err)
		}

	case "endpoint":
		device.log.Verbosef("%v - UAPI: Updating endpoint", peer.Peer)
		endpoint, err := device.net.bind.ParseEndpoint(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to set endpoint %v: %w", value, err)
		}
		peer.endpoint.Lock()
		defer peer.endpoint.Unlock()
		peer.endpoint.val = endpoint

	case "persistent_keepalive_interval":
		device.log.Verbosef("%v - UAPI: Updating persistent keepalive interval", peer.Peer)

		var rang UintRange
		if err := rang.FromString(value); err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to set persistent keepalive interval: %w", err)
		}

		old := peer.persistentKeepaliveInterval.Swap(rang)

		// Send immediate keepalive if we're turning it on and before it wasn't on.
		peer.pkaOn = old.IsZero() && !rang.IsZero()

	case "up_mbps":
		mbps, err := parseMbpsUAPI(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse up_mbps: %w", err)
		}
		if !peer.dummy {
			device.log.Verbosef("%v - UAPI: Updating up_mbps", peer.Peer)
			peer.bandwidth.SetUpMbps(mbps)
		}

	case "down_mbps":
		mbps, err := parseMbpsUAPI(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse down_mbps: %w", err)
		}
		if !peer.dummy {
			device.log.Verbosef("%v - UAPI: Updating down_mbps", peer.Peer)
			peer.bandwidth.SetDownMbps(mbps)
		}

	case "replace_allowed_ips":
		device.log.Verbosef("%v - UAPI: Removing all allowedips", peer.Peer)
		if value != "true" {
			return ipcErrorf(
				ipc.IpcErrorInvalid,
				"failed to replace allowedips, invalid value: %v",
				value,
			)
		}
		if peer.dummy {
			return nil
		}
		device.allowedips.RemoveByPeer(peer.Peer)

	case "allowed_ip":
		add := true
		verb := "Adding"
		if len(value) > 0 && value[0] == '-' {
			add = false
			verb = "Removing"
			value = value[1:]
		}
		device.log.Verbosef("%v - UAPI: %s allowedip", peer.Peer, verb)
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to set allowed ip: %w", err)
		}
		if peer.dummy {
			return nil
		}
		if add {
			device.allowedips.Insert(prefix, peer.Peer)
		} else {
			device.allowedips.Remove(prefix, peer.Peer)
		}

	case "protocol_version":
		if value != "1" {
			return ipcErrorf(ipc.IpcErrorInvalid, "invalid protocol version: %v", value)
		}

	default:
		return ipcErrorf(ipc.IpcErrorInvalid, "invalid UAPI peer key: %v", key)
	}

	return nil
}

func (device *Device) IpcGet() (string, error) {
	buf := new(strings.Builder)
	if err := device.IpcGetOperation(buf); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func (device *Device) IpcSet(uapiConf string) error {
	return device.IpcSetOperation(strings.NewReader(uapiConf))
}

func (device *Device) IpcHandle(socket net.Conn) {
	defer socket.Close()

	buffered := func(s io.ReadWriter) *bufio.ReadWriter {
		reader := bufio.NewReader(s)
		writer := bufio.NewWriter(s)
		return bufio.NewReadWriter(reader, writer)
	}(socket)

	for {
		op, err := buffered.ReadString('\n')
		if err != nil {
			return
		}

		// handle operation
		switch op {
		case "set=1\n":
			err = device.IpcSetOperation(buffered.Reader)
		case "get=1\n":
			var nextByte byte
			nextByte, err = buffered.ReadByte()
			if err != nil {
				return
			}
			if nextByte != '\n' {
				err = ipcErrorf(
					ipc.IpcErrorInvalid,
					"trailing character in UAPI get: %q",
					nextByte,
				)
				break
			}
			err = device.IpcGetOperation(buffered.Writer)
		default:
			device.log.Errorf("invalid UAPI operation: %v", op)
			return
		}

		// write status
		var status *IPCError
		if err != nil && !errors.As(err, &status) {
			// shouldn't happen
			status = ipcErrorf(ipc.IpcErrorUnknown, "other UAPI error: %w", err)
		}
		if status != nil {
			device.log.Errorf("%v", status)
			fmt.Fprintf(buffered, "errno=%d\n\n", status.ErrorCode())
		} else {
			fmt.Fprintf(buffered, "errno=0\n\n")
		}
		buffered.Flush()
	}
}

type ipcSetDevice struct {
	headers struct {
		init      UintRange
		response  UintRange
		cookie    UintRange
		transport UintRange
	}
	paddings struct {
		init      uint32
		response  uint32
		cookie    uint32
		transport uint32
	}
	headerProtectionKey HeaderCipherKey
	// lx:begin pathology
	pathologyPresent             bool
	pathologyValue               bool
	pathologyKeyPresent          bool
	pathologyKey                 []byte
	pathologyPersonaPresent      bool
	pathologyPersona             string
	pathologyPadBudgetPresent    bool
	pathologyPadBudget           int
	pathologyStrategyPresent     bool
	pathologyStrategy            string
	pathologyIdlePersonaPresent  bool
	pathologyIdlePersona         string
	pathologyPadProfilePresent   bool
	pathologyPadProfile          []pathologyPadMode
	pathologyStartCoverPresent   bool
	pathologyStartCover          int
	pathologyStartGapPresent     bool
	pathologyStartGapMin         int
	pathologyStartGapMax         int
	pathologyCoverEveryPresent   bool
	pathologyCoverEveryMs        int
	pathologyLowEntropyPresent   bool
	pathologyLowEntropy          bool
	pathologyFramePresent        bool
	pathologyFrame               string
	pathologyFrameDCIDPresent    bool
	pathologyFrameDCIDLen        int
	pathologyStartDecoyPresent   bool
	pathologyStartDecoy          string
	pathologyCipherPresent       bool
	pathologyCipher              string
	pathologyPresetPresent       bool
	pathologyPreset              string
	pathologyRotateSecPresent    bool
	pathologyRotateSec           int
	pathologyIntensityPresent    bool
	pathologyIntensity           int
	pathologyModePresent         bool
	pathologyMode                string
	pathologyDialogPresent       bool
	pathologyDialog              string
	pathologyAutoPresent         bool
	pathologyAuto                bool
	// lx:end pathology
}

func (d *ipcSetDevice) fromDevice(device *Device) {
	device.headerProtection.RLock()
	defer device.headerProtection.RUnlock()

	d.headers.init = device.headers.init.Load()
	d.headers.response = device.headers.response.Load()
	d.headers.cookie = device.headers.cookie.Load()
	d.headers.transport = device.headers.transport.Load()

	d.paddings.init = device.paddings.init.Load()
	d.paddings.response = device.paddings.response.Load()
	d.paddings.cookie = device.paddings.cookie.Load()
	d.paddings.transport = device.paddings.transport.Load()

	d.headerProtectionKey = device.headerProtection.key
}

func (d *ipcSetDevice) mergeWithDevice(device *Device) error {
	device.headerProtection.Lock()
	// unlocked explicitly before pathology apply (not deferred) — see below

	headers := []UintRange{d.headers.init, d.headers.response, d.headers.cookie, d.headers.transport}
	for i := 0; i < len(headers); i++ {
		for j := i + 1; j < len(headers); j++ {
			left := headers[i]
			right := headers[j]

			if left.Overlap(right) {
				device.headerProtection.Unlock()
				return errors.New("headers must not overlap")
			}
		}
	}

	// lx:begin pathology
	wantPathology := device.pathologyEnabled()
	if d.pathologyPresent {
		wantPathology = d.pathologyValue
	}
	if wantPathology && d.pendingPaddingOrHP() {
		device.headerProtection.Unlock()
		return errors.New("pathology cannot be combined with AmneziaWG padding (s1–s4) or header_protection_key")
	}
	// lx:end pathology

	device.log.Verbosef("UAPI: Updating h1")
	device.headers.init.Store(d.headers.init)

	device.log.Verbosef("UAPI: Updating h2")
	device.headers.response.Store(d.headers.response)

	device.log.Verbosef("UAPI: Updating h3")
	device.headers.cookie.Store(d.headers.cookie)

	device.log.Verbosef("UAPI: Updating h4")
	device.headers.transport.Store(d.headers.transport)

	if !d.headerProtectionKey.IsZero() {
		paddings := []uint32{d.paddings.init, d.paddings.response, d.paddings.cookie, d.paddings.transport}
		for i, padding := range paddings {
			if padding < HeaderCipherNonceSize {
				device.headerProtection.Unlock()
				return fmt.Errorf("S%d must be at least %d when header_protection_key is set", i+1, HeaderCipherNonceSize)
			}
		}
	}

	device.log.Verbosef("UAPI: Updating s1 padding")
	device.paddings.init.Store(d.paddings.init)

	device.log.Verbosef("UAPI: Updating s2 padding")
	device.paddings.response.Store(d.paddings.response)

	device.log.Verbosef("UAPI: Updating s3 padding")
	device.paddings.cookie.Store(d.paddings.cookie)

	device.log.Verbosef("UAPI: Updating s4 padding")
	device.paddings.transport.Store(d.paddings.transport)

	device.log.Verbosef("UAPI: Updating header protection key")
	device.headerProtection.key = d.headerProtectionKey
	device.headerProtection.Unlock()

	// lx:begin pathology
	// Applied after releasing headerProtection (awgKnobsConflictWithPathology may RLock it).
	if d.pathologyPresent {
		if d.pathologyValue {
			if err := device.awgKnobsConflictWithPathology(); err != nil {
				return err
			}
			cfg := defaultPathologyRuntimeConfig()
			if d.pathologyPersonaPresent {
				cfg.Persona = d.pathologyPersona
			}
			if d.pathologyPadBudgetPresent {
				cfg.PadBudget = d.pathologyPadBudget
			}
			if d.pathologyStrategyPresent {
				cfg.Strategy = d.pathologyStrategy
			}
			if d.pathologyIdlePersonaPresent {
				cfg.IdlePersona = d.pathologyIdlePersona
			}
			if d.pathologyPadProfilePresent {
				cfg.PadProfile = d.pathologyPadProfile
			}
			if d.pathologyStartCoverPresent {
				cfg.StartCover = d.pathologyStartCover
			}
			if d.pathologyStartGapPresent {
				cfg.StartGapMin = d.pathologyStartGapMin
				cfg.StartGapMax = d.pathologyStartGapMax
			}
			if d.pathologyCoverEveryPresent {
				cfg.CoverEveryMs = d.pathologyCoverEveryMs
			}
			if d.pathologyLowEntropyPresent {
				cfg.LowEntropy = d.pathologyLowEntropy
			}
			if d.pathologyFramePresent {
				cfg.Frame = d.pathologyFrame
			}
			if d.pathologyFrameDCIDPresent {
				cfg.FrameDCIDLen = d.pathologyFrameDCIDLen
			}
			if d.pathologyStartDecoyPresent {
				cfg.StartDecoy = d.pathologyStartDecoy
			}
			if d.pathologyCipherPresent {
				cfg.Cipher = d.pathologyCipher
			}
			if d.pathologyPresetPresent {
				cfg.Preset = d.pathologyPreset
			}
			if d.pathologyRotateSecPresent {
				cfg.RotateSec = d.pathologyRotateSec
			}
			if d.pathologyIntensityPresent {
				cfg.Intensity = d.pathologyIntensity
			}
			if d.pathologyModePresent {
				cfg.Mode = d.pathologyMode
			}
			if d.pathologyDialogPresent {
				cfg.Dialog = d.pathologyDialog
			}
			if d.pathologyAutoPresent {
				cfg.Auto = d.pathologyAuto
			}
			var key []byte
			if d.pathologyKeyPresent {
				key = d.pathologyKey
			}
			m, err := newPathologyMorpherFromConfig(key, cfg)
			if err != nil {
				return err
			}
			if env, ok := m.(*envelopePathology); ok {
				cfg = env.cfg // resolved preset/cipher/frame
			}
			device.setPathologyMorpherConfig(m, cfg, len(key) > 0)
			if len(key) > 0 {
				device.log.Verbosef("UAPI: pathology enabled (envelope persona=%s cipher=%s frame=%s dialog=%s auto=%v intensity=%d rotate_sec=%d)", cfg.Persona, cfg.Cipher, cfg.Frame, cfg.Dialog, cfg.Auto, cfg.Intensity, cfg.RotateSec)
			} else {
				device.log.Verbosef("UAPI: pathology enabled (identity morpher)")
			}
		} else {
			device.setPathologyMorpherConfig(nil, pathologyRuntimeConfig{}, false)
			device.log.Verbosef("UAPI: pathology disabled")
		}
	}
	// lx:end pathology

	return nil
}
