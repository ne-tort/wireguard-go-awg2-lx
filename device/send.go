/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/sagernet/wireguard-go/conn"
	"github.com/sagernet/wireguard-go/tun"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

/* Outbound flow
 *
 * 1. TUN queue
 * 2. Routing (sequential)
 * 3. Nonce assignment (sequential)
 * 4. Encryption (parallel)
 * 5. Transmission (sequential)
 *
 * The functions in this file occur (roughly) in the order in
 * which the packets are processed.
 *
 * Locking, Producers and Consumers
 *
 * The order of packets (per peer) must be maintained,
 * but encryption of packets happen out-of-order:
 *
 * The sequential consumers will attempt to take the lock,
 * workers release lock when they have completed work (encryption) on the packet.
 *
 * If the element is inserted into the "encryption queue",
 * the content is preceded by enough "junk" to contain the transport header
 * (to allow the construction of transport messages in-place)
 */

type QueueOutboundElement struct {
	buffer []byte // sing-allocated buffer holding the packet data
	// packet is always a slice of "buffer". The starting offset in buffer
	// is either:
	//  a) MessageEncapsulatingTransportSize+padding+MessageTransportHeaderSize (plaintext)
	//  b) 0 / padding-inclusive (post-encryption)
	packet  []byte
	nonce   uint64   // nonce for encryption
	keypair *Keypair // keypair for encryption
	peer    *Peer    // related peer
	padding uint32   // AmneziaWG S4 leading padding (HP nonce source)
}

type QueueOutboundElementsContainer struct {
	sync.Mutex
	elems []*QueueOutboundElement
}

func (device *Device) NewOutboundElement() *QueueOutboundElement {
	elem := device.GetOutboundElement()
	elem.buffer = device.GetOutboundBuffer(MaxMessageSize)
	elem.nonce = 0
	elem.padding = device.paddings.transport.Load()
	// keypair and peer were cleared (if necessary) by clearPointers.
	return elem
}

// clearPointers clears elem fields that contain pointers.
// This makes the garbage collector's life easier and
// avoids accidentally keeping other objects around unnecessarily.
// It also reduces the possible collateral damage from use-after-free bugs.
func (elem *QueueOutboundElement) clearPointers() {
	elem.buffer = nil
	elem.packet = nil
	elem.keypair = nil
	elem.peer = nil
}

/* Queues a keepalive if no packets are queued for peer
 */
func (peer *Peer) SendKeepalive() {
	if len(peer.queue.staged) == 0 && peer.isRunning.Load() {
		elem := peer.device.NewOutboundElement()
		elemsContainer := peer.device.GetOutboundElementsContainer()
		elemsContainer.elems = append(elemsContainer.elems, elem)
		select {
		case peer.queue.staged <- elemsContainer:
			peer.queuedOutboundPackets.Add(1)
			peer.device.log.Verbosef("%v - Sending keepalive packet", peer)
		default:
			peer.device.PutOutboundBuffer(elem.buffer)
			peer.device.PutOutboundElement(elem)
			peer.device.PutOutboundElementsContainer(elemsContainer)
		}
	}
	peer.SendStagedPackets()
	// lx:begin pathology
	// T-IDLE: optional mid-session cover datagram after keepalive cadence.
	if cover := peer.device.pathologyMaybeIdleCover(); cover != nil {
		peer.endpoint.Lock()
		endpoint := peer.endpoint.val
		peer.endpoint.Unlock()
		if endpoint != nil {
			peer.device.net.RLock()
			_ = peer.device.net.bind.Send([][]byte{cover}, endpoint, MessageEncapsulatingTransportSize)
			peer.device.net.RUnlock()
		}
	}
	// lx:end pathology
}

func (peer *Peer) SendHandshakeInitiation(isRetry bool) error {
	if !isRetry {
		peer.timers.handshakeAttempts.Store(0)
		peer.timers.maxHandshakeAttempts.Store(peer.device.maxHandshakeAttemps())
	}

	peer.noteSessionHandshakeStarted()

	timeout := peer.device.rekeyMinTimeout()

	peer.handshake.mutex.RLock()
	if time.Since(peer.handshake.lastSentHandshake) < timeout {
		peer.handshake.mutex.RUnlock()
		return nil
	}
	peer.handshake.mutex.RUnlock()

	peer.handshake.mutex.Lock()
	if time.Since(peer.handshake.lastSentHandshake) < timeout {
		peer.handshake.mutex.Unlock()
		return nil
	}
	peer.handshake.lastSentHandshake = time.Now()
	peer.handshake.mutex.Unlock()

	peer.device.log.Verbosef("%v - Sending handshake initiation", peer)

	// Resolve candidates before pathology dialog / packet build so the race set
	// is fixed for this attempt (upstream c6c8a83).
	candidates := peer.resolveEndpoints()

	// lx:begin pathology
	// T-DIALOG / T-START: polite legend exchange (or legacy covers) before initiation.
	// Sleep happens *outside* net.RLock so bind is not held idle.
	peer.endpoint.Lock()
	endpoint := peer.endpoint.val
	peer.endpoint.Unlock()
	if endpoint != nil {
		peer.device.pathologyRunStartDialog(func(pkt []byte) {
			peer.device.net.RLock()
			_ = peer.device.net.bind.Send([][]byte{pkt}, endpoint, MessageEncapsulatingTransportSize)
			peer.device.net.RUnlock()
		})
	}
	// lx:end pathology

	msg, err := peer.device.CreateMessageInitiation(peer)
	if err != nil {
		peer.device.log.Errorf("%v - Failed to create initiation message: %v", peer, err)
		return err
	}

	var sendBuffer [][]byte

	for _, ipacket := range peer.device.ipackets {
		if ipacket != nil {
			buf := make([]byte, ipacket.ObfuscatedLen(0))
			ipacket.Obfuscate(buf, nil)
			sendBuffer = append(sendBuffer, buf)
		}
	}

	sendBuffer = append(sendBuffer, peer.device.JunkPackets()...)

	padding := peer.device.paddings.init.Load()
	buf := make([]byte, int(padding)+MessageInitiationSize)

	crypt := buf[:padding]
	rand.Read(crypt)

	writer := bytes.NewBuffer(buf[padding:padding])
	binary.Write(writer, binary.LittleEndian, msg)
	packet := writer.Bytes()
	peer.cookieGenerator.AddMacs(packet)

	peer.timersAnyAuthenticatedPacketTraversal()
	peer.timersAnyAuthenticatedPacketSent()

	cip, err := peer.device.HeaderProtectionCipher(crypt[:HeaderCipherNonceSize])
	if err != nil {
		return err
	}
	if cip != nil {
		cip.XORKeyStream(packet, packet)
	}

	sendBuffer = append(sendBuffer, buf)

	// Race the full AWG preamble+initiation to every candidate when a resolver
	// is set; otherwise keep the single-path SendBuffers (pathology seal inside).
	if len(candidates) > 0 {
		err = peer.sendHandshakeBuffers(sendBuffer, candidates)
	} else {
		err = peer.SendBuffers(sendBuffer)
	}
	if err != nil {
		peer.device.log.Errorf("%v - Failed to send handshake initiation: %v", peer, err)
	}
	peer.timersHandshakeInitiated()

	return err
}

func (peer *Peer) SendHandshakeResponse() error {
	peer.handshake.mutex.Lock()
	peer.handshake.lastSentHandshake = time.Now()
	peer.handshake.mutex.Unlock()

	peer.device.log.Verbosef("%v - Sending handshake response", peer)

	response, err := peer.device.CreateMessageResponse(peer)
	if err != nil {
		peer.device.log.Errorf("%v - Failed to create response message: %v", peer, err)
		return err
	}

	padding := peer.device.paddings.response.Load()
	buf := make([]byte, int(padding)+MessageResponseSize)

	crypt := buf[:padding]
	rand.Read(crypt)

	writer := bytes.NewBuffer(buf[padding:padding])
	binary.Write(writer, binary.LittleEndian, response)
	packet := writer.Bytes()
	peer.cookieGenerator.AddMacs(packet)

	err = peer.BeginSymmetricSession()
	if err != nil {
		peer.device.log.Errorf("%v - Failed to derive keypair: %v", peer, err)
		return err
	}

	peer.noteSessionState(PeerSessionEstablished)
	peer.timersSessionDerived()
	peer.timersAnyAuthenticatedPacketTraversal()
	peer.timersAnyAuthenticatedPacketSent()

	cip, err := peer.device.HeaderProtectionCipher(crypt[:HeaderCipherNonceSize])
	if err != nil {
		return err
	}
	if cip != nil {
		cip.XORKeyStream(packet, packet)
	}

	// TODO: allocation could be avoided
	err = peer.SendBuffers([][]byte{buf})
	if err != nil {
		peer.device.log.Errorf("%v - Failed to send handshake response: %v", peer, err)
	}
	return err
}

func (device *Device) SendHandshakeCookie(initiatingElem *QueueHandshakeElement) error {
	device.log.Verbosef("Sending cookie response for denied handshake message for %v", initiatingElem.endpoint.DstToString())

	sender := binary.LittleEndian.Uint32(initiatingElem.packet[4:8])
	msgType := device.headers.cookie.Load().PickOne()

	reply, err := device.cookieChecker.CreateReply(
		initiatingElem.packet,
		sender,
		initiatingElem.endpoint.DstToBytes(),
		msgType,
	)
	if err != nil {
		device.log.Errorf("Failed to create cookie reply: %v", err)
		return err
	}

	padding := device.paddings.cookie.Load()
	buf := make([]byte, int(padding)+MessageCookieReplySize)

	crypt := buf[:padding]
	rand.Read(crypt)

	writer := bytes.NewBuffer(buf[padding:padding])
	binary.Write(writer, binary.LittleEndian, reply)
	packet := writer.Bytes()

	cip, err := device.HeaderProtectionCipher(crypt[:HeaderCipherNonceSize])
	if err != nil {
		return err
	}
	if cip != nil {
		cip.XORKeyStream(packet, packet)
	}

	// TODO: allocation could be avoided
	device.net.bind.Send([][]byte{buf}, initiatingElem.endpoint, 0)
	return nil
}

func (peer *Peer) keepKeyFreshSending() {
	keypair := peer.keypairs.Current()
	if keypair == nil {
		return
	}
	nonce := keypair.sendNonce.Load()
	if nonce > RekeyAfterMessages || (keypair.isInitiator && time.Since(keypair.created) > peer.device.keyRefreshTimeoutSending()) {
		peer.SendHandshakeInitiation(false)
	}
}

func (device *Device) RoutineReadFromTUN() {
	defer func() {
		device.log.Verbosef("Routine: TUN reader - stopped")
		device.state.stopping.Done()
		device.queue.encryption.wg.Done()
	}()

	device.log.Verbosef("Routine: TUN reader - started")

	var (
		batchSize   = device.BatchSize()
		readErr     error
		elems       = make([]*QueueOutboundElement, batchSize)
		bufs        = make([][]byte, batchSize)
		elemsByPeer = make(map[*Peer]*QueueOutboundElementsContainer, batchSize)
		count       = 0
		sizes       = make([]int, batchSize)
	)

	for i := range elems {
		elems[i] = device.NewOutboundElement()
		bufs[i] = elems[i].buffer[:]
	}

	defer func() {
		for _, elem := range elems {
			if elem != nil {
				device.PutOutboundBuffer(elem.buffer)
				device.PutOutboundElement(elem)
			}
		}
	}()

	for {
		padding := device.paddings.transport.Load()
		offset := MessageEncapsulatingTransportSize + MessageTransportHeaderSize + int(padding)

		// read packets
		count, readErr = device.tun.device.Read(bufs, sizes, offset)
		for i := 0; i < count; i++ {
			if sizes[i] < 1 {
				continue
			}

			elem := elems[i]
			elem.packet = bufs[i][offset : offset+sizes[i]]
			elem.padding = padding

			// lookup peer
			var peer *Peer
			switch elem.packet[0] >> 4 {
			case 4:
				if len(elem.packet) < ipv4.HeaderLen {
					continue
				}
				src := netip.AddrFrom4([4]byte(elem.packet[IPv4offsetSrc : IPv4offsetSrc+net.IPv4len]))
				dst := netip.AddrFrom4([4]byte(elem.packet[IPv4offsetDst : IPv4offsetDst+net.IPv4len]))
				peer = device.allowedips.LookupFromPacket(src, dst, elem.packet)

			case 6:
				if len(elem.packet) < ipv6.HeaderLen {
					continue
				}
				src := netip.AddrFrom16([16]byte(elem.packet[IPv6offsetSrc : IPv6offsetSrc+net.IPv6len]))
				dst := netip.AddrFrom16([16]byte(elem.packet[IPv6offsetDst : IPv6offsetDst+net.IPv6len]))
				peer = device.allowedips.LookupFromPacket(src, dst, elem.packet)

			default:
				device.log.Verbosef("Received packet with unknown IP version")
			}

			if peer == nil {
				continue
			}
			elemsForPeer, ok := elemsByPeer[peer]
			if !ok {
				elemsForPeer = device.GetOutboundElementsContainer()
				elemsByPeer[peer] = elemsForPeer
			}
			elemsForPeer.elems = append(elemsForPeer.elems, elem)
			elems[i] = device.NewOutboundElement()
			bufs[i] = elems[i].buffer[:]
		}

		for peer, elemsForPeer := range elemsByPeer {
			if peer.isRunning.Load() {
				peer.StagePackets(elemsForPeer)
				peer.SendStagedPackets()
			} else {
				for _, elem := range elemsForPeer.elems {
					device.PutOutboundBuffer(elem.buffer)
					device.PutOutboundElement(elem)
				}
				device.PutOutboundElementsContainer(elemsForPeer)
			}
			delete(elemsByPeer, peer)
		}

		if readErr != nil {
			if errors.Is(readErr, tun.ErrTooManySegments) {
				// TODO: record stat for this
				// This will happen if MSS is surprisingly small (< 576)
				// coincident with reasonably high throughput.
				device.log.Verbosef("Dropped some packets from multi-segment read: %v", readErr)
				continue
			}
			if !device.isClosed() {
				if !errors.Is(readErr, os.ErrClosed) {
					device.log.Errorf("Failed to read packet from TUN device: %v", readErr)
				}
				go device.Close()
			}
			return
		}
	}
}

// maxQueuedInputPackets bounds the staged+outbound backlog of a peer fed via
// InputPacket/InputPackets. Injected packets beyond it are dropped before they
// are copied into pooled message buffers, like a full qdisc: injection has no
// flow control, and the queues are bounded in containers (up to a full batch
// each), so without this cap a flood is buffered instead of dropped.
const maxQueuedInputPackets = 2048

func (device *Device) inputPacketPeer(destination []byte, packetSlices [][]byte) *Peer {
	var src, dst netip.Addr
	switch len(destination) {
	case net.IPv4len:
		dst = netip.AddrFrom4([4]byte(destination))
		var srcBytes [net.IPv4len]byte
		if !gatherPacketBytes(packetSlices, IPv4offsetSrc, srcBytes[:]) {
			return nil
		}
		src = netip.AddrFrom4(srcBytes)
	case net.IPv6len:
		dst = netip.AddrFrom16([16]byte(destination))
		var srcBytes [net.IPv6len]byte
		if !gatherPacketBytes(packetSlices, IPv6offsetSrc, srcBytes[:]) {
			return nil
		}
		src = netip.AddrFrom16(srcBytes)
	default:
		return nil
	}
	var ipPkt []byte
	if len(packetSlices) == 1 {
		ipPkt = packetSlices[0]
	}
	return device.allowedips.LookupFromPacket(src, dst, ipPkt)
}

func gatherPacketBytes(packetSlices [][]byte, offset int, destination []byte) bool {
	for _, packetSlice := range packetSlices {
		if offset >= len(packetSlice) {
			offset -= len(packetSlice)
			continue
		}
		n := copy(destination, packetSlice[offset:])
		destination = destination[n:]
		offset = 0
		if len(destination) == 0 {
			return true
		}
	}
	return false
}

func (device *Device) outboundContentPadBudget() int {
	if addition := device.contentPaddingAddition.Load(); !addition.IsZero() {
		return int(addition.Hi())
	}
	return PaddingMultiple
}

func (device *Device) InputPacket(destination []byte, packetSlices [][]byte) {
	peer := device.inputPacketPeer(destination, packetSlices)
	if peer == nil {
		return
	}
	if peer.queuedOutboundPackets.Load() >= maxQueuedInputPackets {
		return
	}
	var totalLength int
	for _, packetSlice := range packetSlices {
		totalLength += len(packetSlice)
	}
	padding := device.paddings.transport.Load()
	allocLength := MessageEncapsulatingTransportSize + int(padding) + MessageTransportHeaderSize + totalLength + device.outboundContentPadBudget() + chacha20poly1305.Overhead
	if allocLength > MaxMessageSize {
		return
	}
	elem := device.GetOutboundElement()
	elem.buffer = device.GetOutboundBuffer(allocLength)
	elem.nonce = 0
	elem.padding = padding
	packet := elem.buffer[MessageEncapsulatingTransportSize+int(padding)+MessageTransportHeaderSize:]
	var n int
	for _, packetSlice := range packetSlices {
		n += copy(packet[n:], packetSlice)
	}
	elem.packet = packet[:n]
	elemsForPeer := device.GetOutboundElementsContainer()
	if peer.isRunning.Load() {
		elemsForPeer.elems = append(elemsForPeer.elems, elem)
		peer.StagePackets(elemsForPeer)
		peer.SendStagedPackets()
	} else {
		device.PutOutboundBuffer(elem.buffer)
		device.PutOutboundElement(elem)
		device.PutOutboundElementsContainer(elemsForPeer)
	}
}

type InputPacketRef struct {
	Destination  []byte
	PacketSlices [][]byte
}

func (device *Device) InputPackets(packets []*InputPacketRef) []*InputPacketRef {
	var unmatched []*InputPacketRef
	elemsByPeer := make(map[*Peer][]*QueueOutboundElementsContainer, len(packets))
	for _, packetRef := range packets {
		peer := device.inputPacketPeer(packetRef.Destination, packetRef.PacketSlices)
		if peer == nil {
			unmatched = append(unmatched, packetRef)
			continue
		}
		if peer.queuedOutboundPackets.Load() >= maxQueuedInputPackets {
			continue
		}
		var totalLength int
		for _, packetSlice := range packetRef.PacketSlices {
			totalLength += len(packetSlice)
		}
		padding := device.paddings.transport.Load()
		allocLength := MessageEncapsulatingTransportSize + int(padding) + MessageTransportHeaderSize + totalLength + device.outboundContentPadBudget() + chacha20poly1305.Overhead
		if allocLength > MaxMessageSize {
			continue
		}
		elem := device.GetOutboundElement()
		elem.buffer = device.GetOutboundBuffer(allocLength)
		elem.nonce = 0
		elem.padding = padding
		packet := elem.buffer[MessageEncapsulatingTransportSize+int(padding)+MessageTransportHeaderSize:]
		var n int
		for _, packetSlice := range packetRef.PacketSlices {
			n += copy(packet[n:], packetSlice)
		}
		elem.packet = packet[:n]
		containers := elemsByPeer[peer]
		if len(containers) == 0 || len(containers[len(containers)-1].elems) >= conn.IdealBatchSize {
			containers = append(containers, device.GetOutboundElementsContainer())
			elemsByPeer[peer] = containers
		}
		elemsForPeer := containers[len(containers)-1]
		elemsForPeer.elems = append(elemsForPeer.elems, elem)
	}
	for peer, containers := range elemsByPeer {
		if peer.isRunning.Load() {
			for _, elemsForPeer := range containers {
				peer.StagePackets(elemsForPeer)
			}
			peer.SendStagedPackets()
		} else {
			for _, elemsForPeer := range containers {
				for _, elem := range elemsForPeer.elems {
					device.PutOutboundBuffer(elem.buffer)
					device.PutOutboundElement(elem)
				}
				device.PutOutboundElementsContainer(elemsForPeer)
			}
		}
	}
	return unmatched
}

func (peer *Peer) StagePackets(elems *QueueOutboundElementsContainer) {
	peer.queuedOutboundPackets.Add(int32(len(elems.elems)))
	for {
		select {
		case peer.queue.staged <- elems:
			return
		default:
		}
		select {
		case tooOld := <-peer.queue.staged:
			peer.queuedOutboundPackets.Add(-int32(len(tooOld.elems)))
			for _, elem := range tooOld.elems {
				peer.device.PutOutboundBuffer(elem.buffer)
				peer.device.PutOutboundElement(elem)
			}
			peer.device.PutOutboundElementsContainer(tooOld)
		default:
		}
	}
}

func (peer *Peer) SendStagedPackets() {
top:
	if len(peer.queue.staged) == 0 || !peer.device.isUp() {
		return
	}

	keypair := peer.keypairs.Current()
	if keypair == nil || keypair.sendNonce.Load() >= RejectAfterMessages || time.Since(keypair.created) >= peer.device.keychainExpireTime() {
		peer.SendHandshakeInitiation(false)
		return
	}

	for {
		var elemsContainerOOO *QueueOutboundElementsContainer
		select {
		case elemsContainer := <-peer.queue.staged:
			i := 0
			for _, elem := range elemsContainer.elems {
				elem.peer = peer
				elem.nonce = keypair.sendNonce.Add(1) - 1
				if elem.nonce >= RejectAfterMessages {
					keypair.sendNonce.Store(RejectAfterMessages)
					if elemsContainerOOO == nil {
						elemsContainerOOO = peer.device.GetOutboundElementsContainer()
					}
					elemsContainerOOO.elems = append(elemsContainerOOO.elems, elem)
					continue
				} else {
					elemsContainer.elems[i] = elem
					i++
				}

				elem.keypair = keypair
			}
			elemsContainer.Lock()
			elemsContainer.elems = elemsContainer.elems[:i]

			if elemsContainerOOO != nil {
				// Already counted at their original staging; StagePackets will count them again.
				peer.queuedOutboundPackets.Add(-int32(len(elemsContainerOOO.elems)))
				peer.StagePackets(elemsContainerOOO) // XXX: Out of order, but we can't front-load go chans
			}

			if len(elemsContainer.elems) == 0 {
				peer.device.PutOutboundElementsContainer(elemsContainer)
				goto top
			}

			// add to parallel and sequential queue
			if peer.isRunning.Load() {
				peer.queue.outbound.c <- elemsContainer
				peer.device.queue.encryption.c <- elemsContainer
			} else {
				peer.queuedOutboundPackets.Add(-int32(len(elemsContainer.elems)))
				for _, elem := range elemsContainer.elems {
					peer.device.PutOutboundBuffer(elem.buffer)
					peer.device.PutOutboundElement(elem)
				}
				peer.device.PutOutboundElementsContainer(elemsContainer)
			}

			if elemsContainerOOO != nil {
				goto top
			}
		default:
			return
		}
	}
}

func (peer *Peer) FlushStagedPackets() {
	for {
		select {
		case elemsContainer := <-peer.queue.staged:
			peer.queuedOutboundPackets.Add(-int32(len(elemsContainer.elems)))
			for _, elem := range elemsContainer.elems {
				peer.device.PutOutboundBuffer(elem.buffer)
				peer.device.PutOutboundElement(elem)
			}
			peer.device.PutOutboundElementsContainer(elemsContainer)
		default:
			return
		}
	}
}

func calculatePaddingSize(packetSize, mtu int) int {
	lastUnit := packetSize
	if mtu == 0 {
		return ((lastUnit + PaddingMultiple - 1) & ^(PaddingMultiple - 1)) - lastUnit
	}
	if lastUnit > mtu {
		lastUnit %= mtu
	}
	paddedSize := ((lastUnit + PaddingMultiple - 1) & ^(PaddingMultiple - 1))
	if paddedSize > mtu {
		paddedSize = mtu
	}
	return paddedSize - lastUnit
}

func (device *Device) randomPaddingAddition(packetSize, mtu int) int {
	addition := device.contentPaddingAddition.Load()

	if addition.IsZero() {
		return -1
	}

	add := int(addition.PickOne())
	if mtu != 0 {
		if packetSize > mtu {
			packetSize %= mtu
		}

		space := mtu - packetSize
		if add > space {
			add = space
		}
	}
	return add
}

/* Encrypts the elements in the queue
 * and marks them for sequential consumption (by releasing the mutex)
 *
 * Obs. One instance per core
 */
func (device *Device) RoutineEncryption(id int) {
	var nonce [chacha20poly1305.NonceSize]byte

	defer device.log.Verbosef("Routine: encryption worker %d - stopped", id)
	device.log.Verbosef("Routine: encryption worker %d - started", id)

	for elemsContainer := range device.queue.encryption.c {
		for _, elem := range elemsContainer.elems {
			// fill crypto padding
			crypt := elem.buffer[:elem.padding]
			rand.Read(crypt)

			// populate header fields
			header := elem.buffer[elem.padding : elem.padding+MessageTransportHeaderSize]

			fieldType := header[0:4]
			fieldReceiver := header[4:8]
			fieldNonce := header[8:16]

			binary.LittleEndian.PutUint32(fieldType, device.headers.transport.Load().PickOne())
			binary.LittleEndian.PutUint32(fieldReceiver, elem.keypair.remoteIndex)
			binary.LittleEndian.PutUint64(fieldNonce, elem.nonce)

			packetSize := len(elem.packet)
			mtu := int(device.tun.mtu.Load())

			paddingSize := device.randomPaddingAddition(packetSize, mtu)
			if paddingSize < 0 {
				// pad content to multiple of 16
				paddingSize = calculatePaddingSize(packetSize, mtu)
			}

			// append trailing zeroes
			if paddingSize > 0 {
				elem.packet = append(elem.packet, make([]byte, paddingSize)...)
			}

			// encrypt content and release to consumer

			binary.LittleEndian.PutUint64(nonce[4:], elem.nonce)
			elem.packet = elem.keypair.send.Seal(
				elem.buffer[:elem.padding+MessageTransportHeaderSize],
				nonce[:],
				elem.packet,
				nil,
			)

			cip, err := device.HeaderProtectionCipher(crypt[:HeaderCipherNonceSize])
			if err != nil {
				device.log.Errorf("Routing: header obfuscation failed - packet dropped")
				elem.packet = nil
				continue
			}
			if cip != nil {
				cip.XORKeyStream(header, header)
			}
		}
		elemsContainer.Unlock()
	}
}

func (peer *Peer) RoutineSequentialSender(maxBatchSize int) {
	device := peer.device
	defer func() {
		defer device.log.Verbosef("%v - Routine: sequential sender - stopped", peer)
		peer.stopping.Done()
	}()
	device.log.Verbosef("%v - Routine: sequential sender - started", peer)

	bufs := make([][]byte, 0, maxBatchSize)

	for elemsContainer := range peer.queue.outbound.c {
		bufs = bufs[:0]
		if elemsContainer == nil {
			return
		}
		if !peer.isRunning.Load() {
			// peer has been stopped; return re-usable elems to the shared pool.
			// This is an optimization only. It is possible for the peer to be stopped
			// immediately after this check, in which case, elem will get processed.
			// The timers and SendBuffers code are resilient to a few stragglers.
			// TODO: rework peer shutdown order to ensure
			// that we never accidentally keep timers alive longer than necessary.
			elemsContainer.Lock()
			peer.queuedOutboundPackets.Add(-int32(len(elemsContainer.elems)))
			for _, elem := range elemsContainer.elems {
				device.PutOutboundBuffer(elem.buffer)
				device.PutOutboundElement(elem)
			}
			device.PutOutboundElementsContainer(elemsContainer)
			continue
		}
		dataSent := false
		dataBytes := 0
		elemsContainer.Lock()
		for _, elem := range elemsContainer.elems {
			if elem.packet == nil {
				continue
			}
			// lx: awg — amneziawg-go v3.0.1 compares against MessageKeepaliveSize
			// only (ignores S4), so with S4>0 every keepalive looks like data.
			// Count the leading S-padding so timers match real keepalive size.
			if len(elem.packet) != int(elem.padding)+MessageKeepaliveSize {
				dataSent = true
				dataBytes += len(elem.packet)
			}
			bufs = append(bufs, elem.packet)
		}

		peer.timersAnyAuthenticatedPacketTraversal()
		peer.timersAnyAuthenticatedPacketSent()

		// lx: bandwidth — shape data only (keepalive/handshake excluded).
		if dataBytes > 0 {
			peer.shapeUpload(dataBytes)
		}

		err := peer.SendBuffers(bufs)
		if dataSent {
			peer.timersDataSent()
		}
		peer.queuedOutboundPackets.Add(-int32(len(elemsContainer.elems)))
		for _, elem := range elemsContainer.elems {
			device.PutOutboundBuffer(elem.buffer)
			device.PutOutboundElement(elem)
		}
		device.PutOutboundElementsContainer(elemsContainer)
		if err != nil {
			var errGSO conn.ErrUDPGSODisabled
			if errors.As(err, &errGSO) {
				device.log.Verbosef(err.Error())
				err = errGSO.RetryErr
			}
		}
		if err != nil {
			device.log.Errorf("%v - Failed to send data packets: %v", peer, err)
			continue
		}

		peer.keepKeyFreshSending()
	}
}
