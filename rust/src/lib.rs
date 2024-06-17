#![no_std]

use core::ptr::addr_of_mut;
use core::{
    cmp::min,
    ffi,
    mem::size_of,
    ops::Div,
    ptr::{null_mut, slice_from_raw_parts_mut},
    sync::atomic::{AtomicPtr, AtomicU32, Ordering},
};

use base64::Engine;
use smoltcp::{
    iface::{SocketSet, SocketStorage},
    phy::{DeviceCapabilities, RxToken, TxToken},
    socket::udp::{self, UdpMetadata},
    storage::PacketBuffer,
    time::Instant,
};

pub fn start_wg(
    a: *mut uk_alloc,
    peer_device_idx: ffi::c_uint,
    internal_device_idx: ffi::c_uint,
    static_private: *const ffi::c_char,
    peer_static_public: *const ffi::c_char,
) -> ffi::c_int {
    let static_private: boringtun::x25519::StaticSecret = unsafe {
        let mut slice = [0u8; 32];
        assert_eq!(
            32,
            base64::prelude::BASE64_STANDARD
                .decode_slice_unchecked(
                    ffi::CStr::from_ptr(static_private).to_str().unwrap(),
                    &mut slice,
                )
                .unwrap()
        );
        slice
    }
    .into();
    let peer_static_public: boringtun::x25519::PublicKey = unsafe {
        let mut slice = [0u8; 32];
        assert_eq!(
            32,
            base64::prelude::BASE64_STANDARD
                .decode_slice_unchecked(
                    ffi::CStr::from_ptr(peer_static_public).to_str().unwrap(),
                    &mut slice,
                )
                .unwrap()
        );
        slice
    }
    .into();

    match boringtun::noise::Tunn::new(
        static_private,
        peer_static_public,
        None,
        None,
        0, // TODO: Is this relevant?
        None,
    ) {
        Ok(tunn) => {
            return run_tunnel(
                a,
                tunn,
                peer_device_idx.into(),
                internal_device_idx.into(),
                Some(smoltcp::wire::Ipv4Address([196, 168, 0, 1])),
                None,
                Some(smoltcp::wire::Ipv4Cidr::new(
                    smoltcp::wire::Ipv4Address([192, 168, 1, 0]),
                    24,
                )),
                None,
            )
            .into();
        }
        Err(_e) => {
            return -1;
        }
    }
}

#[repr(C)]
struct uk_netdev;

#[repr(C)]
pub struct uk_alloc;

#[repr(C)]
#[derive(Default)]
struct uk_netdev_info {
    max_rx_queues: u16,
    max_tx_queues: u16,
    in_queue_pairs: ffi::c_int, /*< If true, allocate queues in pairs. */
    max_mtu: u16,               /*< Maximum supported MTU size. */
    nb_encap_tx: u16,           /*< Number of bytes required as headroom for tx. */
    nb_encap_rx: u16,           /*< Number of bytes required as headroom for rx. */
    ioalign: u16,               /*< Alignment in bytes for packet data buffers */
    features: ffi::c_uint,      /*< bitmap of the features supported */
}

#[repr(C)]
struct uk_netdev_conf {
    nb_rx_queues: u16,
    nb_tx_queues: u16,
}

#[repr(C)]
#[derive(Default)]
struct uk_netdev_queue_info {
    nb_max: u16,                    /*< Max allowed number of descriptors. */
    nb_min: u16,                    /*< Min allowed number of descriptors. */
    nb_align: u16,                  /*< Number of descriptors should be aligned. */
    nb_is_power_of_two: ffi::c_int, /*< Number of descriptors should be a power of two. */
}

#[repr(C)]
struct uk_sched {
    // TOOD
}

#[repr(C)]
struct uk_netdev_rxqueue_conf {
    callback: extern "C" fn(dev: *mut uk_netdev, queue_id: u16, argp: *mut ffi::c_void) -> (), /*< Event callback function. */
    callback_cookie: *mut ffi::c_void, /*< Argument pointer for callback. */

    a: *mut uk_alloc, /*< Allocator for descriptors. */
    alloc_rxpkts: extern "C" fn(argp: *mut ffi::c_void, pkts: *mut uk_netbuf, count: u16) -> u16, /*< Allocator for rx netbufs */
    alloc_rxpkts_argp: *mut ffi::c_void, /*< Argument for alloc_rxpkts */

    // Depending on config:
    s: *mut uk_sched, /*< Scheduler for dispatcher. */
}

/*
 * A structure used to configure an Unikraft network device TX queue.
 */
#[repr(C)]
struct uk_netdev_txqueue_conf {
    a: *mut uk_alloc, /* Allocator for descriptors. */
}

// arch-specific type.
// Use https://github.com/unikraft/unikraft/blob/staging/include/uk/refcount.h for accesssing!
#[repr(C)]
struct __atomic {
    counter: u32,
}

#[repr(C)]
struct uk_netbuf {
    next: *mut uk_netbuf,
    prev: *mut uk_netbuf,

    flags: u8, /*< Flags for this netbuf */

    data: *mut ffi::c_void, /*< Payload start, is part of buf. */
    len: u16,               /*< Payload length (should be <= buflen). */
    refcount: __atomic,     /*< Reference counter */

    priv_: *mut ffi::c_void, /*< Reference to user-provided private data */

    buf: *mut ffi::c_void, /*< Start address of contiguous buffer. */
    buflen: usize,         /*< Length of buffer. */

    csum_start: u16, /*< Used if UK_NETBUF_F_PARTIAL_CSUM is set;
                      * Offset within this netbuf's data segment to
                      * begin checksumming
                      */
    csum_offset: u16, /*< Used if UK_NETBUF_F_PARTIAL_CSUM is set;
                       * Number of bytes starting from `csum_start`
                       * pointing to the checksum field
                       */

    header_len: u16, /*< Used if UK_NETBUF_F_GSO_* is set;
                      * Number of bytes to copy into each split
                      * packet as a header
                      */
    gso_size: u16, /*< Used if UK_NETBUF_F_GSO_* is set;
                    * Maximum size of each packet beyond the header
                    */

    dtor: extern "C" fn(*mut uk_netbuf) -> ffi::c_void, /*< Destructor callback */
    _a: *mut uk_alloc,                                  /*< @internal Allocator for free'ing */
    _b: *mut ffi::c_void,                               /*< @internal Base address for free'ing */
}

extern "C" {
    fn uk_malloc(a: *mut uk_alloc, size: usize) -> *mut ffi::c_void;
    fn uk_free(a: *mut uk_alloc, ptr: *mut ffi::c_void) -> ffi::c_void;
    fn uk_realloc(a: *mut uk_alloc, ptr: *mut ffi::c_void, size: usize) -> ffi::c_void;

    fn uk_netdev_get(id: ffi::c_uint) -> *mut uk_netdev;
    fn uk_netdev_probe(dev: *mut uk_netdev) -> ffi::c_int;
    fn uk_netdev_info_get(dev: *mut uk_netdev, info: *mut uk_netdev_info) -> ffi::c_void;
    fn uk_netdev_configure(dev: *mut uk_netdev, conf: *const uk_netdev_conf) -> ffi::c_int;
    fn uk_netdev_rxq_info_get(
        dev: *mut uk_netdev,
        queue_id: u16,
        queue_info: *mut uk_netdev_queue_info,
    ) -> ffi::c_int;
    fn uk_netdev_txq_info_get(
        dev: *mut uk_netdev,
        queue_id: u16,
        queue_info: *mut uk_netdev_queue_info,
    ) -> ffi::c_int;
    fn uk_netdev_rxq_configure(
        dev: *mut uk_netdev,
        queue_id: u16,
        conf: *const uk_netdev_rxqueue_conf,
    ) -> ffi::c_int;
    fn uk_netdev_txq_configure(
        dev: *mut uk_netdev,
        queue_id: u16,
        conf: *const uk_netdev_txqueue_conf,
    ) -> ffi::c_int;
    fn uk_netbuf_init_indir(
        m: *mut uk_netbuf,
        buf: *mut ffi::c_void,
        buflen: usize,
        headroom: u16,
        priv_: *mut ffi::c_void,
        dtor: extern "C" fn(*mut uk_netbuf) -> (),
    );
    fn uk_refcount_acquire(ref_: *mut __atomic) -> ffi::c_void;
    fn uk_refcount_release(ref_: *mut __atomic) -> ffi::c_void;
    fn uk_netdev_rx_one(dev: *mut uk_netdev, queue_id: u16, pkt: *mut *mut uk_netbuf)
        -> ffi::c_int;
    fn uk_netdev_tx_one(dev: *mut uk_netdev, queue_id: u16, pkt: *mut uk_netbuf) -> ffi::c_int;
    fn uk_netdev_start(dev: *mut uk_netdev) -> ffi::c_int;
    fn uk_netbuf_free(ref_: *mut uk_netbuf) -> ffi::c_void;
    fn ukplat_wall_clock() -> u64; // nsec
}

#[repr(packed)]
struct NetbufState {
    alloc: *mut uk_alloc,
    first: Option<*mut uk_netbuf>,
    next_queue: Option<*mut uk_netbuf>,
}

extern "C" fn netbuf_dtor(buf: *mut uk_netbuf) -> () {
    unsafe {
        let priv_: *mut NetbufState = (*buf).priv_.cast();
        match (*priv_).first {
            Some(first) => {
                uk_netbuf_free(first);
            }
            None => {
                uk_free(
                    (*priv_).alloc,
                    (*buf).buf.byte_sub(RX_NETBUF_PAGE_HEAD_OFFSET),
                );
            }
        }
    }
}

// I believe while larger packets can be put into smoltcp, it claims no support for jumbo packets!
/// !!!!!!!
// Adjust very carefully - we allocate this for every single netbuf!
/// !!!!!!!
const MAX_MTU: usize = 1500;
const PAGE_SIZE: usize = 16384;
// TODO: Colocate NetbufState for netbufs across pages! (For now page size above is modified.)
const RX_NETBUF_SIZE: usize = MAX_MTU.next_power_of_two();
const RX_NETBUF_PER_PAGE_FLOOR: usize = {
    let mut left = PAGE_SIZE;
    let mut c: usize = 0;
    loop {
        if left > (size_of::<NetbufState>() + RX_NETBUF_SIZE) {
            c += 1;
            left -= size_of::<NetbufState>() + RX_NETBUF_SIZE;
        } else {
            break c;
        }
    }
};
const RX_NETBUF_PAGE_HEAD_OFFSET: usize = RX_NETBUF_PER_PAGE_FLOOR * size_of::<NetbufState>();

extern "C" fn alloc_rxpkts(argp: *mut ffi::c_void, mut netbufs: *mut uk_netbuf, count: u16) -> u16 {
    unsafe {
        let mut alloced = 0;
        let state: *mut uk_alloc = argp.cast();
        while count > alloced {
            let data = uk_malloc(state, PAGE_SIZE);
            if data.is_null() {
                return alloced;
            }
            let priv_states: *mut NetbufState = data.cast();
            let data = data.byte_add(RX_NETBUF_PAGE_HEAD_OFFSET);
            let mut first = Some(netbufs);
            for idx in 0..RX_NETBUF_PER_PAGE_FLOOR {
                let priv_state = priv_states.add(idx);
                *priv_state = NetbufState {
                    alloc: state,
                    first,
                    next_queue: None,
                };
                uk_netbuf_init_indir(
                    netbufs.cast(),
                    data,
                    RX_NETBUF_SIZE,
                    0,
                    priv_state.cast(),
                    netbuf_dtor,
                );

                match first {
                    Some(first) => {
                        uk_refcount_acquire(addr_of_mut!((*first).refcount));
                    }
                    None => first = Some(netbufs),
                }

                netbufs = netbufs.add(1);
                alloced += 1;

                if count <= alloced {
                    break;
                }
            }
        }
        return alloced;
    }
}

const UK_NETDEV_STATUS_SUCCESS: u32 = 0x1;
const UK_NETDEV_STATUS_MORE: u32 = 0x2;
const UK_NETDEV_STATUS_UNDERRUN: u32 = 0x4;

extern "C" fn on_recv(dev: *mut uk_netdev, queue_id: u16, argp: *mut ffi::c_void) -> () {
    let device: *mut UnikraftNetDevDevice = argp.cast();
    unsafe {
        loop {
            let mut pkt: *mut uk_netbuf = null_mut();
            let res = uk_netdev_rx_one(dev, queue_id, addr_of_mut!(pkt));
            if res < 0 {
                panic!("uk_netdev_rx_one < 0");
            }
            let res: u32 = res.try_into().unwrap();
            if (res & UK_NETDEV_STATUS_SUCCESS) != 0 {
                let _ = (*device).rx_queue_head.fetch_update(
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                    |mut head| {
                        let tail = loop {
                            // TODO(multi-queue): We assume only one queue here!
                            // next_queue is only written to by one thread at a time
                            match (*(*head).priv_.cast::<NetbufState>()).next_queue {
                                Some(new_head) => head = new_head,
                                None => break head,
                            }
                        };
                        (*(*tail).priv_.cast::<NetbufState>()).next_queue = Some(pkt);
                        Some(pkt)
                    },
                );
            }
            if (res & UK_NETDEV_STATUS_UNDERRUN) != 0 {
                // TODO: Handle OOM here!
                // This isn't a huge problem TBH.
            }
            if (res & UK_NETDEV_STATUS_MORE) != 0 {
                continue;
            }
            break;
        }
    }
}

fn alloc_udp_socket(a: *mut uk_alloc) -> Result<udp::Socket<'static>, i32> {
    unsafe {
        let rx_metadata_storage = {
            let p: *mut u8 = uk_malloc(a, PAGE_SIZE).cast();
            if p.is_null() {
                return Err(-12);
            }
            slice_from_raw_parts_mut(p, PAGE_SIZE).as_mut().unwrap()
        };
        let rx_payload_storage = {
            let p: *mut smoltcp::storage::PacketMetadata<UdpMetadata> =
                uk_malloc(a, PAGE_SIZE).cast();
            if p.is_null() {
                return Err(-13);
            }
            slice_from_raw_parts_mut(
                p,
                PAGE_SIZE.div(size_of::<smoltcp::storage::PacketMetadata<UdpMetadata>>()),
            )
            .as_mut()
            .unwrap()
        };
        let tx_metadata_storage = {
            let p: *mut u8 = uk_malloc(a, PAGE_SIZE).cast();
            if p.is_null() {
                return Err(-14);
            }
            slice_from_raw_parts_mut(p, PAGE_SIZE).as_mut().unwrap()
        };
        let tx_payload_storage = {
            let p: *mut smoltcp::storage::PacketMetadata<UdpMetadata> =
                uk_malloc(a, PAGE_SIZE).cast();
            if p.is_null() {
                return Err(-15);
            }
            slice_from_raw_parts_mut(
                p,
                PAGE_SIZE.div(size_of::<smoltcp::storage::PacketMetadata<UdpMetadata>>()),
            )
            .as_mut()
            .unwrap()
        };

        let rx_buffer = PacketBuffer::new(rx_payload_storage, rx_metadata_storage);
        let tx_buffer = PacketBuffer::new(tx_payload_storage, tx_metadata_storage);
        return Ok(udp::Socket::new(rx_buffer, tx_buffer));
    }
}

fn get_now() -> Instant {
    Instant::from_micros_const((unsafe { ukplat_wall_clock() } * 1000).try_into().unwrap())
}

fn run_tunnel(
    a: *mut uk_alloc,
    tunn: boringtun::noise::Tunn,
    peer_device_idx: u32,
    internal_device_idx: u32,
    gateway4: Option<smoltcp::wire::Ipv4Address>,
    gateway6: Option<smoltcp::wire::Ipv6Address>,
    listen4: Option<smoltcp::wire::Ipv4Cidr>,
    listen6: Option<smoltcp::wire::Ipv6Cidr>,
) -> i32 {
    unsafe {
        let peer_netdev = uk_netdev_get(peer_device_idx);
        let internal_netdev = uk_netdev_get(internal_device_idx);

        if peer_netdev.is_null() {
            return -1;
        }

        if internal_netdev.is_null() {
            return -2;
        }

        if uk_netdev_probe(peer_netdev) < 0 {
            return -3;
        }

        if uk_netdev_probe(internal_netdev) < 0 {
            return -4;
        }

        let mut peer_netdev_info = uk_netdev_info::default();
        let mut internal_netdev_info = uk_netdev_info::default();

        uk_netdev_info_get(peer_netdev, addr_of_mut!(peer_netdev_info));
        uk_netdev_info_get(internal_netdev, addr_of_mut!(internal_netdev_info));

        let peer_mtu = min(MAX_MTU, peer_netdev_info.max_mtu.into());
        let internal_mtu = min(MAX_MTU, internal_netdev_info.max_mtu.into());

        if uk_netdev_configure(
            peer_netdev,
            &uk_netdev_conf {
                nb_rx_queues: 1,
                nb_tx_queues: 1,
            },
        ) < 0
        {
            return -5;
        }

        if uk_netdev_configure(
            internal_netdev,
            &uk_netdev_conf {
                nb_rx_queues: 1,
                nb_tx_queues: 1,
            },
        ) < 0
        {
            return -6;
        }

        let mut peer_rxq_info = uk_netdev_queue_info::default();
        if uk_netdev_rxq_info_get(peer_netdev, 0, addr_of_mut!(peer_rxq_info)) < 0 {
            return -7;
        }

        let mut internal_rxq_info = uk_netdev_queue_info::default();
        if (uk_netdev_rxq_info_get(internal_netdev, 0, addr_of_mut!(internal_rxq_info)) < 0) {
            return -8;
        }

        let mut peer_txq_info = uk_netdev_queue_info::default();
        if (uk_netdev_txq_info_get(peer_netdev, 0, addr_of_mut!(peer_txq_info)) < 0) {
            return -9;
        }

        let mut internal_txq_info = uk_netdev_queue_info::default();
        if (uk_netdev_rxq_info_get(internal_netdev, 0, addr_of_mut!(internal_txq_info)) < 0) {
            return -10;
        }

        let mut peer_device = UnikraftNetDevDevice {
            mtu: peer_mtu.try_into().unwrap(),
            device: peer_netdev,
            rx_queue_head: AtomicPtr::new(null_mut()),
            allocator: a,
            tx_blocking: AtomicU32::new(0),
        };

        let mut internal_device = UnikraftNetDevDevice {
            mtu: internal_mtu.try_into().unwrap(),
            device: internal_netdev,
            rx_queue_head: AtomicPtr::new(null_mut()),
            allocator: a,
            tx_blocking: AtomicU32::new(0),
        };

        if uk_netdev_rxq_configure(
            peer_netdev,
            0,
            &uk_netdev_rxqueue_conf {
                a,
                alloc_rxpkts: alloc_rxpkts,
                alloc_rxpkts_argp: a.cast(),
                s: null_mut(),
                callback: on_recv,
                callback_cookie: addr_of_mut!(peer_device).cast(),
            },
        ) < 0
        {
            return -11;
        }

        if uk_netdev_rxq_configure(
            internal_netdev,
            0,
            &uk_netdev_rxqueue_conf {
                a,
                alloc_rxpkts: alloc_rxpkts,
                alloc_rxpkts_argp: a.cast(),
                s: null_mut(),
                callback: on_recv,
                callback_cookie: addr_of_mut!(internal_device).cast(),
            },
        ) < 0
        {
            return -16;
        }

        if uk_netdev_txq_configure(peer_netdev, 0, &uk_netdev_txqueue_conf { a }) < 0 {
            return -17;
        }

        if uk_netdev_txq_configure(internal_netdev, 0, &uk_netdev_txqueue_conf { a }) < 0 {
            return -18;
        }

        if uk_netdev_start(peer_netdev) < 0 {
            return -19;
        }

        if uk_netdev_start(internal_netdev) < 0 {
            return -20;
        }

        let now = get_now();
        let mut internal_if = smoltcp::iface::Interface::new(
            smoltcp::iface::Config::new(smoltcp::wire::HardwareAddress::Ethernet(
                smoltcp::wire::EthernetAddress([1, 2, 3, 4, 5, 6]),
            )),
            &mut internal_device,
            now,
        );

        let mut peer_if = smoltcp::iface::Interface::new(
            smoltcp::iface::Config::new(smoltcp::wire::HardwareAddress::Ethernet(
                smoltcp::wire::EthernetAddress([1, 2, 3, 4, 5, 6]),
            )),
            &mut peer_device,
            now,
        );

        // TODO: Routing
        if let Some(gateway4) = gateway4 {
            internal_if
                .routes_mut()
                .add_default_ipv4_route(gateway4)
                .unwrap();
        }
        if let Some(gateway6) = gateway6 {
            internal_if
                .routes_mut()
                .add_default_ipv6_route(gateway6)
                .unwrap();
        }
        if let Some(listen4) = listen4 {
            peer_if.update_ip_addrs(|e| {
                e.push(smoltcp::wire::IpCidr::Ipv4(listen4));
            });
        }
        if let Some(listen6) = listen6 {
            peer_if.update_ip_addrs(|e| {
                e.push(smoltcp::wire::IpCidr::Ipv6(listen6));
            });
        }

        let mut internal_socket = match alloc_udp_socket(a) {
            Ok(s) => s,
            Err(i) => return i,
        };
        let mut peer_socket = match alloc_udp_socket(a) {
            Ok(s) => s,
            Err(i) => return i,
        };

        let mut _internal_sockets = [SocketStorage::EMPTY];
        let mut internal_sockets = SocketSet::new(_internal_sockets.as_mut());
        let mut _peer_sockets = [SocketStorage::EMPTY];
        let mut peer_sockets = SocketSet::new(_peer_sockets.as_mut());

        let internal_handle = internal_sockets.add(internal_socket);
        let peer_handle = peer_sockets.add(peer_socket);

        // Loop, first spin uk_netdev, then each interface (with associated sockets)
        loop {
            // TODO: spin uk_netdev

            let now = get_now();
            internal_if.poll(now, &mut internal_device, &mut internal_sockets);
            peer_if.poll(now, &mut peer_device, &mut peer_sockets);

            let peer_socket: &mut udp::Socket = peer_sockets.get_mut(peer_handle);
            let internal_socket: &mut udp::Socket = internal_sockets.get_mut(internal_handle);

            if !peer_socket.is_open() {
                peer_socket.bind(1234).unwrap();
            }

            if peer_socket.is_open() {
                match peer_socket.recv() {
                    Ok((slice, metadata)) => internal_socket.send_slice(slice, metadata).unwrap(),
                    Err(_) => (),
                }
            }
        }
    }
}

struct UnikraftNetDevDevice {
    mtu: u16,
    device: *mut uk_netdev,
    rx_queue_head: core::sync::atomic::AtomicPtr<uk_netbuf>,
    tx_blocking: AtomicU32,
    allocator: *mut uk_alloc,
}

impl smoltcp::phy::Device for UnikraftNetDevDevice {
    type RxToken<'a> = UnikraftNetDevDeviceRxToken;

    type TxToken<'a> = UnikraftNetDevDeviceTxToken<'a>;

    fn receive<'a>(
        &'a mut self,
        _timestamp: smoltcp::time::Instant,
    ) -> Option<(Self::RxToken<'a>, Self::TxToken<'a>)> {
        unsafe {
            let netbuf = self
                .rx_queue_head
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |buf| {
                    if buf.is_null() {
                        return None;
                    }
                    Some(
                        (*(*buf).priv_.cast::<NetbufState>())
                            .next_queue
                            .unwrap_or_else(|| null_mut()),
                    )
                })
                .unwrap();

            if netbuf.is_null() {
                return None;
            }

            return Some((
                UnikraftNetDevDeviceRxToken { netbuf },
                UnikraftNetDevDeviceTxToken {
                    device: self.device,
                    queue: 0,
                    netbuf,
                    tx_blocking: &self.tx_blocking,
                },
            ));
        }
    }

    fn transmit<'a>(&'a mut self, _timestamp: smoltcp::time::Instant) -> Option<Self::TxToken<'a>> {
        if self.tx_blocking.load(Ordering::SeqCst) > 0 {
            return None;
        }

        unsafe {
            let og_data = uk_malloc(
                self.allocator,
                RX_NETBUF_SIZE + size_of::<*mut ffi::c_void>() * 2 + size_of::<uk_netbuf>(),
            );
            let netbuf = og_data.cast();
            let data = og_data.add(size_of::<uk_netbuf>());
            let priv_state: *mut *mut ffi::c_void = data.cast();
            *priv_state = self.allocator.cast();
            *(priv_state.add(1)) = og_data;
            let data = data.add(size_of::<*mut ffi::c_void>() * 2);
            extern "C" fn dtor(netbuf: *mut uk_netbuf) -> () {
                unsafe {
                    let priv_state: *mut *mut ffi::c_void = (*netbuf).priv_.cast();
                    uk_free(priv_state.cast(), priv_state.add(1).cast());
                }
            }

            uk_netbuf_init_indir(netbuf, data, RX_NETBUF_SIZE, 0, priv_state.cast(), dtor);

            Some(UnikraftNetDevDeviceTxToken {
                device: self.device,
                queue: 0,
                netbuf,
                tx_blocking: &self.tx_blocking,
            })
        }
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = self.mtu.into();
        caps.max_burst_size = None;
        caps.medium = smoltcp::phy::Medium::Ethernet;
        caps
    }
}

struct UnikraftNetDevDeviceRxToken {
    netbuf: *mut uk_netbuf,
}
struct UnikraftNetDevDeviceTxToken<'a> {
    device: *mut uk_netdev,
    queue: u16,
    netbuf: *mut uk_netbuf,
    tx_blocking: &'a AtomicU32,
}

impl RxToken for UnikraftNetDevDeviceRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        unsafe {
            // TODO: handle chains
            assert!((*self.netbuf).next.is_null());
            let real_data: &mut [u8] =
                slice_from_raw_parts_mut((*self.netbuf).data.cast(), (*self.netbuf).len.into())
                    .as_mut()
                    .unwrap();

            let result = f(real_data);

            uk_netbuf_free(self.netbuf);

            return result;
        }
    }
}

impl<'b> TxToken for UnikraftNetDevDeviceTxToken<'b> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        unsafe {
            // TODO: handle chains
            assert!((*self.netbuf).next.is_null());
            let left_over = (*self.netbuf).buflen - len;

            let side = left_over.div(2);
            (*self.netbuf).data = (*self.netbuf).buf.add(side);
            (*self.netbuf).len = len.try_into().unwrap();

            let real_data: &mut [u8] =
                slice_from_raw_parts_mut((*self.netbuf).data.cast(), (*self.netbuf).len.into())
                    .as_mut()
                    .unwrap();

            let result = f(real_data);

            let mut blocking = false;
            loop {
                let status = uk_netdev_tx_one(self.device, self.queue, self.netbuf);

                if status < 0 {
                    panic!("Driver Error!");
                }
                let status: u32 = status.try_into().unwrap();

                if (status & UK_NETDEV_STATUS_SUCCESS) != 0 {
                    break;
                }
                if !blocking {
                    blocking = true;
                    self.tx_blocking.fetch_add(1, Ordering::SeqCst);
                }
            }
            if blocking {
                self.tx_blocking.fetch_sub(1, Ordering::SeqCst);
            }

            uk_netbuf_free(self.netbuf);

            return result;
        }
    }
}
