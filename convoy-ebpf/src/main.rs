#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::XskMap,
    programs::XdpContext,
};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{Ipv4Hdr, IpProto},
    tcp::TcpHdr,
};

#[map]
static XSKS_MAP: XskMap = XskMap::with_max_entries(64, 0);

const SSH_PORT: u16 = 22;

#[xdp]
pub fn xsk_def_prog(ctx: XdpContext) -> u32 {
    match unsafe { try_xsk_def_prog(ctx) } {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = core::mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

unsafe fn try_xsk_def_prog(ctx: XdpContext) -> Result<u32, u32> {
    let eth: *const EthHdr = ptr_at(&ctx, 0).map_err(|_| xdp_action::XDP_PASS)?;
    if (*eth).ether_type == EtherType::Ipv4.into() {
        let eth_len = core::mem::size_of::<EthHdr>();
        let ip: *const Ipv4Hdr = ptr_at(&ctx, eth_len).map_err(|_| xdp_action::XDP_PASS)?;
        if (*ip).proto == IpProto::Tcp.into() {
            let ip_len = ((*ip).ihl() as usize) * 4;
            let tcp: *const TcpHdr = ptr_at(&ctx, eth_len + ip_len).map_err(|_| xdp_action::XDP_PASS)?;
            let dest_port = u16::from_be_bytes((*tcp).dest);
            let src_port = u16::from_be_bytes((*tcp).source);
            if dest_port == SSH_PORT || src_port == SSH_PORT {
                return Ok(xdp_action::XDP_PASS);
            }
        }
    }
    let queue_id = (*ctx.ctx).rx_queue_index;
    let flags = xdp_action::XDP_PASS as u64;

    match XSKS_MAP.redirect(queue_id, flags) {
        Ok(action) => Ok(action as u32),
        Err(_) => Ok(xdp_action::XDP_PASS),
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
