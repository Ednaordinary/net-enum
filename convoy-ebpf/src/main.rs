#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{Array, XskMap},
    programs::XdpContext,
    bpf_printk,
};
use aya_log_ebpf::info; 
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{Ipv4Hdr, IpProto},
    tcp::TcpHdr,
};

#[map]
static XSKS_MAP: XskMap = XskMap::with_max_entries(64, 0);

#[map]
static CAPTURE_PORTS_BITMAP: Array<u8> = Array::with_max_entries(65536, 0);

#[xdp]
pub fn xsk_def_prog(ctx: XdpContext) -> u32 {
    unsafe{
    }
    match unsafe { try_xsk_def_prog(&ctx) } {
        Ok(ret) => ret,
        Err(err) => {
            info!(&ctx, "XDP ABRT");
            xdp_action::XDP_ABORTED
        },
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

unsafe fn try_xsk_def_prog(ctx: &XdpContext) -> Result<u32, u32> {
    let eth: *const EthHdr = ptr_at(&ctx, 0).map_err(|_| xdp_action::XDP_PASS)?;
    
    if u16::from_be((*eth).ether_type) == 0x0800 {
        let eth_len = core::mem::size_of::<EthHdr>();
        let ip: *const Ipv4Hdr = ptr_at(&ctx, eth_len).map_err(|_| xdp_action::XDP_PASS)?;
        //bpf_printk!(c"ETH FOUND: %d", (*ip).proto as u8);
        
        if (*ip).proto as u8 == 6 {
            //bpf_printk!(c"TCP FOUND");
            let tcp: *const TcpHdr = ptr_at(&ctx, eth_len + 20).map_err(|_| xdp_action::XDP_PASS)?;
            
            let dest_port = u16::from_be_bytes((*tcp).dest);
            let src_port = u16::from_be_bytes((*tcp).source);
            //bpf_printk!(c"PARSED PORTS - SRC: %d, DST: %d", src_port, dest_port);
            
            let capture_dest = match CAPTURE_PORTS_BITMAP.get(dest_port as u32) {
                Some(flag) => *flag == 1,
                None => false,
            };

            let capture_src = match CAPTURE_PORTS_BITMAP.get(src_port as u32) {
                Some(flag) => *flag == 1,
                None => false,
            };
            
            if capture_dest || capture_src {
                bpf_printk!(c"MATCH: TCP packet {}:{} -> AF_XDP", src_port, dest_port);
                info!(&ctx, "MATCH: TCP packet {}:{} -> AF_XDP", src_port, dest_port);

                let queue_id = (*ctx.ctx).rx_queue_index;
                let flags = xdp_action::XDP_PASS as u64;

                match XSKS_MAP.redirect(queue_id, flags) {
                    Ok(action) => return Ok(action as u32),
                    Err(_) => {
                        info!(&ctx, "REDIRECT FAILED: Falling back to XDP_PASS");
                        return Ok(xdp_action::XDP_PASS);
                    }
                }
            }
        }
    }
    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
