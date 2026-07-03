#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::XskMap,
    programs::XdpContext,
};

#[map]
static XSKS_MAP: XskMap = XskMap::with_max_entries(64, 0);

#[xdp]
pub fn xsk_def_prog(ctx: XdpContext) -> u32 {
    match unsafe { try_xsk_def_prog(ctx) } {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

unsafe fn try_xsk_def_prog(ctx: XdpContext) -> Result<u32, u32> {
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
