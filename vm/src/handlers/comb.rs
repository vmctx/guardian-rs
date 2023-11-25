use crate::{Machine, OpSize};

macro_rules! impl_set_bytes {
    ($from:ident, $to:ident) => {
    ::paste::paste! {
        trait [<SetBytes $to>] {
            fn set_low(&mut self, value: $from);
            fn set_high(&mut self, value: $from);
        }

        impl [<SetBytes $to>] for $to {
            fn set_low(&mut self, value: $from) {
                *self |= value as $to;
            }

            fn set_high(&mut self, value: $from) {
                *self |= (value as $to) << $from::BITS as usize;
            }
        }
    }};
}

impl_set_bytes!(u8, u16);
impl_set_bytes!(u16, u32);
impl_set_bytes!(u32, u64);
impl_set_bytes!(u64, u128);

pub unsafe fn combine(vm: &mut Machine, op_size: OpSize) {
    match op_size {
        OpSize::Qword => {
            let mut combined = 0u128;
            combined.set_low(vm.stack_pop::<u64>());
            combined.set_high(vm.stack_pop::<u64>());
            vm.stack_push::<u128>(combined);
        }
        OpSize::Dword => {
            let mut combined = 0u64;
            combined.set_low(vm.stack_pop::<u32>());
            combined.set_high(vm.stack_pop::<u32>());
            vm.stack_push::<u64>(combined);
        }
        OpSize::Word => {
            let mut combined = 0u32;
            combined.set_low(vm.stack_pop::<u16>());
            combined.set_high(vm.stack_pop::<u16>());
            vm.stack_push::<u32>(combined);
        }
        OpSize::Byte => {
            let mut combined = 0u16;
            combined.set_low(vm.stack_pop::<u16>() as u8);
            combined.set_high(vm.stack_pop::<u16>() as u8);
            vm.stack_push::<u16>(combined);
        }
    }
}