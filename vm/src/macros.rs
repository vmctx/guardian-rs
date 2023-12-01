use core::convert::TryFrom;
use core::ops::{BitAnd, Shr};

fn one<N: TryFrom<u8>>() -> N {
    1u8.try_into().unwrap_or_else(|_| unreachable!())
}

pub fn get_msb<N>(n: N) -> N
    where
        N: Shr<usize, Output = N> + BitAnd<Output = N> + TryFrom<u8>,
{
    let shift = core::mem::size_of::<N>() * 8 - 1;
    (n >> shift) & one()
}

macro_rules! calculate_rflags {
    // of also sets cf for now
    ($self:ident, $op1:ident, $op2: ident, $result:ident, OF) => {{
        use x86::bits64::rflags::RFlags;
        let mut rflags = RFlags::from_bits_truncate($self.rflags);
        rflags.set(RFlags::FLAGS_OF, (($crate::macros::get_msb($op1) == 0 && $crate::macros::get_msb($op2) == 0)
            && $crate::macros::get_msb($result) == 1) || (($crate::macros::get_msb($op1) == 1 && $crate::macros::get_msb($op2) == 1)
            && $crate::macros::get_msb($result) == 0)
        );
        $self.rflags = rflags.bits();
    }};
    ($self:ident, $op1:ident, $op2: ident, $result:ident, CF_ADD) => {{
        use x86::bits64::rflags::RFlags;
        let mut rflags = RFlags::from_bits_truncate($self.rflags);
        rflags.set(RFlags::FLAGS_CF, $result < $op1);
        $self.rflags = rflags.bits();
    }};
    ($self:ident, $op1:ident, $op2: ident, $result:ident, CF_SUB) => {{
        use x86::bits64::rflags::RFlags;
        let mut rflags = RFlags::from_bits_truncate($self.rflags);
        rflags.set(RFlags::FLAGS_CF, $result > $op1);
        $self.rflags = rflags.bits();
    }};
     ($self:ident, $op1:ident, $op2: ident, $result:ident, AF) => {{
        unimplemented!()
    }};
    ($self:ident, $op1:ident, $op2: ident, $result:ident, ZF) => {{
        use x86::bits64::rflags::RFlags;
        let mut rflags = RFlags::from_bits_truncate($self.rflags);
        rflags.set(RFlags::FLAGS_ZF, $result == 0);
        $self.rflags = rflags.bits();
    }};
    ($self:ident, $op1:ident, $op2: ident, $result:ident, PF) => {{
        use x86::bits64::rflags::RFlags;
        let mut rflags = RFlags::from_bits_truncate($self.rflags);
        rflags.set(RFlags::FLAGS_PF, $result.count_ones() % 2 != 0);
        $self.rflags = rflags.bits();
    }};
    ($self:ident, $op1:ident, $op2: ident, $result:ident, SF) => {{
        use x86::bits64::rflags::RFlags;
        let mut rflags = RFlags::from_bits_truncate($self.rflags);
        rflags.set(RFlags::FLAGS_SF, $crate::macros::get_msb($result) == 1);
        $self.rflags = rflags.bits();
    }};
    ($self:ident, $op1:ident, $op2: ident, $result:ident, $($flag:ident),+ $(,)?) => {
        $(
            $crate::calculate_rflags!($self, $op1, $op2, $result, $flag);
        )+
    };
}

pub(crate) use calculate_rflags;

macro_rules! binary_op {
    ($self:ident, $op:ident) => {{
        let (op2, op1) = unsafe { ($self.stack_pop::<u64>(), $self.stack_pop::<u64>()) };
        let result = op1.$op(op2);

        unsafe { $self.stack_push(result);}
    }}
}

pub(crate) use binary_op;

macro_rules! binary_op_sized {
    ($self:ident, $op_size:ident, $op:ident) => {{
       match $op_size {
            OpSize::Qword => binary_op_sized!($self, u64, $op;),
            OpSize::Dword => binary_op_sized!($self, u32, $op;),
            OpSize::Word => binary_op_sized!($self, u16, $op;),
            OpSize::Byte => binary_op_sized!($self, u8, $op;),
        }
    }};
    ($self:ident, $bit:ident, $op:ident;) => {{
        let (op2, op1) = if core::mem::size_of::<$bit>() == 1 {
            unsafe { ($self.stack_pop::<u16>() as $bit, $self.stack_pop::<u16>() as $bit) }
        } else {
            unsafe { ($self.stack_pop::<$bit>(), $self.stack_pop::<$bit>()) }
        };

        let result = op1.$op(op2);

        if core::mem::size_of::<$bit>() == 1 {
            unsafe { $self.stack_push(result as u16); }
        } else {
            unsafe { $self.stack_push(result); }
        }
    }}
}

pub(crate) use binary_op_sized;

macro_rules! binary_op_save_flags {
    ($self:ident, $op_size:ident, $op:ident $(, $rflag:ident)*) => {{
       match $op_size {
            OpSize::Qword => binary_op_save_flags!($self, u64, $op, $($rflag),*;),
            OpSize::Dword => binary_op_save_flags!($self, u32, $op, $($rflag),*;),
            OpSize::Word => binary_op_save_flags!($self, u16, $op, $($rflag),*;),
            OpSize::Byte => binary_op_save_flags!($self, u8, $op, $($rflag),*;),
        }
    }};
    ($self:ident, $bit:ident, $op:ident $(, $rflag:ident)* ;) => {{
        let (op2, op1) = if core::mem::size_of::<$bit>() == 1 {
            unsafe { ($self.stack_pop::<u16>() as $bit, $self.stack_pop::<u16>() as $bit) }
        } else {
            unsafe { ($self.stack_pop::<$bit>(), $self.stack_pop::<$bit>()) }
        };

        let result = op1.$op(op2);

        $crate::calculate_rflags!($self, op1, op2, result, $($rflag),*);

        //$self.set_rflags();

        if core::mem::size_of::<$bit>() == 1 {
            unsafe { $self.stack_push(result as u16); }
        } else {
            unsafe { $self.stack_push(result); }
        }
    }}
}

pub(crate) use binary_op_save_flags;

macro_rules! binary_op_arg1 {
    ($self:ident, $op_size:ident, $op:ident) => {{
       match $op_size {
            OpSize::Qword => binary_op_arg1!($self, u64, $op;),
            OpSize::Dword => binary_op_arg1!($self, u32, $op;),
            OpSize::Word => binary_op_arg1!($self, u16, $op;),
            OpSize::Byte => binary_op_arg1!($self, u8, $op;),
        }
    }};
    ($self:ident, $bit:ident, $op:ident;) => {{
        let op1 = if core::mem::size_of::<$bit>() == 1 {
            unsafe { $self.stack_pop::<u16>() as $bit }
        } else {
            unsafe { $self.stack_pop::<$bit>() }
        };
        let result = op1.$op();

         if core::mem::size_of::<$bit>() == 1 {
            unsafe { $self.stack_push(result as u16); }
        } else {
            unsafe { $self.stack_push(result); }
        }
    }}
}

pub(crate) use binary_op_arg1;

macro_rules! rotate {
    ($self:ident, $bit:ident, $op:ident) => {{
        let op1 = if core::mem::size_of::<$bit>() == 1 {
            unsafe { $self.stack_pop::<u16>() as $bit }
        } else {
            unsafe { $self.stack_pop::<$bit>() }
        };

        let result = op1.$op(8);

        if core::mem::size_of::<$bit>() == 1 {
            unsafe { $self.stack_push(result as u16); }
        } else {
            unsafe { $self.stack_push(result); }
        }
    }}
}

pub(crate) use rotate;