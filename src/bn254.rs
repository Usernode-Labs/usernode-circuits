#![allow(clippy::module_name_repetitions)]
#![deny(unsafe_op_in_unsafe_fn)]

#[derive(Copy, Clone, PartialEq, Eq, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct Field([u8; 32]);

impl Field {
    pub fn from(v: u128) -> Self {
        let mut be = [0u8; 32];
        be[16..].copy_from_slice(&v.to_be_bytes());
        Field(be)
    }

    pub fn zero() -> Self {
        Field([0u8; 32])
    }

    pub fn one() -> Self {
        Self::from(1u128)
    }

    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Field(bytes)
    }

    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl AsRef<[u8; 32]> for Field {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<[u8; 32]> for Field {
    fn from(bytes: [u8; 32]) -> Self {
        Field(bytes)
    }
}

impl From<Field> for [u8; 32] {
    fn from(f: Field) -> Self {
        f.0
    }
}

impl core::ops::AddAssign for Field {
    fn add_assign(&mut self, rhs: Self) {
        *self = ffi::fr_add(self, &rhs);
    }
}

impl core::ops::Add for Field {
    type Output = Field;

    fn add(self, rhs: Self) -> Self::Output {
        ffi::fr_add(&self, &rhs)
    }
}

impl core::ops::Mul for Field {
    type Output = Field;

    fn mul(self, rhs: Self) -> Self::Output {
        ffi::fr_mul(&self, &rhs)
    }
}

impl core::ops::MulAssign for Field {
    fn mul_assign(&mut self, rhs: Self) {
        *self = ffi::fr_mul(self, &rhs);
    }
}

impl core::ops::Sub for Field {
    type Output = Field;

    fn sub(self, rhs: Self) -> Self::Output {
        ffi::fr_sub(&self, &rhs)
    }
}

impl core::ops::SubAssign for Field {
    fn sub_assign(&mut self, rhs: Self) {
        *self = ffi::fr_sub(self, &rhs);
    }
}

impl PartialOrd for Field {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(ffi::fr_cmp(self, other))
    }
}

mod ffi {
    use super::Field;

    #[inline]
    fn be32(f: &Field) -> [u8; 32] {
        f.0
    }

    #[inline]
    fn from_be32(bytes: &[u8; 32]) -> Field {
        Field(*bytes)
    }

    #[inline]
    pub fn fr_add(a: &Field, b: &Field) -> Field {
        let mut out_ptr: *mut u8 = core::ptr::null_mut();
        let mut out_len: usize = 0;
        let rc = unsafe {
            aztec_barretenberg_sys_rs::bb_fr_add(
                be32(a).as_ptr(),
                be32(b).as_ptr(),
                &mut out_ptr,
                &mut out_len,
            )
        };
        assert_eq!(rc, 0, "bb_fr_add failed");
        assert_eq!(out_len, 32, "bb_fr_add returned wrong length");
        let out_slice = unsafe { core::slice::from_raw_parts(out_ptr, out_len) };
        let mut be = [0u8; 32];
        be.copy_from_slice(out_slice);
        unsafe { aztec_barretenberg_sys_rs::bb_free(out_ptr) };
        from_be32(&be)
    }

    #[inline]
    pub fn fr_sub(a: &Field, b: &Field) -> Field {
        let mut out_ptr: *mut u8 = core::ptr::null_mut();
        let mut out_len: usize = 0;
        let rc = unsafe {
            aztec_barretenberg_sys_rs::bb_fr_sub(
                be32(a).as_ptr(),
                be32(b).as_ptr(),
                &mut out_ptr,
                &mut out_len,
            )
        };
        assert_eq!(rc, 0, "bb_fr_sub failed");
        assert_eq!(out_len, 32, "bb_fr_sub returned wrong length");
        let out_slice = unsafe { core::slice::from_raw_parts(out_ptr, out_len) };
        let mut be = [0u8; 32];
        be.copy_from_slice(out_slice);
        unsafe { aztec_barretenberg_sys_rs::bb_free(out_ptr) };
        from_be32(&be)
    }

    #[inline]
    pub fn fr_mul(a: &Field, b: &Field) -> Field {
        let mut out_ptr: *mut u8 = core::ptr::null_mut();
        let mut out_len: usize = 0;
        let rc = unsafe {
            aztec_barretenberg_sys_rs::bb_fr_mul(
                be32(a).as_ptr(),
                be32(b).as_ptr(),
                &mut out_ptr,
                &mut out_len,
            )
        };
        assert_eq!(rc, 0, "bb_fr_mul failed");
        assert_eq!(out_len, 32, "bb_fr_mul returned wrong length");
        let out_slice = unsafe { core::slice::from_raw_parts(out_ptr, out_len) };
        let mut be = [0u8; 32];
        be.copy_from_slice(out_slice);
        unsafe { aztec_barretenberg_sys_rs::bb_free(out_ptr) };
        from_be32(&be)
    }

    #[inline]
    pub fn fr_cmp(a: &Field, b: &Field) -> core::cmp::Ordering {
        let rc =
            unsafe { aztec_barretenberg_sys_rs::bb_fr_cmp(be32(a).as_ptr(), be32(b).as_ptr()) };
        if rc < 0 {
            core::cmp::Ordering::Less
        } else if rc > 0 {
            core::cmp::Ordering::Greater
        } else {
            core::cmp::Ordering::Equal
        }
    }
}

impl binprot::BinProtWrite for Field {
    fn binprot_write<W: std::io::Write>(&self, w: &mut W) -> std::io::Result<()> {
        let v: Vec<u8> = self.0.to_vec();
        binprot::BinProtWrite::binprot_write(&v, w)
    }
}

impl binprot::BinProtRead for Field {
    fn binprot_read<R: std::io::Read + ?Sized>(r: &mut R) -> Result<Self, binprot::Error> {
        let v: Vec<u8> = binprot::BinProtRead::binprot_read(r)?;
        if v.len() != 32 {
            return Err(binprot::Error::CustomError(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("expected 32 bytes for bn254::Field, got {}", v.len()),
            ))));
        }
        let mut be = [0u8; 32];
        be.copy_from_slice(&v);
        Ok(Field::from_bytes(be))
    }
}
