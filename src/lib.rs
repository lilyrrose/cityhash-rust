#![warn(clippy::pedantic)]
#![allow(clippy::many_single_char_names)]

#[cfg(test)]
mod test;
#[cfg(test)]
mod test_128;

use std::ptr::read_unaligned;

pub const K0: u64 = 0xc3a5_c85c_97cb_3127;
pub const K1: u64 = 0xb492_b66f_be98_f273;
pub const K2: u64 = 0x9ae1_6a3b_2f90_404f;
pub const K3: u64 = 0xc949_d7c7_509e_6557;
pub const K_MUL: u64 = 0x9ddf_ea08_eb38_2d69;

// low bits, high bits
#[derive(Debug, Clone, Copy)]
pub struct U128(u64, u64);

// This is the point clippy :p
#[allow(clippy::cast_possible_truncation)]
impl From<u128> for U128 {
    fn from(value: u128) -> Self {
        U128(value as u64, (value >> 64) as u64)
    }
}

impl From<U128> for u128 {
    fn from(value: U128) -> Self {
        u128::from(value.1) << 64 | u128::from(value.0)
    }
}

#[inline]
#[must_use]
pub fn fetch32(data: &[u8]) -> u32 {
    let p = unsafe { read_unaligned(data.as_ptr().cast::<u32>()) };
    if cfg!(not(target_endian = "little")) {
        return p.swap_bytes();
    }

    p
}

#[inline]
#[must_use]
pub fn fetch64(data: &[u8]) -> u64 {
    let p = unsafe { read_unaligned(data.as_ptr().cast::<u64>()) };
    if cfg!(not(target_endian = "little")) {
        return p.swap_bytes();
    }

    p
}

#[inline]
#[must_use]
pub fn rotate_by_at_least1(val: u64, shift: u64) -> u64 {
    (val >> shift) | (val << (64 - shift))
}

#[inline]
#[must_use]
pub fn shift_mix(val: u64) -> u64 {
    val ^ (val >> 47)
}

#[inline]
#[must_use]
pub fn hash128_to_64(x: U128) -> u64 {
    let mut a = (x.0 ^ x.1).wrapping_mul(K_MUL);
    a ^= a >> 47;
    let mut b = (x.1 ^ a).wrapping_mul(K_MUL);
    b ^= b >> 47;
    b.wrapping_mul(K_MUL)
}

#[inline]
#[must_use]
pub fn hash_len_16(u: u64, v: u64) -> u64 {
    hash128_to_64(U128(u, v))
}

#[must_use]
pub fn hash_len_0_16(data: &[u8]) -> u64 {
    if data.len() > 8 {
        let a = fetch64(data);
        let b = fetch64(&data[data.len() - 8..]);
        hash_len_16(
            a,
            rotate_by_at_least1(b.wrapping_add(data.len() as u64), data.len() as u64),
        ) ^ b
    } else if data.len() >= 4 {
        let a = u64::from(fetch32(data));
        hash_len_16(
            (a << 3).wrapping_add(data.len() as u64),
            u64::from(fetch32(&data[data.len() - 4..])),
        )
    } else if !data.is_empty() {
        let a = u64::from(data[0]);
        let b = u64::from(data[data.len() >> 1]);
        let c = u64::from(data[data.len() - 1]);
        let y = a.wrapping_add(b << 8);
        let z = (c << 2).wrapping_add(data.len() as u64);
        shift_mix(y.wrapping_mul(K2) ^ z.wrapping_mul(K3)).wrapping_mul(K2)
    } else {
        K2
    }
}

#[must_use]
pub fn hash_len_17_32(data: &[u8]) -> u64 {
    let a = fetch64(data).wrapping_mul(K1);
    let b = fetch64(&data[8..]);
    let c = fetch64(&data[data.len() - 8..]).wrapping_mul(K2);
    let d = fetch64(&data[data.len() - 16..]).wrapping_mul(K0);
    hash_len_16(
        rotate_by_at_least1(a.wrapping_sub(b), 43)
            .wrapping_add(rotate_by_at_least1(c, 30))
            .wrapping_add(d),
        a.wrapping_add(rotate_by_at_least1(b ^ K3, 20))
            .wrapping_sub(c)
            .wrapping_add(data.len() as u64),
    )
}

#[must_use]
pub fn weak_hash_len32_with_seeds_p(
    w: u64,
    x: u64,
    y: u64,
    z: u64,
    mut a: u64,
    mut b: u64,
) -> (u64, u64) {
    a = a.wrapping_add(w);
    b = rotate_by_at_least1(b.wrapping_add(a).wrapping_add(z), 21);
    let c = a;
    a = a.wrapping_add(x);
    a = a.wrapping_add(y);
    b = b.wrapping_add(rotate_by_at_least1(a, 44));
    (a.wrapping_add(z), b.wrapping_add(c))
}

#[must_use]
#[inline]
pub fn weak_hash_len32_with_seeds(data: &[u8], a: u64, b: u64) -> (u64, u64) {
    weak_hash_len32_with_seeds_p(
        fetch64(data),
        fetch64(&data[8..]),
        fetch64(&data[16..]),
        fetch64(&data[24..]),
        a,
        b,
    )
}

#[must_use]
pub fn hash_len_33_64(data: &[u8]) -> u64 {
    let mut z = fetch64(&data[24..]);
    let mut a = fetch64(data).wrapping_add(
        fetch64(&data[data.len() - 16..])
            .wrapping_add(data.len() as u64)
            .wrapping_mul(K0),
    );
    let mut b = rotate_by_at_least1(a + z, 52);
    let mut c = rotate_by_at_least1(a, 37);
    a = a.wrapping_add(fetch64(&data[8..]));
    c = c.wrapping_add(rotate_by_at_least1(a, 7));
    a = a.wrapping_add(fetch64(&data[16..]));
    let vf = a.wrapping_add(z);
    let vs = b.wrapping_add(rotate_by_at_least1(a, 31)).wrapping_add(c);
    a = fetch64(&data[16..]).wrapping_add(fetch64(&data[data.len() - 32..]));
    z = fetch64(&data[data.len() - 8..]);
    b = rotate_by_at_least1(a.wrapping_add(z), 52);
    c = rotate_by_at_least1(a, 37);
    a = a.wrapping_add(fetch64(&data[data.len() - 24..]));
    c = c.wrapping_add(rotate_by_at_least1(a, 7));
    a = a.wrapping_add(fetch64(&data[data.len() - 16..]));
    let wf = a.wrapping_add(z);
    let ws = b.wrapping_add(rotate_by_at_least1(a, 31)).wrapping_add(c);
    let r = shift_mix(
        vf.wrapping_add(ws)
            .wrapping_mul(K2)
            .wrapping_add((wf.wrapping_add(vs)).wrapping_mul(K0)),
    );
    shift_mix(r.wrapping_mul(K0).wrapping_add(vs)).wrapping_mul(K2)
}

#[must_use]
pub fn city_hash_64(data: &[u8]) -> u64 {
    if data.len() <= 32 {
        if data.len() <= 16 {
            return hash_len_0_16(data);
        }
        return hash_len_17_32(data);
    } else if data.len() <= 64 {
        return hash_len_33_64(data);
    }

    let mut x = fetch64(data);
    let mut y = fetch64(&data[data.len() - 16..]) ^ K1;
    let mut z = fetch64(&data[data.len() - 56..]) ^ K0;
    let mut v = weak_hash_len32_with_seeds(&data[data.len() - 64..], data.len() as u64, y);
    let mut w = weak_hash_len32_with_seeds(
        &data[data.len() - 32..],
        (data.len() as u64).wrapping_mul(K1),
        K0,
    );

    z = z.wrapping_add(shift_mix(v.1).wrapping_mul(K1));
    x = rotate_by_at_least1(z.wrapping_add(x), 39).wrapping_mul(K1);
    y = rotate_by_at_least1(y, 33).wrapping_mul(K1);

    let mut len = (data.len() - 1) & !63;
    let mut offset = 0;
    loop {
        x = rotate_by_at_least1(
            x.wrapping_add(y)
                .wrapping_add(v.0)
                .wrapping_add(fetch64(&data[offset + 16..])),
            37,
        )
        .wrapping_mul(K1);
        y = rotate_by_at_least1(
            y.wrapping_add(v.1)
                .wrapping_add(fetch64(&data[offset + 48..])),
            42,
        )
        .wrapping_mul(K1);
        x ^= w.1;
        y ^= v.0;
        z = rotate_by_at_least1(z ^ w.0, 33);
        v = weak_hash_len32_with_seeds(&data[offset..], v.1.wrapping_mul(K1), x.wrapping_add(w.0));
        w = weak_hash_len32_with_seeds(&data[offset + 32..], z.wrapping_add(w.1), y);
        std::mem::swap(&mut z, &mut x);
        offset += 64;
        len -= 64;
        if len == 0 {
            break;
        }
    }

    hash_len_16(
        hash_len_16(v.0, w.0).wrapping_add(shift_mix(y).wrapping_mul(K1).wrapping_add(z)),
        hash_len_16(v.1, w.1).wrapping_add(x),
    )
}

#[must_use]
pub fn city_murmur(data: &[u8], seed: u128) -> u128 {
    let seed = U128::from(seed);
    let mut a = seed.0;
    let mut b = seed.1;
    let mut c;
    let mut d;

    let mut len = data.len();
    if len <= 16 {
        a = shift_mix(a.wrapping_mul(K1)).wrapping_mul(K1);
        c = b.wrapping_mul(K1).wrapping_add(hash_len_0_16(data));
        let additive = if len >= 8 { fetch64(data) } else { c };
        d = shift_mix(a.wrapping_add(additive));
    } else {
        c = hash_len_16(fetch64(&data[len - 8..]).wrapping_add(K1), a);
        d = hash_len_16(
            b.wrapping_add(len as u64),
            c.wrapping_add(fetch64(&data[len - 16..])),
        );
        a = a.wrapping_add(d);

        let mut offset = 0;
        loop {
            a ^= shift_mix(fetch64(&data[offset..]).wrapping_mul(K1)).wrapping_mul(K1);
            a = a.wrapping_mul(K1);
            b ^= a;
            c ^= shift_mix(fetch64(&data[offset + 8..]).wrapping_mul(K1)).wrapping_mul(K1);
            c = c.wrapping_mul(K1);
            d ^= c;
            offset += 16;
            len -= 16;
            if len <= 16 {
                break;
            }
        }
    }

    a = hash_len_16(a, c);
    b = hash_len_16(d, b);
    U128(a ^ b, hash_len_16(b, a)).into()
}

#[must_use]
pub fn city_hash_128_seed(data: &[u8], seed: u128) -> u128 {
    if data.len() < 128 {
        return city_murmur(data, seed);
    }

    let seed = U128::from(seed);
    let mut v = (0, 0);
    let mut w = (0, 0);
    let mut x = seed.0;
    let mut y = seed.1;
    let mut z = (data.len() as u64).wrapping_mul(K1);
    v.0 = rotate_by_at_least1(y ^ K1, 49)
        .wrapping_mul(K1)
        .wrapping_add(fetch64(data));
    v.1 = rotate_by_at_least1(v.0, 42)
        .wrapping_mul(K1)
        .wrapping_add(fetch64(&data[8..]));
    w.0 = rotate_by_at_least1(y.wrapping_add(z), 35)
        .wrapping_mul(K1)
        .wrapping_add(x);
    w.1 = rotate_by_at_least1(x.wrapping_add(fetch64(&data[88..])), 53).wrapping_mul(K1);

    let mut offset = 0;
    let mut len = data.len();
    loop {
        x = rotate_by_at_least1(
            x.wrapping_add(y)
                .wrapping_add(v.0)
                .wrapping_add(fetch64(&data[offset + 16..])),
            37,
        )
        .wrapping_mul(K1);
        y = rotate_by_at_least1(
            y.wrapping_add(v.1)
                .wrapping_add(fetch64(&data[offset + 48..])),
            42,
        )
        .wrapping_mul(K1);
        x ^= w.1;
        y ^= v.0;
        z = rotate_by_at_least1(z ^ w.0, 33);
        v = weak_hash_len32_with_seeds(&data[offset..], v.1.wrapping_mul(K1), x.wrapping_add(w.0));
        w = weak_hash_len32_with_seeds(&data[offset + 32..], z.wrapping_add(w.1), y);
        std::mem::swap(&mut z, &mut x);
        offset += 64;

        x = rotate_by_at_least1(
            x.wrapping_add(y)
                .wrapping_add(v.0)
                .wrapping_add(fetch64(&data[offset + 16..])),
            37,
        )
        .wrapping_mul(K1);
        y = rotate_by_at_least1(
            y.wrapping_add(v.1)
                .wrapping_add(fetch64(&data[offset + 48..])),
            42,
        )
        .wrapping_mul(K1);
        x ^= w.1;
        y ^= v.0;
        z = rotate_by_at_least1(z ^ w.0, 33);
        v = weak_hash_len32_with_seeds(&data[offset..], v.1.wrapping_mul(K1), x.wrapping_add(w.0));
        w = weak_hash_len32_with_seeds(&data[offset + 32..], z.wrapping_add(w.1), y);
        std::mem::swap(&mut z, &mut x);
        offset += 64;
        len -= 128;
        if len < 128 {
            break;
        }
    }
    y = y.wrapping_add(
        rotate_by_at_least1(w.0, 37)
            .wrapping_mul(K0)
            .wrapping_add(z),
    );
    x = x.wrapping_add(rotate_by_at_least1(v.0.wrapping_add(z), 49).wrapping_mul(K0));

    let mut tail_done = 0;
    while tail_done < len {
        tail_done += 32;
        y = rotate_by_at_least1(y.wrapping_sub(x), 42)
            .wrapping_mul(K0)
            .wrapping_add(v.1);
        w.0 =
            w.0.wrapping_add(fetch64(&data[offset + len - tail_done + 16..]));
        x = rotate_by_at_least1(x, 49)
            .wrapping_mul(K0)
            .wrapping_add(w.0);
        w.0 = w.0.wrapping_add(v.0);
        v = weak_hash_len32_with_seeds(&data[offset + len - tail_done..], v.0, v.1);
    }

    x = hash_len_16(x, v.0);
    y = hash_len_16(y, w.0);

    U128(
        hash_len_16(x.wrapping_add(v.1), w.1).wrapping_add(y),
        hash_len_16(x.wrapping_add(w.1), y.wrapping_add(v.1)),
    )
    .into()
}

#[must_use]
pub fn city_hash_128(data: &[u8]) -> u128 {
    if data.len() >= 16 {
        city_hash_128_seed(
            &data[16..],
            U128(fetch64(data) ^ K3, fetch64(&data[8..])).into(),
        )
    } else if data.len() >= 8 {
        city_hash_128_seed(
            &[],
            U128(
                fetch64(data) ^ ((data.len() as u64).wrapping_mul(K0)),
                fetch64(&data[data.len() - 8..]) ^ K1,
            )
            .into(),
        )
    } else {
        city_hash_128_seed(data, U128(K0, K1).into())
    }
}
