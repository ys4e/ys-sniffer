use std::num::Wrapping;

/// Performs an XOR cipher on the data.
pub fn xor(data: &mut [u8], key: &[u8]) {
    for i in 0..data.len() {
        data[i] ^= key[i % key.len()];
    }
}

/// A random number generator.
/// 
/// Original implementation is from the C# source code.
pub struct Random {
    m_big: i32,
    m_seed: i32,
    inext: i32,
    inextp: i32,
    seed_array: [i32; 56],
}

impl Random {
    /// Creates a new instance of the `Random`.
    /// 
    /// This uses a default seed.
    pub fn default() -> Self {
        Random {
            m_big: i32::MAX,
            m_seed: 161803398,
            inext: 0,
            inextp: 0,
            seed_array: [0; 56],
        }
    }

    /// Creates a new instance of the `Random`.
    /// 
    /// `seed`: The seed to use for the generator.
    pub fn seeded(seed: i32) -> Random {
        let mut ii;
        let mut rand = Random::default();

        let subtraction = if seed == i32::MIN {
            i32::MAX
        } else {
            i32::abs(seed)
        };
        let mut mj = rand.m_seed - subtraction;
        rand.seed_array[55] = mj;

        let mut mk = 1;

        for i in 1..55 {
            ii = 21 * i % 55;
            rand.seed_array[ii] = mk;
            mk = mj - mk;
            if mk < 0 {
                mk += rand.m_big
            }
            mj = rand.seed_array[ii]
        }

        for _ in 1..5 {
            for i in 1..56 {
                rand.seed_array[i] =
                    rand.seed_array[i].wrapping_sub(rand.seed_array[1 + (i + 30) % 55]);
                if rand.seed_array[i] < 0 {
                    rand.seed_array[i] += rand.m_big
                };
            }
        }

        rand.inext = 0;
        rand.inextp = 21;

        rand
    }

    pub fn next_double(&mut self) -> f64 {
        (self.internal_sample() as f64) * (1.0 / (self.m_big as f64))
    }

    fn internal_sample(&mut self) -> i32 {
        let mut ret_val: i32;
        let mut loc_inext = self.inext;
        let mut loc_inextp = self.inextp;

        if (loc_inext += 1, loc_inext).1 >= 56 {
            loc_inext = 1;
        }
        if (loc_inextp += 1, loc_inextp).1 >= 56 {
            loc_inextp = 1;
        }

        ret_val = self.seed_array[loc_inext as usize] - self.seed_array[loc_inextp as usize];

        if ret_val == self.m_big { ret_val -= 1 };
        if ret_val < 0 { ret_val += self.m_big };

        self.seed_array[loc_inext as usize] = ret_val;

        self.inext = loc_inext;
        self.inextp = loc_inextp;

        ret_val
    }

    pub fn next_safe_uint64(&mut self) -> u64 {
        (self.next_double() * (u64::MAX as f64)) as u64
    }
}

/// A random number generator.
/// 
/// An implementation of Mersenne Twister.
pub struct MT19937_64 {
    mt: [u64; 312],
    mti: u32,
}

impl MT19937_64 {
    pub fn default() -> MT19937_64 {
        MT19937_64 {
            mt: [0; 312],
            mti: 0x139,
        }
    }

    /// Seeds the generator.
    pub fn seed(&mut self, seed: u64) {
        self.mt[0] = seed & 0xffffffffffffffff;
        for i in 1..312 {
            let value = Wrapping(self.mt[i - 1] ^ (self.mt[i - 1] >> 62));
            self.mt[i] = ((Wrapping(6364136223846793005u64) * value).0 + (i as u64)) & 0xffffffffffffffff;
        }
        
        self.mti = 312;
    }

    /// Generates the next 64-bit random number in the sequence.
    pub fn next_ulong(&mut self) -> u64 {
        if self.mti >= 312 {
            if self.mti == 313 {
                self.seed(5489)
            }
            for k in 0..311 {
                let y = (self.mt[k] & 0xffffffff80000000) | (self.mt[k + 1] & 0x7fffffff);
                if k < (312 - 156) {
                    self.mt[k] = self.mt[k + 156]
                        ^ (y >> 1)
                        ^ (if (y & 1) == 0 { 0 } else { 0xb5026f5aa96619e9 });
                } else {
                    self.mt[k] = self.mt[(Wrapping(k + 156 + self.mt.len()) - Wrapping(624)).0]
                        ^ (y >> 1)
                        ^ (if (y & 1) == 0 { 0 } else { 0xb5026f5aa96619e9 });
                }
            }

            let yy = (self.mt[311] & 0xffffffff80000000) | (self.mt[0] & 0x7fffffff);
            self.mt[311] =
                self.mt[155] ^ (yy >> 1) ^ (if yy & 1 == 0 { 0 } else { 0xb5026f5aa96619e9 });
            self.mti = 0;
        }
        
        let mut x = self.mt[self.mti as usize];
        
        self.mti += 1;
        x ^= (x >> 29) & 0x5555555555555555;
        x ^= (x << 17) & 0x71d67fffeda60000;
        x ^= (x << 37) & 0xfff7eee000000000;
        x ^= x >> 43;
        x
    }
}