use rand;

pub fn compute_challenge(input: u32) -> u32 {
    let encoded = (input ^ 0x74DE3F82).wrapping_add(input);
    encoded
}

pub fn genrand() -> u64 {
    rand::random::<u64>()
}
