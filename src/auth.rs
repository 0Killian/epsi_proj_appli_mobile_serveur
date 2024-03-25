use rand;

pub fn encodecode(input: u64) -> u64 {
    let encoded = (input ^ 0x74DE3F8276ABC849).wrapping_add(input);
    encoded
}

pub fn genrand() -> u64 {
    rand::random::<u64>()
}

pub fn checkcode(code: u64, encodedcode: u64) -> bool {
    encodedcode == encodecode(code)
}
