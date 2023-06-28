use std::io::{self, Write};

fn main() {
    // taxa obfuscated flag
    let f1 = '\x43';
    let f2 = '\x43';
    let f3 = '\x53';
    let f4 = '\x43';
    let f5 = '\x7B';
    let f6 = '\x31';
    let f7 = '\x6D';
    let f8 = '\x5F';
    let f9 = '\x73';
    let f10 = '\x74';
    let f11 = '\x31';
    let f12 = '\x6C';
    let f13 = '\x31';
    let f14 = '\x5F';
    let f15 = '\x74';
    let f16 = '\x52';
    let f17 = '\x79';
    let f18 = '\x31';
    let f19 = '\x6E';
    let f20 = '\x36';
    let f21 = '\x5F';
    let f22 = '\x74';
    let f23 = '\x30';
    let f24 = '\x2D';
    let f25 = '\x6C';
    let f26 = '\x33';
    let f27 = '\x34';
    let f28 = '\x72';
    let f29 = '\x4E';
    let f30 = '\x5F';
    let f31 = '\x72';
    let f32 = '\x75';
    let f33 = '\x73';
    let f34 = '\x74';
    let f35 = '\x7D';
    let _ = [
        f1, f2, f3, f4, f5, f6, f7, f8, f9, f10, f11, f12, f13, f14, f15, f16, f17, f18, f19, f20,
        f21, f22, f23, f24, f25, f26, f27, f28, f29, f30, f31, f32, f33, f34, f35,
    ]; // Obfuscate the flag

    // to klidi sior
    let key = 13;

    // sorepse tis kuventes tou user
    print!("Enter the secret: ");
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    let input = input.trim();
    let decrypted_flag: String = input.chars().map(|c| (c as u8 ^ key) as char).collect();

    // bitwise XOR na doume ti ginete
    if decrypted_flag
        == format!(
            "{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}",
            f1,
            f2,
            f3,
            f4,
            f5,
            f6,
            f7,
            f8,
            f9,
            f10,
            f11,
            f12,
            f13,
            f14,
            f15,
            f16,
            f17,
            f18,
            f19,
            f20,
            f21,
            f22,
            f23,
            f24,
            f25,
            f26,
            f27,
            f28,
            f29,
            f30,
            f31,
            f32,
            f33,
            f34,
            f35
        )
    // checkare an en sosti i simaia
    {
        println!("Secret decrypted successfully: {}", decrypted_flag);
    } else {
        println!("Incorrect, YOU WILL NEVER GUESS THE SECRET!");
    }
}

// rustc -O --crate-type bin --edition=2018 -C link-args="-s" -o flag flag.rs
