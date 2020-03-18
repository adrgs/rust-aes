mod aes;
extern crate clap;

use clap::{Arg, App};

fn main() {

    let matches = App::new("rust-aes")
        .version("0.1.0")
        .author("adrgs github.com/adrgs/rust-aes")
        .about("A pure Rust implementation of AES 128")
        .arg(Arg::with_name("file")
            .short("f")
            .long("file")
            .takes_value(true)
            .help("(Optional) Input file, otherwise input is read from stdin, or from -i option"))
        .arg(Arg::with_name("output")
            .short("o")
            .long("output")
            .takes_value(true)
            .help("(Optional) Output file, otherwise output is directed to stdout"))
        .arg(Arg::with_name("input")
            .short("i")
            .long("input")
            .takes_value(true)
            .help("(Optional) Encrypt/Decrypt the argument, format: hexadecimal characters, needs to be divisible by 16 if -d flag is present or if -p flag is not present"))
        .arg(Arg::with_name("key")
            .short("k")
            .long("key")
            .takes_value(true)
            .help("The AES key, format: 32 hexadecimal characters"))
        .arg(Arg::with_name("encrypt")
            .short("e")
            .long("encrypt")
            .help("(Implicit) Encrypt mode"))
        .arg(Arg::with_name("decrypt")
            .short("d")
            .long("decrypt")
            .help("Decrypt mode"))
        .arg(Arg::with_name("padding")
            .short("p")
            .long("padding")
            .help("Flag specifies whether the input should be padded/unpadded")).get_matches();

    let key = matches.value_of("key").unwrap_or("");

    if key == "" {
        aes::run_test();
    } else {
        if key.len() != 32 {
            eprintln!("Key should be 32 hexadecimal digits long but your key is {} hexadecimal digits long", key.len());
        }

        let mut good = true;

        for (i, c) in key.chars().enumerate() {
            if (c>='0' && c<='9') || (c>='a' && c<='f') || (c>='A' && c<='F') {
                continue;
            } else {
                let padding_left = " ".repeat(i);
                eprintln!("Error");
                eprintln!("{}", key);
                eprintln!("{}^", padding_left);
                eprintln!("{}Not a valid hexadecimal character", padding_left);
                good = false;
                break;
            }
        }

        if good == true {
            
        }

    }
}
