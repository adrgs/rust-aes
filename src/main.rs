mod aes;
extern crate rand;
extern crate clap;

use std::fs::{File,read};
use std::io::{stdin,stdout,prelude::*};
use clap::{Arg, App,AppSettings};
use rand::Rng;
extern crate hex;

fn get_key_bytes(key_string: &str, key_file: &str, generate_key: bool) -> [u8;16] {
    let mut key_bytes = [0u8; 16];

    if key_string != "" {
        if key_string.len() != 32 {
            eprintln!("Key should be 32 hexadecimal digits long but your key is {} hexadecimal digits long", key_string.len());
            assert!(key_string.len() == 32);
        }

        let mut good = true;

        for (i, c) in key_string.chars().enumerate() {
            if (c>='0' && c<='9') || (c>='a' && c<='f') || (c>='A' && c<='F') {
                continue;
            } else {
                let padding_left = " ".repeat(i);
                eprintln!("Error");
                eprintln!("{}", key_string);
                eprintln!("{}^", padding_left);
                eprintln!("{}Not a valid hexadecimal character", padding_left);
                good = false;
                break;
            }
        }

        assert!(good == true);

        let bytes = &hex::decode(key_string).expect("Invalid key")[..key_bytes.len()];
        key_bytes.copy_from_slice(bytes);
    } else if key_file != "" {
        let bytes = read(key_file).expect("Failed to read");
        let tmp = &bytes[..key_bytes.len()];
        assert!(bytes.len()==16);
        key_bytes.copy_from_slice(tmp);
    } else if generate_key != false {
        let mut rng = rand::thread_rng();

        for i in 0..16 {
            key_bytes[i] = rng.gen();
        }
        write_generated_key(&key_bytes);

    } else {
        panic!("No key provided");
    }

    return key_bytes;
}

fn write_generated_key(key_bytes: &[u8;16]) -> std::io::Result<()> {
    let mut f = File::create("key.out")?;
    f.write_all(key_bytes)?;

    f.sync_all()?;
    Ok(())
}

fn write_output_file(output_bytes: &[u8], file_name: &str) -> std::io::Result<()> {
    let mut f = File::create(file_name)?;
    f.write_all(output_bytes)?;

    f.sync_all()?;
    Ok(())
}

fn main() {
    let matches = App::new("rust-aes")
        .setting(AppSettings::ArgRequiredElseHelp)
        .version("0.1.1")
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
        .arg(Arg::with_name("generate")
            .short("g")
            .long("generate")
            .help("Generate a random AES key to use for encryption, the key will be saved to the file key.out"))
        .arg(Arg::with_name("raw")
            .short("r")
            .long("raw")
            .help("Read raw bytes from stdin and write raw byte to stdout (default is hex)"))
        .arg(Arg::with_name("keyfile")
            .long("kf")
            .takes_value(true)
            .help("Read the AES key from file"))
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
            .help("Flag specifies whether the input should be padded/unpadded"))
        .arg(Arg::with_name("test")
            .short("t")
            .long("test")
            .help("Test the encryption/decryption algorithm")).get_matches();

    //Get test flag
    let test = matches.occurrences_of("test") > 0;
    if test == true {
        aes::run_test();
        std::process::exit(0);
    }

    //Get arguments
    let key_string = matches.value_of("key").unwrap_or("");
    let key_file = matches.value_of("keyfile").unwrap_or("");
    let generate = matches.occurrences_of("generate") > 0;
    let input_string = matches.value_of("input").unwrap_or("");
    let in_file_name = matches.value_of("file").unwrap_or("");
    let out_file_name = matches.value_of("output").unwrap_or("");
    let use_padding = matches.occurrences_of("padding") > 0;
    let decrypt = matches.occurrences_of("decrypt") > 0;
    let raw = matches.occurrences_of("raw") > 0;
    let encrypt = !decrypt;

    //Get key
    let key_bytes = get_key_bytes(key_string, key_file, generate);

    //Get input bytes
    let mut input_bytes:Vec<u8>;

    if input_string != "" {
        input_bytes = hex::decode(input_string).expect("Decoding input failed");
    }
    else if in_file_name != "" {
        input_bytes = read(in_file_name).expect("Failed to read");
    } else {
        let mut reader = stdin();
        let mut string : String = "".to_string();
        reader.read_line(&mut string).ok().expect("Failed to read");
        string.pop();

        if raw == false {
            if string.len() % 2 == 1 {
                eprintln!("Invalid input string");
                assert!(string.len() % 2==0);
            }
            input_bytes = hex::decode(string).expect("Decoding input failed");
        }
        else {
            input_bytes = string.as_bytes().to_vec();
        }
    }
    //Pad if the flag is set, PKCS#7 padding for 16 byte blocks
    if use_padding == true && decrypt == false {
        let pad_byte : u8 = (16 - input_bytes.len() % 16) as u8;
        for i in 0..pad_byte {
            input_bytes.push(pad_byte);
        }
    }

    //Assert length of input % 16 == 0
    assert!(input_bytes.len() % 16 == 0);

    //
    let mut output_bytes:Vec<u8>;

    //Instantiate the AES algorithm
    let aes: aes::AES128 = aes::AES128::new(&key_bytes);

    //Encrypt/Decrypt the input
    if encrypt == true {
        output_bytes = (aes.encrypt)(&aes, &input_bytes);
    } else { 
        //Decrypt
        panic!("TODO: implement decryption");

        //
        if use_padding == true {
            panic!("TODO: implement unpadding");
            // If we can't unpad, just send a warning
            eprintln!("Warning! The data could not be unpadded");
        }
    }

    //Save the output to file/stdout;
    if out_file_name != "" {
        write_output_file(&output_bytes, out_file_name);
    } else {
        if raw == true {
            stdout().write_all(&output_bytes);
        } else {
            println!("{}", hex::encode(output_bytes));
        }
    }

    //Done!
}
