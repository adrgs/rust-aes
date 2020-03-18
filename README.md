# rust-aes

```
rust-aes 0.1.0
adrgs github.com/adrgs/rust-aes
A pure Rust implementation of AES 128

USAGE:
    rust-aes [FLAGS] [OPTIONS]

FLAGS:
    -d, --decrypt    Decrypt mode
    -e, --encrypt    (Implicit) Encrypt mode
    -h, --help       Prints help information
    -p, --padding    Flag specifies whether the input should be padded/unpadded
    -V, --version    Prints version information

OPTIONS:
    -f, --file <file>        (Optional) Input file, otherwise input is read from stdin, or from -i option
    -i, --input <input>      (Optional) Encrypt/Decrypt the argument, format: hexadecimal characters, needs to be
                             divisible by 16 if -d flag is present or if -p flag is not present
    -k, --key <key>          The AES key, format: 32 hexadecimal characters
    -o, --output <output>    (Optional) Output file, otherwise output is directed to stdout
```