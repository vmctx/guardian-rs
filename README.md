[![Rust](https://github.com/felix-rs/guardian-rs/actions/workflows/test_vm.yml/badge.svg)](https://github.com/felix-rs/guardian-rs/actions/workflows/test_vm.yml)

# guardian-rs
This is my x86-64 code virtualizer I decided to open-source, although work will continue mostly on a private version, im open to [contributions and questions](#contributing)!

32-bit support probably soon :3

### Obfuscator Features
- Virtualization of functions within a binary given a .map file
- Embeds .text section of VM into target binary
- Easily extendable set of supported instructions

### Vm Features
- Relocation and execution of any not supported instruction via vmexit and reenter.
- Direct threaded (optional, 'threaded' feature)
- Preserves GPRs, RFlags and XMM registers
- Stack Based using dynamically allocated Virtual Stack
- Seperate CPU stack to prevent stack corruption
- Conditional Jumps (although incomplete)
- Manual calculation of RFLAGs (instead of pushfq)
- Builds as PIE (position independent executeable)

Known Issues:
- Need to fix relocations for Dlls

## Project Overview

### Project Structure

The project is organized into three main components:

1. **Obfuscator**: The obfuscator is responsible for lifting x86-64 instructions and integrating the VM. It employs various techniques to obscure the code and enhance the overall security of the virtualized environment. Additionally, the obfuscator patches targeted functions with a redirect to the VM entry, ensuring seamless execution.

2. **VM (Virtual Machine)**: The VM crate is the core of the virtualization process. It interprets and executes the virtualized x86-64 code.

3. **VM-Build**: This crate is used to compile and test the virtual machine.

## Getting Started

To build and run the project, we use `cargo make`, a task runner and build tool for Rust projects. Make sure you have Rust and Cargo installed on your system before proceeding.

### Install [rust](https://www.rust-lang.org/tools/install)

To start using Rust, [download the installer](https://www.rust-lang.org/tools/install), then run the program and follow the onscreen instructions. You may need to install the [Visual Studio C++ Build tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) when prompted to do so.


### Install and change to [rust nightly](https://rust-lang.github.io/rustup/concepts/channels.html)

Execute the following commands to install the nightly version of Rust:

```powershell
rustup toolchain install nightly
```

### Installation of [cargo-make](https://github.com/sagiegurari/cargo-make)
In order to install, just run the following command

```sh
cargo install --force cargo-make
```

This will install cargo-make in your `~/.cargo/bin`.<br>
Make sure to add `~/.cargo/bin` directory to your `PATH` variable.<br>

### Build Steps

1. Clone the repository:
   ```bash
   git clone https://github.com/felix-rs/guardian-rs.git
   ```

2. Navigate to the project directory:
   ```bash
   cd guardian-rs
   ```

3. Run the build tasks using Cargo Make:
   ```bash
   cargo make build
   ```

4. Run tests to verify everything works as it should:
   ```bash
   cargo make test
   ```
5. To compile the vm as position independent dll (all code in .text section)
   ```bash
   cargo make vm
   ```

### Usage

```console
> guardian --help
Virtualize x86 PE files

Usage: guardian.exe --in <IN> --out <OUT> --map-file <MAP_FILE> [FUNCTIONS]...

Arguments:
  [FUNCTIONS]...  Array of functions names (demangled) to virtualize

Options:
  -i, --in <IN>              Path to the input file
  -o, --out <OUT>            Path to output destination
  -m, --map-file <MAP_FILE>  Path to .map file
  -h, --help                 Print help
  -V, --version              Print version
```

## Contributing

If you're interested in improving the project feel free to create a PR
and if you have any questions u can contact me on discord [@felixfem](https://discordapp.com/users/660564083355156504)

## Credits
- [cursey/x64-virtualizer-rs](https://github.com/cursey/x64-virtualizer-rs)
for the awesome help and repo this project is based on ^-^
- [unknowntrojan/mapparse](https://github.com/unknowntrojan/mapparse) for his .map file parser
- [johannst/juicebox-asm](https://github.com/johannst/juicebox-asm/tree/main) for their jit assembler

## License

This project is licensed under the [GPL-3.0 License](LICENSE).
