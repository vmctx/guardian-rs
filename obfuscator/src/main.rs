use std::path::PathBuf;
use obfuscator::virtualize_file;

mod diassembler;
mod pe;
mod virt;

// virtualization of code that is in between a call of function like begin_virtualization and end_virtualization
// which are imported from a stub dll, the code is virtualized, a machine is created from the virtual code and the
// original code segment is replaced by the vmentry of the machine


fn main() {
   virtualize_file(
      "../hello_world/target/release/hello_world.exe",
      "../hello_world/target/release/hello_world.map",
      "../hello_world/target/release/hello_world_modded.exe",
      vec!["hello_world::calc".to_string()]
   )
}
