use guardian_core::Obfuscator;

// virtualization of code that is in between a call of function like begin_virtualization and end_virtualization
// which are imported from a stub dll, the code is virtualized, a machine is created from the virtual code and the
// original code segment is replaced by the vmentry of the machine

fn main() {
   let mut obfuscator = Obfuscator::new(
      "../hello_world/target/release/hello_world.exe".to_string(),
      "../hello_world/target/release/hello_world_modded.exe".to_string()
   ).unwrap().with_map_file("../hello_world/target/release/hello_world.map".to_string());
   obfuscator.add_functions( vec!["hello_world::calc".to_string()]).unwrap();

   obfuscator.virtualize();
}
