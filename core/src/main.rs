use std::env::current_dir;
use guardian::Obfuscator;
use clap::Parser;
use clap_derive::Parser;


/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
   /// Name of the person to greet
   #[arg(short, long)]
   r#in: String,
   #[arg(short, long)]
   out: String,
   #[arg(short, long)]
   map_file: String,
   #[clap(value_parser, num_args = 1.., value_delimiter = ',')]
   functions: Vec<String>,
}

fn main() {
   let args = Args::parse();
   assert!(!args.functions.is_empty());
   println!("{:?}", current_dir().unwrap());
   let mut obfuscator = Obfuscator::new(
      args.r#in,
      args.out
   ).unwrap().with_map_file(args.map_file);
   obfuscator.add_functions( args.functions).unwrap();

   obfuscator.virtualize();
}
// virtualization of code that is in between a call of function like begin_virtualization and end_virtualization
// which are imported from a stub dll, the code is virtualized, a machine is created from the virtual code and the
// original code segment is replaced by the vmentry of the machine
