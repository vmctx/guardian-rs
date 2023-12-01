use guardian::Obfuscator;
use clap::Parser;
use clap_derive::Parser;


/// Virtualize x86 PE files
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
   /// Path to the input file
   #[arg(short, long)]
   r#in: String,
   /// Path to output destination
   #[arg(short, long)]
   out: String,
   #[arg(short, long)]
   /// Path to .map file
   map_file: String,
   /// Array of functions names (demangled) to virtualize
   #[clap(value_parser, num_args = 1.., value_delimiter = ',')]
   functions: Vec<String>,
}

fn main() {
   let args = Args::parse();
   assert!(!args.functions.is_empty());

   if let Err(error) = run_guardian(args) {
      eprintln!("{}", error);
   }
}

fn run_guardian(args: Args) -> anyhow::Result<()> {
   let mut obfuscator = Obfuscator::new(
      args.r#in,
      args.out
   )?.with_map_file(args.map_file);
   obfuscator.add_functions( args.functions)?;

   obfuscator.virtualize()
}
