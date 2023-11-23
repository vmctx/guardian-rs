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

   if let Err(error) = run_guardian(args) {
      eprintln!("{}", error.to_string());
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
