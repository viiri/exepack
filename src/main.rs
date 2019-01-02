extern crate getopts;

use std::env;
use std::error::Error;
use std::io::{self, Write};
use std::process;

fn print_usage<W: Write>(w: &mut W, opts: getopts::Options) -> io::Result<()> {
    let brief = format!("\
Usage: {} [OPTION]... INPUT.EXE OUTPUT.EXE\n\
Compress or decompress a DOS executable with EXEPACK.",
        env::args().next().unwrap());
    write!(w, "{}", opts.usage(&brief))
}

fn main_sub() -> Result<(), Box<Error>> {
    let mut opts = getopts::Options::new();
    opts.optflag("d", "decompress", "decompress");
    opts.optflag("h", "help", "show this help");
    let matches = opts.parse(env::args().skip(1))?;

    if matches.opt_present("h") {
        print_usage(&mut io::stdout(), opts)?;
        return Ok(())
    }

    if matches.free.len() != 2 {
        print_usage(&mut io::stderr(), opts)?;
        return Err(From::from("\nerror: Need INPUT.EXE and OUTPUT.EXE arguments"));
    }
    let input_filename = &matches.free[0];
    let output_filename = &matches.free[1];

    if matches.opt_present("d") {
        unimplemented!("decompress");
    } else {
        unimplemented!("compress");
    }
}

fn main() {
    if let Err(err) = main_sub() {
        eprintln!("{}", err);
        process::exit(1);
    }
}
