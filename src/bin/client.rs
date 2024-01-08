use anyhow::{Ok, Result};
use dns_resolver::{resolver::Resolver, rr_types};
use std::{env, process};

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("expected two arguments; specifying the domain name and record_type");
        process::exit(1);
    }

    let domain = args[1].clone();
    let record_type = args[2].clone();
    let rr_type = rr_types::str_to_record_type(&record_type)?;

    let resolver = Resolver::new("0.0.0.0:3400").await?;
    let message = resolver.resolve(domain, &rr_type).await?;
    let ips = message.answers_data(&rr_type);

    println!("answer(s): {:?}", ips);
    Ok(())
}
