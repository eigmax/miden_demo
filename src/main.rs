use anyhow::Result;
use clap::Clap;
use miden::{Program, ProgramInputs, ProofOptions, StarkProof};
use miden_assembly::Assembler;
use std::time::Instant;

#[derive(Debug, Clap)]
pub struct ExampleOptions {
    //#[clap(short = "n", default_value = "1024")]
    //sequence_length: usize,
    #[clap(short = "s", long = "security", default_value = "96bits")]
    security: String,
    #[clap(short = "f", default_value = "0")]
    flag: u64,
}

pub fn get_example(flag: usize) -> Example {
    // convert flag to a field element
    let flag = flag as u64;

    // determine the expected result
    let expected_result = match flag {
        0 => 15u64,
        1 => 8u64,
        _ => panic!("flag must be a binary value"),
    };

    let assembler = Assembler::new(true); //debug mode
                                          // construct the program which either adds or multiplies two numbers
                                          // based on the value provided via secret inputs
    let program = assembler
        .compile(
            "
    begin
        push.3
        push.5
        push.1
        push.10
        gte
        if.true
            add
        else
            mul
        end
        # keep stack size to 16
        swap
        drop
    end",
        )
        .unwrap();

    println!(
        "Generated a program to test conditional execution; expected result: {} for {}",
        expected_result, program,
    );

    Example {
        program,
        inputs: ProgramInputs::new(&[], &[flag], vec![]).unwrap(),
        pub_inputs: vec![],
        expected_result: vec![expected_result],
        num_outputs: 1,
    }
}

pub struct Example {
    pub program: Program,
    pub inputs: ProgramInputs,
    pub pub_inputs: Vec<u64>,
    pub num_outputs: usize,
    pub expected_result: Vec<u64>,
}

impl ExampleOptions {
    pub fn get_proof_options(&self) -> ProofOptions {
        match self.security.as_str() {
            "96bits" => ProofOptions::with_96_bit_security(),
            "128bits" => ProofOptions::with_128_bit_security(),
            other => panic!("{} is not a valid security level", other),
        }
    }

    pub fn execute(&self) -> Result<()> {
        println!("============================================================");

        let proof_options = self.get_proof_options();

        let Example {
            program,
            inputs,
            num_outputs,
            pub_inputs,
            expected_result,
        } = get_example(self.flag as usize);
        println!("--------------------------------");

        // debug
        let trace = miden::execute(&program, &ProgramInputs::new(&[], &[self.flag], vec![]).unwrap()).unwrap();
        for vm_state in miden::execute_iter(&program, &ProgramInputs::new(&[], &[self.flag], vec![]).unwrap()) {
            match vm_state {
                Ok(vm_state) => println!("{:?}", vm_state),
                Err(_) => println!("something went terribly wrong!"),
            }
        }

        // execute the program and generate the proof of execution
        let now = Instant::now();
        let (outputs, proof) =
            miden::prove(&program, &inputs, num_outputs, &proof_options).unwrap();
        println!("--------------------------------");

        println!(
            "Executed program in {} ms",
            //hex::encode(program.hash()), // TODO: include into message
            now.elapsed().as_millis()
        );
        println!("Program output: {:?}", outputs);
        assert_eq!(
            expected_result, outputs,
            "Program result was computed incorrectly"
        );

        // serialize the proof to see how big it is
        let proof_bytes = proof.to_bytes();
        println!("Execution proof size: {} KB", proof_bytes.len() / 1024);
        println!(
            "Execution proof security: {} bits",
            proof.security_level(true)
        );
        println!("--------------------------------");

        // verify that executing a program with a given hash and given inputs
        // results in the expected output
        let proof = StarkProof::from_bytes(&proof_bytes).unwrap();
        let now = Instant::now();
        match miden::verify(program.hash(), &pub_inputs, &outputs, proof) {
            Ok(_) => println!("Execution verified in {} ms", now.elapsed().as_millis()),
            Err(err) => println!("Failed to verify execution: {}", err),
        }

        Ok(())
    }
}

fn basic_example() {
    //let args = ExampleOptions::parse();
    //args.execute().unwrap();
    // instantiate the assembler
    let assembler = Assembler::default();

    // this is our program, we compile it from assembly code
    let program = assembler.compile("begin push.3 push.5 add swap drop end").unwrap();

    // let's execute it and generate a STARK proof
    let (outputs, proof) = miden::prove(
        &program,
        &ProgramInputs::none(),   // we won't provide any inputs
        1,                        // we'll return one item from the stack
        &ProofOptions::default(), // we'll be using default options
    )
    .unwrap();

    // the output should be 8
    assert_eq!(vec![8], outputs);
}

fn main() {
    //basic_example();

    let example_opts = ExampleOptions::parse();
    example_opts.execute().unwrap();
}
