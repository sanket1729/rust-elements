// A sample interpreter for elements Script
// Easier for debuggin
// Does not attempt to save execution stack because 
// of nested Ifs as it not necessary


use bitcoin::Script;
use bitcoin::blockdata::script::{read_scriptint, read_scriptbool, Instruction};
use bitcoin::blockdata::opcodes::all::*;
use bitcoin::hashes::sha256;
use bitcoin::hashes::Hash;

use std::io;

#[derive(Debug, Clone)]
struct State{
    stack: Vec<Vec<u8>>,
    alt_stack: Vec<Vec<u8>>, 
}

/// Helper to encode an integer in script format
fn build_scriptint(n: i64) -> Vec<u8> {
    if n == 0 { return vec![] }

    let neg = n < 0;

    let mut abs = if neg { -n } else { n } as usize;
    let mut v = vec![];
    while abs > 0xFF {
        v.push((abs & 0xFF) as u8);
        abs >>= 8;
    }
    // If the number's value causes the sign bit to be set, we need an extra
    // byte to get the correct value and correct sign bit
    if abs & 0x80 != 0 {
        v.push(abs as u8);
        v.push(if neg { 0x80u8 } else { 0u8 });
    }
    // Otherwise we just set the sign bit ourselves
    else {
        abs |= if neg { 0x80 } else { 0 };
        v.push(abs as u8);
    }
    v
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub enum Context{
    IfContext,
    NotIfContext,
    ElseContext,
    NoContext,
}

impl State{

    pub fn init_witness(witness: Vec<Vec<u8>>) -> Self{
        Self{
            stack: witness,
            alt_stack: vec![], 
        }
    }

    pub fn step(&mut self, ins: Instruction, ctx: &mut Context){
        
        if *ctx == Context::NotIfContext{
            match ins.clone(){
                Instruction::Op(OP_ELSE) | 
                Instruction::Op(OP_ENDIF) => {},
                _ => return
            }
        }
        match ins {
            // Push a bunch of data
            Instruction::PushBytes(data) => self.stack.push(Vec::from(data)),
            /// Some non-push opcode
            Instruction::Op(op) => {
                match op{
                    OP_CAT => {
                        let a = self.stack.pop().expect("OP_CAT pop error");
                        let mut b = self.stack.pop().expect("OP_CAT pop error");
                        b.extend(a);
                        self.stack.push(b);
                    },
                    OP_OVER => {
                        let a = self.stack[self.stack.len() - 2].clone();
                        self.stack.push(a);
                    }
                    OP_SHA256 => {
                        let a = self.stack.pop().expect("SHA2 pop");
                        self.stack.push(Vec::from(sha256::Hash::hash(&a).into_inner()))
                    }
                    OP_PICK => {
                        let n = read_scriptint(&self.stack.pop().unwrap()).unwrap() as usize;
                        let elem = self.stack[self.stack.len() - 1 - n ].clone();
                        self.stack.push(elem);
                    }
                    OP_CHECKSIGVERIFY | OP_2DROP => {
                        self.stack.pop().unwrap();
                        self.stack.pop().unwrap();
                    }
                    OP_CHECKSIGFROMSTACKVERIFY =>{
                        self.stack.pop().unwrap();
                        self.stack.pop().unwrap();
                        self.stack.pop().unwrap();
                    }
                    OP_RIGHT =>{
                        let ind = read_scriptint(&self.stack.pop().unwrap()).unwrap() as usize;
                        let mut elem = self.stack.pop().unwrap();
                        self.stack.push(elem.split_off(ind));
                    }
                    OP_LEFT =>{
                        let ind = read_scriptint(&self.stack.pop().unwrap()).unwrap() as usize;
                        let mut elem = self.stack.pop().unwrap();
                        elem.split_off(ind);
                        self.stack.push(elem);
                    }
                    OP_SUBSTR =>{
                        let size = read_scriptint(&self.stack.pop().unwrap()).unwrap() as usize;
                        let begin = read_scriptint(&self.stack.pop().unwrap()).unwrap() as usize;
                        let mut elem = self.stack.pop().unwrap();
                        elem.drain(begin..(begin+size));
                        self.stack.push(elem);
                    }
                    OP_DUP => {
                        let a = self.stack.pop().unwrap();
                        self.stack.push(a.clone());
                        self.stack.push(a);
                    }
                    OP_2DUP =>{
                        let a = self.stack.pop().unwrap();
                        let b = self.stack.pop().unwrap();
                        self.stack.push(b.clone());
                        self.stack.push(a.clone());
                        self.stack.push(b);
                        self.stack.push(a);
                    }
                    OP_3DUP =>{
                        let a = self.stack.pop().unwrap();
                        let b = self.stack.pop().unwrap();
                        let c = self.stack.pop().unwrap();
                        self.stack.push(c.clone());
                        self.stack.push(b.clone());
                        self.stack.push(a.clone());
                        self.stack.push(c);
                        self.stack.push(b);
                        self.stack.push(a);
                    }
                    OP_TOALTSTACK=>{
                        self.alt_stack.push(self.stack.pop().unwrap());
                    }
                    OP_FROMALTSTACK=>{
                        self.stack.push(self.alt_stack.pop().unwrap());
                    }
                    OP_SWAP => {
                        let l = self.stack.len();
                        self.stack.swap(l - 1, l -2);
                    }
                    OP_DROP =>{
                        self.stack.pop().unwrap();
                    }
                    OP_SIZE => {
                        self.stack.push(build_scriptint(self.stack.last().unwrap().len() as i64));
                    }
                    OP_EQUAL =>{
                        let a = self.stack.pop().unwrap();
                        let b = self.stack.pop().unwrap();
                        self.stack.push(vec![(a == b) as u8]);
                    }
                    OP_EQUALVERIFY =>{
                        let a = self.stack.pop().unwrap();
                        let b = self.stack.pop().unwrap();
                        assert!(a == b)
                    }
                    OP_2SWAP => {
                        let l = self.stack.len();
                        self.stack.swap(l - 1, l -3);
                        self.stack.swap(l - 2, l -4);
                    }
                    OP_NIP => {
                        let l = self.stack.len();
                        self.stack.remove(l-2);
                    }
                    OP_ROT => {
                        let l = self.stack.len();
                        let elem = self.stack.remove(l-3);
                        self.stack.push(elem);
                    }
                    OP_IF => {
                        let cond = read_scriptbool(&self.stack.pop().unwrap());
                        if cond{
                            *ctx = Context::IfContext;
                        } else{
                            *ctx = Context::NotIfContext;
                        }
                    }
                    OP_ELSE => {
                        assert!(*ctx == Context::NotIfContext);
                        *ctx = Context::ElseContext;
                    }
                    OP_ENDIF => {
                        assert!(*ctx == Context::NotIfContext || *ctx == Context::ElseContext);
                        *ctx = Context::NoContext;
                    }
                    x => {
                        panic!("invalid op-code: {}", x);
                    }
                }
            }
            Instruction::Error(..) => panic!("Error in script execution")
            }
        }

    pub fn execute_script(&mut self, script: Script){
        let mut ctx = Context::NoContext;
        for ins in script.iter(true){
            self.step(ins, &mut ctx);

            let mut input = String::new();
            println!("Type y for step; n for exit");
            match io::stdin().read_line(&mut input) {
                Ok(_n) => {
                    if input == "y" {
                        continue;
                    } else{
                        break
                    }
                }
                Err(error) => println!("error: {}", error),
            }
        }
    }
}