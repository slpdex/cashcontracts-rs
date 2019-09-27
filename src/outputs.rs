use crate::address::Address;
use crate::unsigned_tx::{Output, PreImage};
use crate::tx::TxOutput;
use crate::script::{Script, Op, OpCodeType};
use crate::hash::hash160;

use byteorder::{BigEndian, WriteBytesExt};

#[derive(Clone, Debug)]
pub struct P2PKHOutput {
    pub value: u64,
    pub address: Address,
}

pub struct P2SHOutput {
    pub output: Box<dyn Output>,
}

#[derive(Clone, Debug)]
pub struct OpReturnOutput {
    pub pushes: Vec<Vec<u8>>,
    pub is_minimal_push: bool,
}

#[derive(Clone, Debug)]
pub struct SLPSend {
    pub token_type: u8,
    pub token_id: [u8; 32],
    pub output_quantities: Vec<u64>,
}


impl Output for P2PKHOutput {
    fn value(&self) -> u64 {
        self.value
    }

    fn script(&self) -> Script {
        Script::new(vec![
            Op::Code(OpCodeType::OpDup),
            Op::Code(OpCodeType::OpHash160),
            Op::Push(self.address.bytes().to_vec()),
            Op::Code(OpCodeType::OpEqualVerify),
            Op::Code(OpCodeType::OpCheckSig),
        ])
    }

    fn script_code(&self) -> Script {
        self.script()
    }

    fn sig_script(&self,
                  serialized_sig: Vec<u8>,
                  serialized_pub_key: Vec<u8>,
                  _pre_image: &PreImage,
                  _outputs: &[TxOutput]) -> Script {
        Script::new(vec![
            Op::Push(serialized_sig),
            Op::Push(serialized_pub_key),
        ])
    }
}

impl Output for P2SHOutput {
    fn value(&self) -> u64 {
        self.output.value()
    }

    fn script(&self) -> Script {
        Script::new(vec![
            Op::Code(OpCodeType::OpHash160),
            Op::Push(hash160(&self.output.script().to_vec()).to_vec()),
            Op::Code(OpCodeType::OpEqual),
        ])
    }

    fn script_code(&self) -> Script {
        self.output.script()
    }

    fn sig_script(&self,
                  serialized_sig: Vec<u8>,
                  serialized_pub_key: Vec<u8>,
                  pre_image: &PreImage,
                  outputs: &[TxOutput]) -> Script {
        let mut script = self.output.sig_script(serialized_sig, serialized_pub_key,
                                                pre_image, outputs);
        script.add_op(Op::Push(self.output.script().to_vec()));
        script
    }
}

impl Output for OpReturnOutput {
    fn value(&self) -> u64 {
        0
    }

    fn script(&self) -> Script {
        let mut script_ops = vec![
            Op::Code(OpCodeType::OpReturn),
        ];
        script_ops.extend(self.pushes.iter().cloned().map(Op::Push));
        if self.is_minimal_push {
            Script::new(script_ops)
        } else {
            Script::new_non_minimal_push(script_ops)
        }
    }

    fn script_code(&self) -> Script {
        panic!("Tried signing an OP_RETURN output, which is impossible to spend.")
    }

    fn sig_script(&self, _: Vec<u8>, _: Vec<u8>, _: &PreImage, _: &[TxOutput]) -> Script {
        panic!("Tried signing an OP_RETURN output, which is impossible to spend.")
    }
}


impl SLPSend {
    /* From the spec:
     * OP_RETURN
     * <lokad id: 'SLP\x00'> (4 bytes, ascii)
     * <token_type: 1> (1 to 2 byte integer)
     * <transaction_type: 'SEND'> (4 bytes, ascii)
     * <token_id> (32 bytes)
     * <token_output_quantity1> (required, 8 byte integer)
     * <token_output_quantity2> (optional, 8 byte integer)
     * ...
     * <token_output_quantity19> (optional, 8 byte integer) */

    pub fn into_output(self) -> OpReturnOutput {
        let mut script_ops = vec![
            b"SLP\0".to_vec(),
            vec![self.token_type],
            b"SEND".to_vec(),
            self.token_id.to_vec(),
        ];
        script_ops.extend(self.output_quantities.iter().map(|quantity| {
            let mut data = Vec::new();
            data.write_u64::<BigEndian>(*quantity).unwrap();
            data
        }));
        OpReturnOutput {
            is_minimal_push: false,
            pushes: script_ops,
        }
    }
}
