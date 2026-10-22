use crate::common::raw_structures::RAW_UNWIND_CODE;
use pers::pe::{UnwindCode, UnwindOpType};

#[test]
fn unwind_code_constructor_works_test() {
    let c = UnwindCode::parse(RAW_UNWIND_CODE, 2).unwrap();

    assert_eq!(0x11, c.code_offset);
    assert_eq!(UnwindOpType::AllocSmall, c.unwind_op);
    assert_eq!(0x3, c.op_info);
    assert_eq!(Some(0x5544), c.frame_offset);
}
