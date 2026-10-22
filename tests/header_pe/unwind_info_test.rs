use crate::common::raw_structures::RAW_UNWIND_INFO;
use pers::pe::{UnwindInfo, UnwindOpType};

#[test]
fn unwind_info_constructor_works_test() {
    let u = UnwindInfo::parse(RAW_UNWIND_INFO, 2).unwrap();
    assert_eq!(0x12, u.version);
    assert_eq!(0x1, u.flags);
    assert_eq!(0x33, u.size_of_prolog);
    assert_eq!(0x5, u.frame_register);
    assert_eq!(0x6, u.frame_offset);

    assert_eq!(1, u.unwind_codes.len());
    assert_eq!(0x77, u.unwind_codes[0].code_offset);
    assert_eq!(UnwindOpType::SaveXmm128, u.unwind_codes[0].unwind_op);
    assert_eq!(0x9, u.unwind_codes[0].op_info);

    assert_eq!(Some(0xffeeddcc), u.exception_handler);
}
