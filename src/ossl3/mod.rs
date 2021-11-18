compile_error!("Ossl3 is not yet done");

use crate::{KdfArgument, KdfError};

pub(crate) fn perform<'a>(
    type_: crate::KdfType,
    args: &[&'a KdfArgument],
    length: usize,
) -> Result<Vec<u8>, KdfError> {
    todo!();
}
