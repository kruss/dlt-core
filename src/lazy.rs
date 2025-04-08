use crate::parse::{
    add_context, dbg_parsed, dlt_type_info, dlt_variable_name, dlt_variable_name_and_unit,
    dlt_zero_terminated_string_intern, NomByteOrder,
};
use crate::{
    dlt::{
        calculate_standard_header_length, float_width_to_type_length, ControlType, DltTimeStamp,
        Endianness, FixedPoint, FixedPointValue, FloatWidth, MessageType, TypeInfo, TypeInfoKind,
        TypeLength, BIG_ENDIAN_FLAG, EXTENDED_HEADER_LENGTH, STORAGE_HEADER_LENGTH, VERBOSE_FLAG,
        WITH_ECU_ID_FLAG, WITH_EXTENDED_HEADER_FLAG, WITH_SESSION_ID_FLAG, WITH_TIMESTAMP_FLAG,
    },
    parse::DltParseError,
};
use byteorder::{BigEndian, LittleEndian};
use nom::{
    bytes::streaming::{tag, take},
    combinator::map,
    multi::count,
    number::streaming::{be_i8, be_u16, be_u32, be_u8, le_u32},
    sequence::tuple,
    IResult,
};
use std::str;

pub struct StoredMessageSlice<'a> {
    slice: &'a [u8],
}

impl<'a> StoredMessageSlice<'a> {
    pub fn new(slice: &'a [u8]) -> Self {
        StoredMessageSlice { slice }
    }

    pub fn storage_header(&self) -> StorageHeaderSlice {
        StorageHeaderSlice::new(&self.slice[..STORAGE_HEADER_LENGTH as usize])
    }

    pub fn message(&self) -> MessageSlice {
        MessageSlice::new(&self.slice[STORAGE_HEADER_LENGTH as usize..])
    }
}

pub struct StorageHeaderSlice<'a> {
    slice: &'a [u8],
}

impl<'a> StorageHeaderSlice<'a> {
    pub fn new(slice: &'a [u8]) -> Self {
        StorageHeaderSlice { slice }
    }

    #[allow(clippy::useless_conversion)]
    pub fn timestamp(&self) -> Result<DltTimeStamp, DltParseError> {
        let (_, (_, _, seconds, microseconds)) =
            tuple((tag("DLT"), tag(&[0x01]), le_u32, le_u32))(self.slice)
                .map_err(nom::Err::<DltParseError>::from)?;

        Ok(DltTimeStamp {
            seconds,
            microseconds,
        })
    }

    #[allow(clippy::useless_conversion)]
    pub fn ecu_id(&self) -> Result<&str, DltParseError> {
        let offset = 12usize;
        match str::from_utf8(&self.slice[offset..(offset + 4usize)]) {
            Ok(value) => Ok(value),
            Err(error) => Err(DltParseError::ParsingHickup(format!(
                "invalid UTF-8 sequence: {}",
                error
            ))),
        }
    }
}

pub struct MessageSlice<'a> {
    slice: &'a [u8],
}

impl<'a> MessageSlice<'a> {
    pub fn new(slice: &'a [u8]) -> Self {
        MessageSlice { slice }
    }

    pub fn standard_header(&self) -> Result<StandardHeaderSlice, DltParseError> {
        StandardHeaderSlice::new(self.slice)
    }

    pub fn extended_header(&self) -> Result<Option<ExtendedHeaderSlice>, DltParseError> {
        let standard_header = self.standard_header()?;
        if standard_header.with_extended_header()? {
            Ok(Some(ExtendedHeaderSlice::new(
                &self.slice[standard_header.length()? as usize..],
            )?))
        } else {
            Ok(None)
        }
    }

    pub fn payload(&self) -> Result<PayloadContent, DltParseError> {
        let standard_header = self.standard_header()?;
        let mut total_headers_length = standard_header.length()?;

        let (verbose, argument_count, message_type) =
            if let Some(extended_header) = self.extended_header()? {
                total_headers_length += EXTENDED_HEADER_LENGTH;
                (
                    extended_header.verbose()?,
                    extended_header.argument_count()?,
                    Some(extended_header.message_type()?),
                )
            } else {
                (false, 0, None)
            };

        let payload_length = standard_header.message_length()? - total_headers_length;
        let payload_bytes = &self.slice[total_headers_length as usize..];

        let (_, payload) = if standard_header.endianness()? == Endianness::Big {
            dlt_payload::<BigEndian>(
                payload_bytes,
                verbose,
                payload_length,
                argument_count,
                message_type,
            )?
        } else {
            dlt_payload::<LittleEndian>(
                payload_bytes,
                verbose,
                payload_length,
                argument_count,
                message_type,
            )?
        };

        Ok(payload)
    }
}

pub struct StandardHeaderSlice<'a> {
    header_type_byte: u8,
    slice: &'a [u8],
}

impl<'a> StandardHeaderSlice<'a> {
    #[allow(clippy::useless_conversion)]
    pub fn new(slice: &'a [u8]) -> Result<Self, DltParseError> {
        let (_, header_type_byte) = be_u8(slice).map_err(nom::Err::<DltParseError>::from)?;
        Ok(StandardHeaderSlice {
            header_type_byte,
            slice,
        })
    }

    fn length(&self) -> Result<u16, DltParseError> {
        Ok(calculate_standard_header_length(self.header_type_byte))
    }

    pub fn with_extended_header(&self) -> Result<bool, DltParseError> {
        Ok(self.header_type_byte & WITH_EXTENDED_HEADER_FLAG != 0)
    }

    pub fn endianness(&self) -> Result<Endianness, DltParseError> {
        if (self.header_type_byte & BIG_ENDIAN_FLAG) != 0 {
            Ok(Endianness::Big)
        } else {
            Ok(Endianness::Little)
        }
    }

    pub fn with_ecu_id(&self) -> Result<bool, DltParseError> {
        Ok(self.header_type_byte & WITH_ECU_ID_FLAG != 0)
    }

    pub fn with_session_id(&self) -> Result<bool, DltParseError> {
        Ok(self.header_type_byte & WITH_SESSION_ID_FLAG != 0)
    }

    pub fn with_timestamp(&self) -> Result<bool, DltParseError> {
        Ok(self.header_type_byte & WITH_TIMESTAMP_FLAG != 0)
    }

    pub fn version(&self) -> Result<u8, DltParseError> {
        Ok((self.header_type_byte >> 5) & 0b111)
    }

    #[allow(clippy::useless_conversion)]
    pub fn message_counter(&self) -> Result<u8, DltParseError> {
        let (_, value) = be_u8(&self.slice[1usize..]).map_err(nom::Err::<DltParseError>::from)?;
        Ok(value)
    }

    #[allow(clippy::useless_conversion)]
    pub fn message_length(&self) -> Result<u16, DltParseError> {
        let (_, value) = be_u16(&self.slice[2usize..]).map_err(nom::Err::<DltParseError>::from)?;
        Ok(value)
    }

    #[allow(clippy::useless_conversion)]
    pub fn ecu_id(&self) -> Result<Option<&str>, DltParseError> {
        if self.with_ecu_id()? {
            let offset = 4usize;
            match str::from_utf8(&self.slice[offset..(offset + 4usize)]) {
                Ok(value) => Ok(Some(value)),
                Err(error) => Err(DltParseError::ParsingHickup(format!(
                    "invalid UTF-8 sequence: {}",
                    error
                ))),
            }
        } else {
            Ok(None)
        }
    }

    #[allow(clippy::useless_conversion)]
    pub fn session_id(&self) -> Result<Option<&str>, DltParseError> {
        if self.with_session_id()? {
            let mut offset = 4usize;
            if self.with_ecu_id()? {
                offset += 4usize;
            }
            match str::from_utf8(&self.slice[offset..(offset + 4usize)]) {
                Ok(value) => Ok(Some(value)),
                Err(error) => Err(DltParseError::ParsingHickup(format!(
                    "invalid UTF-8 sequence: {}",
                    error
                ))),
            }
        } else {
            Ok(None)
        }
    }

    #[allow(clippy::useless_conversion)]
    pub fn timestamp(&self) -> Result<Option<u32>, DltParseError> {
        if self.with_session_id()? {
            let mut offset = 4usize;
            if self.with_ecu_id()? {
                offset += 4usize;
            }
            if self.with_session_id()? {
                offset += 4usize;
            }
            let (_, value) =
                be_u32(&self.slice[offset..]).map_err(nom::Err::<DltParseError>::from)?;
            Ok(Some(value))
        } else {
            Ok(None)
        }
    }
}

pub struct ExtendedHeaderSlice<'a> {
    message_info_byte: u8,
    slice: &'a [u8],
}

impl<'a> ExtendedHeaderSlice<'a> {
    #[allow(clippy::useless_conversion)]
    pub fn new(slice: &'a [u8]) -> Result<Self, DltParseError> {
        let (_, message_info_byte) = be_u8(slice).map_err(nom::Err::<DltParseError>::from)?;
        Ok(ExtendedHeaderSlice {
            message_info_byte,
            slice,
        })
    }

    pub fn verbose(&self) -> Result<bool, DltParseError> {
        Ok((self.message_info_byte & VERBOSE_FLAG) != 0)
    }

    pub fn message_type(&self) -> Result<MessageType, DltParseError> {
        match MessageType::try_from(self.message_info_byte) {
            Ok(message_type) => Ok(message_type),
            Err(error) => Err(DltParseError::ParsingHickup(format!(
                "invalid message type: {}",
                error
            ))),
        }
    }

    #[allow(clippy::useless_conversion)]
    pub fn argument_count(&self) -> Result<u8, DltParseError> {
        let (_, value) = be_u8(&self.slice[1usize..]).map_err(nom::Err::<DltParseError>::from)?;
        Ok(value)
    }

    #[allow(clippy::useless_conversion)]
    pub fn application_id(&self) -> Result<&str, DltParseError> {
        let offset = 2usize;
        match str::from_utf8(&self.slice[offset..(offset + 4usize)]) {
            Ok(value) => Ok(value),
            Err(error) => Err(DltParseError::ParsingHickup(format!(
                "invalid UTF-8 sequence: {}",
                error
            ))),
        }
    }

    #[allow(clippy::useless_conversion)]
    pub fn context_id(&self) -> Result<&str, DltParseError> {
        let offset = 6usize;
        match str::from_utf8(&self.slice[offset..(offset + 4usize)]) {
            Ok(value) => Ok(value),
            Err(error) => Err(DltParseError::ParsingHickup(format!(
                "invalid UTF-8 sequence: {}",
                error
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum PayloadContent<'a> {
    Verbose(Vec<Argument<'a>>),
    NonVerbose(u32, &'a [u8]), // (message_id, payload)
    ControlMsg(ControlType, &'a [u8]),
    NetworkTrace(Vec<&'a [u8]>),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Argument<'a> {
    pub type_info: TypeInfo,
    pub name: Option<String>,
    pub unit: Option<String>,
    pub fixed_point: Option<FixedPoint>,
    pub value: Value<'a>,
}

#[derive(Debug, PartialEq, Clone)]
pub enum Value<'a> {
    Bool(u8),
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    U128(u128),
    I8(i8),
    I16(i16),
    I32(i32),
    I64(i64),
    I128(i128),
    F32(f32),
    F64(f64),
    StringVal(String),
    Raw(&'a [u8]),
}

fn dlt_payload<T: NomByteOrder>(
    input: &[u8],
    verbose: bool,
    payload_length: u16,
    arg_cnt: u8,
    msg_type: Option<MessageType>,
) -> IResult<&[u8], PayloadContent, DltParseError> {
    if verbose {
        match count(dlt_argument::<T>, arg_cnt as usize)(input) {
            Ok((rest, arguments)) => {
                if let Some(MessageType::NetworkTrace(_)) = msg_type {
                    let slices = arguments
                        .iter()
                        .filter_map(|i| match i.value {
                            Value::Raw(bytes) => Some(bytes),
                            _ => None,
                        })
                        .collect();
                    Ok((rest, PayloadContent::NetworkTrace(slices)))
                } else {
                    Ok((rest, PayloadContent::Verbose(arguments)))
                }
            }
            Err(e) => Err(add_context(
                e,
                format!("Problem parsing {} arguments", arg_cnt),
            )),
        }
    } else if let Some(MessageType::Control(_)) = msg_type {
        if payload_length < 1 {
            return Err(nom::Err::Failure(DltParseError::ParsingHickup(format!(
                "error, payload too short {}",
                payload_length
            ))));
        }
        match tuple((nom::number::complete::be_u8, take(payload_length - 1)))(input) {
            Ok((rest, (control_msg_id, payload))) => Ok((
                rest,
                PayloadContent::ControlMsg(ControlType::from_value(control_msg_id), payload),
            )),
            Err(e) => Err(e),
        }
    } else {
        if payload_length < 4 {
            return Err(nom::Err::Failure(DltParseError::ParsingHickup(format!(
                "error, payload too short {}",
                payload_length
            ))));
        }
        match tuple((T::parse_u32, take(payload_length - 4)))(input) {
            Ok((rest, (message_id, payload))) => {
                Ok((rest, PayloadContent::NonVerbose(message_id, payload)))
            }
            Err(e) => Err(e),
        }
    }
}

fn dlt_argument<T: NomByteOrder>(input: &[u8]) -> IResult<&[u8], Argument, DltParseError> {
    let (i, type_info) = dlt_type_info::<T>(input)?;
    dbg_parsed("type info", input, i, &type_info);
    match type_info.kind {
        TypeInfoKind::Signed(width) => {
            let (before_val, name_unit) = dlt_variable_name_and_unit::<T>(&type_info)(i)?;
            dbg_parsed("name and unit", i, before_val, &name_unit);
            let (rest, value) = dlt_sint::<T>(width)(before_val)?;
            dbg_parsed("sint", before_val, rest, &value);
            Ok((
                rest,
                Argument {
                    name: name_unit.0,
                    unit: name_unit.1,
                    value,
                    fixed_point: None,
                    type_info,
                },
            ))
        }
        TypeInfoKind::SignedFixedPoint(width) => {
            let (before_val, name_unit) = dlt_variable_name_and_unit::<T>(&type_info)(i)?;
            dbg_parsed("name and unit", i, before_val, &name_unit);
            let (r, fp) = dlt_fixed_point::<T>(before_val, width)?;
            let (after_fixed_point, fixed_point) = (r, Some(fp));
            dbg_parsed("fixed_point", before_val, after_fixed_point, &fixed_point);
            let (rest, value) =
                dlt_sint::<T>(float_width_to_type_length(width))(after_fixed_point)?;
            Ok((
                rest,
                Argument {
                    name: name_unit.0,
                    unit: name_unit.1,
                    value,
                    fixed_point,
                    type_info,
                },
            ))
        }
        TypeInfoKind::Unsigned(width) => {
            let (before_val, (name, unit)) = dlt_variable_name_and_unit::<T>(&type_info)(i)?;
            let (rest, value) = dlt_uint::<T>(width)(before_val)?;
            dbg_parsed("unsigned", before_val, rest, &value);
            Ok((
                rest,
                Argument {
                    name,
                    unit,
                    value,
                    fixed_point: None,
                    type_info,
                },
            ))
        }
        TypeInfoKind::UnsignedFixedPoint(width) => {
            let (before_val, (name, unit)) = dlt_variable_name_and_unit::<T>(&type_info)(i)?;
            let (after_fixed_point, fixed_point) = {
                let (r, fp) = dlt_fixed_point::<T>(before_val, width)?;
                (r, Some(fp))
            };
            let (rest, value) =
                dlt_uint::<T>(float_width_to_type_length(width))(after_fixed_point)?;
            Ok((
                rest,
                Argument {
                    type_info,
                    name,
                    unit,
                    fixed_point,
                    value,
                },
            ))
        }
        TypeInfoKind::Float(width) => {
            let (rest, ((name, unit), value)) = tuple((
                dlt_variable_name_and_unit::<T>(&type_info),
                dlt_fint::<T>(width),
            ))(i)?;
            Ok((
                rest,
                Argument {
                    name,
                    unit,
                    value,
                    fixed_point: None,
                    type_info,
                },
            ))
        }
        TypeInfoKind::Raw => {
            let (i2, raw_byte_cnt) = T::parse_u16(i)?;
            let (i3, name) = if type_info.has_variable_info {
                map(dlt_variable_name::<T>, Some)(i2)?
            } else {
                (i2, None)
            };
            let (rest, value) = map(take(raw_byte_cnt), |s: &[u8]| Value::Raw(s))(i3)?;
            Ok((
                rest,
                Argument {
                    name,
                    unit: None,
                    value,
                    fixed_point: None,
                    type_info,
                },
            ))
        }
        TypeInfoKind::Bool => {
            let (after_var_name, name) = if type_info.has_variable_info {
                map(dlt_variable_name::<T>, Some)(i)?
            } else {
                (i, None)
            };
            dbg_parsed("var name", i, after_var_name, &name);
            let (rest, bool_value) = be_u8(after_var_name)?;
            dbg_parsed("bool value", after_var_name, rest, &bool_value);
            Ok((
                rest,
                Argument {
                    type_info,
                    name,
                    unit: None,
                    fixed_point: None,
                    value: Value::Bool(bool_value),
                },
            ))
        }
        TypeInfoKind::StringType => {
            let (i2, size) = T::parse_u16(i)?;
            let (i3, name) = if type_info.has_variable_info {
                map(dlt_variable_name::<T>, Some)(i2)?
            } else {
                (i2, None)
            };
            let (rest, value) = dlt_zero_terminated_string_intern(i3, size as usize)?;
            dbg_parsed("StringType", i3, rest, &value);
            Ok((
                rest,
                Argument {
                    name,
                    unit: None,
                    fixed_point: None,
                    value: Value::StringVal(value.to_string()),
                    type_info,
                },
            ))
        }
    }
}

#[allow(clippy::type_complexity)]
fn dlt_uint<T: NomByteOrder>(
    width: TypeLength,
) -> fn(&[u8]) -> IResult<&[u8], Value, DltParseError> {
    match width {
        TypeLength::BitLength8 => |i| map(be_u8, Value::U8)(i),
        TypeLength::BitLength16 => |i| map(T::parse_u16, Value::U16)(i),
        TypeLength::BitLength32 => |i| map(T::parse_u32, Value::U32)(i),
        TypeLength::BitLength64 => |i| map(T::parse_u64, Value::U64)(i),
        TypeLength::BitLength128 => |i| map(T::parse_u128, Value::U128)(i),
    }
}

fn dlt_fixed_point<T: NomByteOrder>(
    input: &[u8],
    width: FloatWidth,
) -> IResult<&[u8], FixedPoint, DltParseError> {
    let (i, quantization) = T::parse_f32(input)?;
    if width == FloatWidth::Width32 {
        let (rest, offset) = T::parse_i32(i)?;
        Ok((
            rest,
            FixedPoint {
                quantization,
                offset: FixedPointValue::I32(offset),
            },
        ))
    } else if width == FloatWidth::Width64 {
        let (rest, offset) = T::parse_i64(i)?;
        Ok((
            rest,
            FixedPoint {
                quantization,
                offset: FixedPointValue::I64(offset),
            },
        ))
    } else {
        let err_msg = "error in dlt_fixed_point".to_string();
        Err(nom::Err::Error(DltParseError::ParsingHickup(err_msg)))
    }
}

#[allow(clippy::type_complexity)]
fn dlt_fint<T: NomByteOrder>(
    width: FloatWidth,
) -> fn(&[u8]) -> IResult<&[u8], Value, DltParseError> {
    match width {
        FloatWidth::Width32 => |i| map(T::parse_f32, Value::F32)(i),
        FloatWidth::Width64 => |i| map(T::parse_f64, Value::F64)(i),
    }
}

#[allow(clippy::type_complexity)]
fn dlt_sint<T: NomByteOrder>(
    width: TypeLength,
) -> fn(&[u8]) -> IResult<&[u8], Value, DltParseError> {
    match width {
        TypeLength::BitLength8 => |i| map(be_i8, Value::I8)(i),
        TypeLength::BitLength16 => |i| map(T::parse_i16, Value::I16)(i),
        TypeLength::BitLength32 => |i| map(T::parse_i32, Value::I32)(i),
        TypeLength::BitLength64 => |i| map(T::parse_i64, Value::I64)(i),
        TypeLength::BitLength128 => |i| map(T::parse_i128, Value::I128)(i),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dlt::{LogLevel, MessageType, StringCoding, TypeInfoKind};

    #[test]
    fn test_lazy() {
        let slice: Vec<u8> = vec![
            // --------------- storage header
            /* DLT + 0x01 */ 0x44, 0x4C, 0x54,
            0x01, /* timestamp sec */ 0x2B, 0x2C, 0xC9, 0x4D, /* timestamp us */ 0x7A,
            0xE8, 0x01, 0x00, /* ecu id "ECU" */ 0x45, 0x43, 0x55, 0x00,
            // --------------- header
            /* header-type       0b0010 0001 */ 0x21,
            /* extended header        | |||^ */
            /* MSBF: 0  little endian | ||^  */
            /* WEID: 0  no ecu id     | |^   */
            /* WSID: 0  no sess id    | ^    */
            /* WTMS: 0  no timestamp  ^      */
            /* version nummber 1   ^^^       */
            /* message counter = 10 */
            0x0A, /* length = 19 */ 0x00, 0x13,
            // --------------- extended header
            0x41, // MSIN 0b0100 0001 => verbose, MST log, ApplicationTraceType::State
            0x01, // arg count
            0x4C, 0x4F, 0x47, 0x00, // app id LOG
            0x54, 0x45, 0x53, 0x32, // context id TES2
            // --------------- payload
            /* type info 0b0001 0000 => type bool */
            0x10, 0x00, 0x00, 0x00, 0x6F,
        ];

        let stored_message = StoredMessageSlice::new(&slice);

        let storage_header = stored_message.storage_header();
        assert_eq!(
            DltTimeStamp {
                seconds: 1305029675,
                microseconds: 125050,
            },
            storage_header.timestamp().expect("timestamp")
        );
        assert_eq!("ECU\0", storage_header.ecu_id().expect("ecu_id"));

        let message = stored_message.message();

        let standard_header = message.standard_header().expect("standard_header");
        assert_eq!(4, standard_header.length().expect("length"));
        assert!(standard_header
            .with_extended_header()
            .expect("with_extended_header"));
        assert_eq!(
            Endianness::Little,
            standard_header.endianness().expect("endianness")
        );
        assert!(!standard_header.with_ecu_id().expect("with_ecu_id"));
        assert!(!standard_header.with_session_id().expect("with_session_id"));
        assert!(!standard_header.with_timestamp().expect("with_timestamp"));
        assert_eq!(1, standard_header.version().expect("version"));
        assert_eq!(
            10,
            standard_header.message_counter().expect("message_length")
        );
        assert_eq!(
            19,
            standard_header.message_length().expect("message_length")
        );
        assert_eq!(None, standard_header.ecu_id().expect("ecu_id"));
        assert_eq!(None, standard_header.session_id().expect("session_id"));
        assert_eq!(None, standard_header.timestamp().expect("timestamp"));

        if let Some(extended_header) = message.extended_header().expect("extended_header") {
            assert!(extended_header.verbose().expect("verbose"));
            assert_eq!(
                MessageType::Log(LogLevel::Info),
                extended_header.message_type().expect("message_type")
            );
            assert_eq!(1, extended_header.argument_count().expect("argument_count"));
            assert_eq!(
                "LOG\0",
                extended_header.application_id().expect("application_id")
            );
            assert_eq!("TES2", extended_header.context_id().expect("context_id"));
        } else {
            panic!("expected extended_header");
        }

        assert_eq!(
            PayloadContent::Verbose(
                [Argument {
                    type_info: TypeInfo {
                        kind: TypeInfoKind::Bool,
                        coding: StringCoding::ASCII,
                        has_variable_info: false,
                        has_trace_info: false
                    },
                    name: None,
                    unit: None,
                    fixed_point: None,
                    value: Value::Bool(111),
                },]
                .to_vec()
            ),
            message.payload().expect("payload")
        );
    }
}
