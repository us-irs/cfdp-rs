use spacepackets::{
    cfdp::{
        SegmentationControl, TransmissionMode,
        tlv::{GenericTlv, Tlv, TlvType},
    },
    util::UnsignedByteField,
};

#[cfg(feature = "alloc")]
pub use alloc_mod::*;

#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct FilePathTooLarge(pub usize);

/// This trait is an abstraction for different Put Request structures which can be used
/// by Put Request consumers.
pub trait ReadablePutRequest {
    fn destination_id(&self) -> UnsignedByteField;
    fn source_file(&self) -> Option<&str>;
    fn dest_file(&self) -> Option<&str>;
    fn trans_mode(&self) -> Option<TransmissionMode>;
    fn closure_requested(&self) -> Option<bool>;
    fn seg_ctrl(&self) -> Option<SegmentationControl>;

    fn msgs_to_user(&self) -> Option<impl Iterator<Item = Tlv<'_>>>;
    fn fault_handler_overrides(&self) -> Option<impl Iterator<Item = Tlv<'_>>>;
    fn flow_label(&self) -> Option<Tlv<'_>>;
    fn fs_requests(&self) -> Option<impl Iterator<Item = Tlv<'_>>>;
}

#[derive(Debug, PartialEq, Eq)]
pub struct PutRequest<'src_file, 'dest_file, 'msgs_to_user, 'fh_ovrds, 'flow_label, 'fs_requests> {
    pub destination_id: UnsignedByteField,
    source_file: Option<&'src_file str>,
    dest_file: Option<&'dest_file str>,
    pub trans_mode: Option<TransmissionMode>,
    pub closure_requested: Option<bool>,
    pub seg_ctrl: Option<SegmentationControl>,
    pub msgs_to_user: Option<&'msgs_to_user [Tlv<'msgs_to_user>]>,
    pub fault_handler_overrides: Option<&'fh_ovrds [Tlv<'fh_ovrds>]>,
    pub flow_label: Option<Tlv<'flow_label>>,
    pub fs_requests: Option<&'fs_requests [Tlv<'fs_requests>]>,
}

impl<'src_file, 'dest_file, 'msgs_to_user, 'fh_ovrds, 'flow_label, 'fs_requests>
    PutRequest<'src_file, 'dest_file, 'msgs_to_user, 'fh_ovrds, 'flow_label, 'fs_requests>
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        destination_id: UnsignedByteField,
        source_file: Option<&'src_file str>,
        dest_file: Option<&'dest_file str>,
        trans_mode: Option<TransmissionMode>,
        closure_requested: Option<bool>,
        seg_ctrl: Option<SegmentationControl>,
        msgs_to_user: Option<&'msgs_to_user [Tlv<'msgs_to_user>]>,
        fault_handler_overrides: Option<&'fh_ovrds [Tlv<'fh_ovrds>]>,
        flow_label: Option<Tlv<'flow_label>>,
        fs_requests: Option<&'fs_requests [Tlv<'fs_requests>]>,
    ) -> Result<Self, FilePathTooLarge> {
        generic_path_checks(source_file, dest_file)?;
        Ok(Self {
            destination_id,
            source_file,
            dest_file,
            trans_mode,
            closure_requested,
            seg_ctrl,
            msgs_to_user,
            fault_handler_overrides,
            flow_label,
            fs_requests,
        })
    }
}

impl ReadablePutRequest for PutRequest<'_, '_, '_, '_, '_, '_> {
    fn destination_id(&self) -> UnsignedByteField {
        self.destination_id
    }

    fn source_file(&self) -> Option<&str> {
        self.source_file
    }

    fn dest_file(&self) -> Option<&str> {
        self.dest_file
    }

    fn trans_mode(&self) -> Option<TransmissionMode> {
        self.trans_mode
    }

    fn closure_requested(&self) -> Option<bool> {
        self.closure_requested
    }

    fn seg_ctrl(&self) -> Option<SegmentationControl> {
        self.seg_ctrl
    }

    fn msgs_to_user(&self) -> Option<impl Iterator<Item = Tlv<'_>>> {
        if let Some(msgs_to_user) = self.msgs_to_user {
            return Some(msgs_to_user.iter().copied());
        }
        None
    }

    fn fault_handler_overrides(&self) -> Option<impl Iterator<Item = Tlv<'_>>> {
        if let Some(fh_overrides) = self.fault_handler_overrides {
            return Some(fh_overrides.iter().copied());
        }
        None
    }

    fn flow_label(&self) -> Option<Tlv<'_>> {
        self.flow_label
    }

    fn fs_requests(&self) -> Option<impl Iterator<Item = Tlv<'_>>> {
        if let Some(fs_requests) = self.msgs_to_user {
            return Some(fs_requests.iter().copied());
        }
        None
    }
}

pub fn generic_path_checks(
    source_file: Option<&str>,
    dest_file: Option<&str>,
) -> Result<(), FilePathTooLarge> {
    if let Some(src_file) = source_file {
        if src_file.len() > u8::MAX as usize {
            return Err(FilePathTooLarge(src_file.len()));
        }
    }
    if let Some(dest_file) = dest_file {
        if dest_file.len() > u8::MAX as usize {
            return Err(FilePathTooLarge(dest_file.len()));
        }
    }
    Ok(())
}

impl<'src_file, 'dest_file> PutRequest<'src_file, 'dest_file, 'static, 'static, 'static, 'static> {
    pub fn new_regular_request(
        dest_id: UnsignedByteField,
        source_file: &'src_file str,
        dest_file: &'dest_file str,
        trans_mode: Option<TransmissionMode>,
        closure_requested: Option<bool>,
    ) -> Result<Self, FilePathTooLarge> {
        generic_path_checks(Some(source_file), Some(dest_file))?;
        Ok(Self {
            destination_id: dest_id,
            source_file: Some(source_file),
            dest_file: Some(dest_file),
            trans_mode,
            closure_requested,
            seg_ctrl: None,
            msgs_to_user: None,
            fault_handler_overrides: None,
            flow_label: None,
            fs_requests: None,
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TlvWithInvalidType(pub(crate) ());

impl<'msgs_to_user> PutRequest<'static, 'static, 'msgs_to_user, 'static, 'static, 'static> {
    pub fn new_msgs_to_user_only(
        dest_id: UnsignedByteField,
        msgs_to_user: &'msgs_to_user [Tlv<'msgs_to_user>],
    ) -> Result<Self, TlvWithInvalidType> {
        Ok(Self {
            destination_id: dest_id,
            source_file: None,
            dest_file: None,
            trans_mode: None,
            closure_requested: None,
            seg_ctrl: None,
            msgs_to_user: Some(msgs_to_user),
            fault_handler_overrides: None,
            flow_label: None,
            fs_requests: None,
        })
    }

    /// Uses [generic_tlv_list_type_check] to check the TLV type validity of all TLV fields.
    pub fn check_tlv_type_validities(&self) -> bool {
        generic_tlv_list_type_check(self.msgs_to_user, TlvType::MsgToUser);
        if let Some(flow_label) = &self.flow_label {
            if flow_label.tlv_type().is_none() {
                return false;
            }
            if flow_label.tlv_type().unwrap() != TlvType::FlowLabel {
                return false;
            }
        }
        generic_tlv_list_type_check(self.fault_handler_overrides, TlvType::FaultHandler);
        generic_tlv_list_type_check(self.fs_requests, TlvType::FilestoreRequest);
        true
    }
}

pub fn generic_tlv_list_type_check<TlvProvider: GenericTlv>(
    opt_tlvs: Option<&[TlvProvider]>,
    tlv_type: TlvType,
) -> bool {
    if let Some(tlvs) = opt_tlvs {
        for tlv in tlvs {
            if tlv.tlv_type().is_none() {
                return false;
            }
            if tlv.tlv_type().unwrap() != tlv_type {
                return false;
            }
        }
    }
    true
}

#[cfg(feature = "alloc")]
pub mod alloc_mod {
    use core::str::Utf8Error;

    use super::*;
    use alloc::string::ToString;
    use spacepackets::{
        ByteConversionError,
        cfdp::tlv::{ReadableTlv, TlvOwned, WritableTlv, msg_to_user::MsgToUserTlv},
    };

    /// Owned variant of [PutRequest] with no lifetimes which is also [Clone]able.
    #[derive(Debug, Clone, PartialEq, Eq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "defmt", derive(defmt::Format))]
    pub struct PutRequestOwned {
        pub destination_id: UnsignedByteField,
        source_file: Option<alloc::string::String>,
        dest_file: Option<alloc::string::String>,
        pub trans_mode: Option<TransmissionMode>,
        pub closure_requested: Option<bool>,
        pub seg_ctrl: Option<SegmentationControl>,
        pub msgs_to_user: Option<alloc::vec::Vec<TlvOwned>>,
        pub fault_handler_overrides: Option<alloc::vec::Vec<TlvOwned>>,
        pub flow_label: Option<TlvOwned>,
        pub fs_requests: Option<alloc::vec::Vec<TlvOwned>>,
    }

    impl PutRequestOwned {
        pub fn new_regular_request(
            dest_id: UnsignedByteField,
            source_file: &str,
            dest_file: &str,
            trans_mode: Option<TransmissionMode>,
            closure_requested: Option<bool>,
        ) -> Result<Self, FilePathTooLarge> {
            if source_file.len() > u8::MAX as usize {
                return Err(FilePathTooLarge(source_file.len()));
            }
            if dest_file.len() > u8::MAX as usize {
                return Err(FilePathTooLarge(dest_file.len()));
            }
            Ok(Self {
                destination_id: dest_id,
                source_file: Some(source_file.to_string()),
                dest_file: Some(dest_file.to_string()),
                trans_mode,
                closure_requested,
                seg_ctrl: None,
                msgs_to_user: None,
                fault_handler_overrides: None,
                flow_label: None,
                fs_requests: None,
            })
        }

        pub fn new_msgs_to_user_only(
            dest_id: UnsignedByteField,
            msgs_to_user: &[MsgToUserTlv<'_>],
        ) -> Result<Self, TlvWithInvalidType> {
            Ok(Self {
                destination_id: dest_id,
                source_file: None,
                dest_file: None,
                trans_mode: None,
                closure_requested: None,
                seg_ctrl: None,
                msgs_to_user: Some(msgs_to_user.iter().map(|msg| msg.tlv.to_owned()).collect()),
                fault_handler_overrides: None,
                flow_label: None,
                fs_requests: None,
            })
        }

        /// Uses [generic_tlv_list_type_check] to check the TLV type validity of all TLV fields.
        pub fn check_tlv_type_validities(&self) -> bool {
            generic_tlv_list_type_check(self.msgs_to_user.as_deref(), TlvType::MsgToUser);
            if let Some(flow_label) = &self.flow_label {
                if flow_label.tlv_type().is_none() {
                    return false;
                }
                if flow_label.tlv_type().unwrap() != TlvType::FlowLabel {
                    return false;
                }
            }
            generic_tlv_list_type_check(
                self.fault_handler_overrides.as_deref(),
                TlvType::FaultHandler,
            );
            generic_tlv_list_type_check(self.fs_requests.as_deref(), TlvType::FilestoreRequest);
            true
        }
    }

    impl From<PutRequest<'_, '_, '_, '_, '_, '_>> for PutRequestOwned {
        fn from(req: PutRequest<'_, '_, '_, '_, '_, '_>) -> Self {
            Self {
                destination_id: req.destination_id,
                source_file: req.source_file.map(|s| s.into()),
                dest_file: req.dest_file.map(|s| s.into()),
                trans_mode: req.trans_mode,
                closure_requested: req.closure_requested,
                seg_ctrl: req.seg_ctrl,
                msgs_to_user: req
                    .msgs_to_user
                    .map(|msgs_to_user| msgs_to_user.iter().map(|msg| msg.to_owned()).collect()),
                fault_handler_overrides: req
                    .msgs_to_user
                    .map(|fh_overides| fh_overides.iter().map(|msg| msg.to_owned()).collect()),
                flow_label: req
                    .flow_label
                    .map(|flow_label_tlv| flow_label_tlv.to_owned()),
                fs_requests: req
                    .fs_requests
                    .map(|fs_requests| fs_requests.iter().map(|msg| msg.to_owned()).collect()),
            }
        }
    }

    impl ReadablePutRequest for PutRequestOwned {
        fn destination_id(&self) -> UnsignedByteField {
            self.destination_id
        }

        fn source_file(&self) -> Option<&str> {
            self.source_file.as_deref()
        }

        fn dest_file(&self) -> Option<&str> {
            self.dest_file.as_deref()
        }

        fn trans_mode(&self) -> Option<TransmissionMode> {
            self.trans_mode
        }

        fn closure_requested(&self) -> Option<bool> {
            self.closure_requested
        }

        fn seg_ctrl(&self) -> Option<SegmentationControl> {
            self.seg_ctrl
        }

        fn msgs_to_user(&self) -> Option<impl Iterator<Item = Tlv<'_>>> {
            if let Some(msgs_to_user) = &self.msgs_to_user {
                return Some(msgs_to_user.iter().map(|tlv_owned| tlv_owned.as_tlv()));
            }
            None
        }

        fn fault_handler_overrides(&self) -> Option<impl Iterator<Item = Tlv<'_>>> {
            if let Some(fh_overrides) = &self.fault_handler_overrides {
                return Some(fh_overrides.iter().map(|tlv_owned| tlv_owned.as_tlv()));
            }
            None
        }

        fn flow_label(&self) -> Option<Tlv<'_>> {
            self.flow_label.as_ref().map(|tlv| tlv.as_tlv())
        }

        fn fs_requests(&self) -> Option<impl Iterator<Item = Tlv<'_>>> {
            if let Some(requests) = &self.fs_requests {
                return Some(requests.iter().map(|tlv_owned| tlv_owned.as_tlv()));
            }
            None
        }
    }

    pub struct StaticPutRequestFields {
        pub destination_id: UnsignedByteField,
        /// Static buffer to store source file path.
        pub source_file_buf: [u8; u8::MAX as usize],
        /// Current source path length.
        pub source_file_len: usize,
        /// Static buffer to store dest file path.
        pub dest_file_buf: [u8; u8::MAX as usize],
        /// Current destination path length.
        pub dest_file_len: usize,
        pub trans_mode: Option<TransmissionMode>,
        pub closure_requested: Option<bool>,
        pub seg_ctrl: Option<SegmentationControl>,
    }

    impl Default for StaticPutRequestFields {
        fn default() -> Self {
            Self {
                destination_id: UnsignedByteField::new(0, 0),
                source_file_buf: [0; u8::MAX as usize],
                source_file_len: Default::default(),
                dest_file_buf: [0; u8::MAX as usize],
                dest_file_len: Default::default(),
                trans_mode: Default::default(),
                closure_requested: Default::default(),
                seg_ctrl: Default::default(),
            }
        }
    }

    impl StaticPutRequestFields {
        pub fn clear(&mut self) {
            self.destination_id = UnsignedByteField::new(0, 0);
            self.source_file_len = 0;
            self.dest_file_len = 0;
            self.trans_mode = None;
            self.closure_requested = None;
            self.seg_ctrl = None;
        }
    }

    /// This is a put request cache structure which can be used to cache [ReadablePutRequest]s
    /// without requiring run-time allocation. The user must specify the static buffer sizes used
    /// to store TLVs or list of TLVs.
    pub struct StaticPutRequestCacher {
        pub static_fields: StaticPutRequestFields,
        opts_buf: alloc::vec::Vec<u8>,
        opts_len: usize, // fs_request_start_end_pos: Option<(usize, usize)>
    }

    impl StaticPutRequestCacher {
        pub fn new(max_len_opts_buf: usize) -> Self {
            Self {
                static_fields: StaticPutRequestFields::default(),
                opts_buf: alloc::vec![0; max_len_opts_buf],
                opts_len: 0,
            }
        }

        pub fn set(
            &mut self,
            put_request: &impl ReadablePutRequest,
        ) -> Result<(), ByteConversionError> {
            self.static_fields.destination_id = put_request.destination_id();
            if let Some(source_file) = put_request.source_file() {
                if source_file.len() > u8::MAX as usize {
                    return Err(ByteConversionError::ToSliceTooSmall {
                        found: self.static_fields.source_file_buf.len(),
                        expected: source_file.len(),
                    });
                }
                self.static_fields.source_file_buf[..source_file.len()]
                    .copy_from_slice(source_file.as_bytes());
                self.static_fields.source_file_len = source_file.len();
            }
            if let Some(dest_file) = put_request.dest_file() {
                if dest_file.len() > u8::MAX as usize {
                    return Err(ByteConversionError::ToSliceTooSmall {
                        found: self.static_fields.source_file_buf.len(),
                        expected: dest_file.len(),
                    });
                }
                self.static_fields.dest_file_buf[..dest_file.len()]
                    .copy_from_slice(dest_file.as_bytes());
                self.static_fields.dest_file_len = dest_file.len();
            }
            self.static_fields.trans_mode = put_request.trans_mode();
            self.static_fields.closure_requested = put_request.closure_requested();
            self.static_fields.seg_ctrl = put_request.seg_ctrl();
            let mut current_idx = 0;
            let mut store_tlv = |tlv: &Tlv| {
                if current_idx + tlv.len_full() > self.opts_buf.len() {
                    return Err(ByteConversionError::ToSliceTooSmall {
                        found: self.opts_buf.len(),
                        expected: current_idx + tlv.len_full(),
                    });
                }
                // We checked the buffer lengths, so this should never fail.
                tlv.write_to_bytes(&mut self.opts_buf[current_idx..current_idx + tlv.len_full()])
                    .unwrap();
                current_idx += tlv.len_full();
                Ok(())
            };
            if let Some(fs_req) = put_request.fs_requests() {
                for fs_req in fs_req {
                    store_tlv(&fs_req)?;
                }
            }
            if let Some(msgs_to_user) = put_request.msgs_to_user() {
                for msg_to_user in msgs_to_user {
                    store_tlv(&msg_to_user)?;
                }
            }
            self.opts_len = current_idx;
            Ok(())
        }

        pub fn has_source_file(&self) -> bool {
            self.static_fields.source_file_len > 0
        }

        pub fn has_dest_file(&self) -> bool {
            self.static_fields.dest_file_len > 0
        }

        pub fn source_file(&self) -> Result<&str, Utf8Error> {
            core::str::from_utf8(
                &self.static_fields.source_file_buf[0..self.static_fields.source_file_len],
            )
        }

        pub fn dest_file(&self) -> Result<&str, Utf8Error> {
            core::str::from_utf8(
                &self.static_fields.dest_file_buf[0..self.static_fields.dest_file_len],
            )
        }

        pub fn opts_len(&self) -> usize {
            self.opts_len
        }

        pub fn opts_slice(&self) -> &[u8] {
            &self.opts_buf[0..self.opts_len]
        }

        /// This clears the cacher structure. This is a cheap operation because it only
        /// sets [Option]al values to [None] and the length of stores TLVs to 0.
        ///
        /// Please note that this method will not set the values in the buffer to 0.
        pub fn clear(&mut self) {
            self.static_fields.clear();
            self.opts_len = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::string::String;

    use spacepackets::{
        cfdp::tlv::{ReadableTlv, msg_to_user::MsgToUserTlv},
        util::UbfU16,
    };

    use super::*;

    pub const DEST_ID: UbfU16 = UbfU16::new(5);

    #[test]
    fn test_put_request_basic() {
        let src_file = "/tmp/hello.txt";
        let dest_file = "/tmp/hello2.txt";
        let put_request = PutRequest::new(
            DEST_ID.into(),
            Some(src_file),
            Some(dest_file),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        let identical_request =
            PutRequest::new_regular_request(DEST_ID.into(), src_file, dest_file, None, None)
                .unwrap();
        assert_eq!(put_request, identical_request);
    }

    #[test]
    fn test_put_request_path_checks_source_too_long() {
        let mut invalid_path = String::from("/tmp/");
        invalid_path += "a".repeat(u8::MAX as usize).as_str();
        let dest_file = "/tmp/hello2.txt";
        let error =
            PutRequest::new_regular_request(DEST_ID.into(), &invalid_path, dest_file, None, None);
        assert!(error.is_err());
        let error = error.unwrap_err();
        assert_eq!(u8::MAX as usize + 5, error.0);
    }

    #[test]
    fn test_put_request_path_checks_dest_file_too_long() {
        let mut invalid_path = String::from("/tmp/");
        invalid_path += "a".repeat(u8::MAX as usize).as_str();
        let source_file = "/tmp/hello2.txt";
        let error =
            PutRequest::new_regular_request(DEST_ID.into(), source_file, &invalid_path, None, None);
        assert!(error.is_err());
        let error = error.unwrap_err();
        assert_eq!(u8::MAX as usize + 5, error.0);
    }

    #[test]
    fn test_owned_put_request_path_checks_source_too_long() {
        let mut invalid_path = String::from("/tmp/");
        invalid_path += "a".repeat(u8::MAX as usize).as_str();
        let dest_file = "/tmp/hello2.txt";
        let error = PutRequestOwned::new_regular_request(
            DEST_ID.into(),
            &invalid_path,
            dest_file,
            None,
            None,
        );
        assert!(error.is_err());
        let error = error.unwrap_err();
        assert_eq!(u8::MAX as usize + 5, error.0);
    }

    #[test]
    fn test_owned_put_request_path_checks_dest_file_too_long() {
        let mut invalid_path = String::from("/tmp/");
        invalid_path += "a".repeat(u8::MAX as usize).as_str();
        let source_file = "/tmp/hello2.txt";
        let error = PutRequestOwned::new_regular_request(
            DEST_ID.into(),
            source_file,
            &invalid_path,
            None,
            None,
        );
        assert!(error.is_err());
        let error = error.unwrap_err();
        assert_eq!(u8::MAX as usize + 5, error.0);
    }

    #[test]
    fn test_put_request_basic_small_ctor() {
        let src_file = "/tmp/hello.txt";
        let dest_file = "/tmp/hello2.txt";
        let put_request =
            PutRequest::new_regular_request(DEST_ID.into(), src_file, dest_file, None, None)
                .unwrap();
        assert_eq!(put_request.source_file(), Some(src_file));
        assert_eq!(put_request.dest_file(), Some(dest_file));
        assert_eq!(put_request.destination_id(), DEST_ID.into());
        assert_eq!(put_request.seg_ctrl(), None);
        assert_eq!(put_request.closure_requested(), None);
        assert_eq!(put_request.trans_mode(), None);
        assert!(put_request.fs_requests().is_none());
        assert!(put_request.msgs_to_user().is_none());
        assert!(put_request.fault_handler_overrides().is_none());
        assert!(put_request.flow_label().is_none());
    }

    #[test]
    fn test_put_request_owned_basic() {
        let src_file = "/tmp/hello.txt";
        let dest_file = "/tmp/hello2.txt";
        let put_request =
            PutRequestOwned::new_regular_request(DEST_ID.into(), src_file, dest_file, None, None)
                .unwrap();
        assert_eq!(put_request.source_file(), Some(src_file));
        assert_eq!(put_request.dest_file(), Some(dest_file));
        assert_eq!(put_request.destination_id(), DEST_ID.into());
        assert_eq!(put_request.seg_ctrl(), None);
        assert_eq!(put_request.closure_requested(), None);
        assert_eq!(put_request.trans_mode(), None);
        assert!(put_request.flow_label().is_none());
        assert!(put_request.fs_requests().is_none());
        assert!(put_request.msgs_to_user().is_none());
        assert!(put_request.fault_handler_overrides().is_none());
        assert!(put_request.flow_label().is_none());
        let put_request_cloned = put_request.clone();
        assert_eq!(put_request, put_request_cloned);
    }

    #[test]
    fn test_put_request_cacher_basic() {
        let put_request_cached = StaticPutRequestCacher::new(128);
        assert_eq!(put_request_cached.static_fields.source_file_len, 0);
        assert_eq!(put_request_cached.static_fields.dest_file_len, 0);
        assert_eq!(put_request_cached.opts_len(), 0);
        assert_eq!(put_request_cached.opts_slice(), &[]);
    }

    #[test]
    fn test_put_request_cacher_set() {
        let mut put_request_cached = StaticPutRequestCacher::new(128);
        let src_file = "/tmp/hello.txt";
        let dest_file = "/tmp/hello2.txt";
        let put_request =
            PutRequest::new_regular_request(DEST_ID.into(), src_file, dest_file, None, None)
                .unwrap();
        put_request_cached.set(&put_request).unwrap();
        assert_eq!(
            put_request_cached.static_fields.source_file_len,
            src_file.len()
        );
        assert_eq!(
            put_request_cached.static_fields.dest_file_len,
            dest_file.len()
        );
        assert_eq!(put_request_cached.source_file().unwrap(), src_file);
        assert_eq!(put_request_cached.dest_file().unwrap(), dest_file);
        assert_eq!(put_request_cached.opts_len(), 0);
    }

    #[test]
    fn test_put_request_cacher_set_and_clear() {
        let mut put_request_cached = StaticPutRequestCacher::new(128);
        let src_file = "/tmp/hello.txt";
        let dest_file = "/tmp/hello2.txt";
        let put_request =
            PutRequest::new_regular_request(DEST_ID.into(), src_file, dest_file, None, None)
                .unwrap();
        put_request_cached.set(&put_request).unwrap();
        put_request_cached.clear();
        assert_eq!(put_request_cached.static_fields.source_file_len, 0);
        assert_eq!(put_request_cached.static_fields.dest_file_len, 0);
        assert_eq!(put_request_cached.opts_len(), 0);
    }

    #[test]
    fn test_messages_to_user_ctor_owned() {
        let msg_to_user = MsgToUserTlv::new(&[1, 2, 3]).expect("creating message to user failed");
        let put_request = PutRequestOwned::new_msgs_to_user_only(DEST_ID.into(), &[msg_to_user])
            .expect("creating msgs to user only put request failed");
        let msg_to_user_iter = put_request.msgs_to_user();
        assert!(msg_to_user_iter.is_some());
        assert!(put_request.check_tlv_type_validities());
        let msg_to_user_iter = msg_to_user_iter.unwrap();
        for msg_to_user_tlv in msg_to_user_iter {
            assert_eq!(msg_to_user_tlv.value(), msg_to_user.value());
            assert_eq!(msg_to_user_tlv.tlv_type().unwrap(), TlvType::MsgToUser);
        }
    }

    #[test]
    fn test_messages_to_user_ctor() {
        let msg_to_user = MsgToUserTlv::new(&[1, 2, 3]).expect("creating message to user failed");
        let binding = &[msg_to_user.to_tlv()];
        let put_request = PutRequest::new_msgs_to_user_only(DEST_ID.into(), binding)
            .expect("creating msgs to user only put request failed");
        let msg_to_user_iter = put_request.msgs_to_user();
        assert!(put_request.check_tlv_type_validities());
        assert!(msg_to_user_iter.is_some());
        let msg_to_user_iter = msg_to_user_iter.unwrap();
        for msg_to_user_tlv in msg_to_user_iter {
            assert_eq!(msg_to_user_tlv.value(), msg_to_user.value());
            assert_eq!(msg_to_user_tlv.tlv_type().unwrap(), TlvType::MsgToUser);
        }
    }

    #[test]
    fn test_put_request_to_owned() {
        let src_file = "/tmp/hello.txt";
        let dest_file = "/tmp/hello2.txt";
        let put_request =
            PutRequest::new_regular_request(DEST_ID.into(), src_file, dest_file, None, None)
                .unwrap();
        let put_request_owned: PutRequestOwned = put_request.into();
        assert_eq!(put_request_owned.destination_id(), DEST_ID.into());
        assert_eq!(put_request_owned.source_file().unwrap(), src_file);
        assert_eq!(put_request_owned.dest_file().unwrap(), dest_file);
        assert!(put_request_owned.msgs_to_user().is_none());
        assert!(put_request_owned.trans_mode().is_none());
        assert!(put_request_owned.closure_requested().is_none());
    }
}
