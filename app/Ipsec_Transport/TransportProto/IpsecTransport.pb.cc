// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: IpsecTransport.proto

#define INTERNAL_SUPPRESS_PROTOBUF_FIELD_DEPRECATION
#include "IpsecTransport.pb.h"

#include <algorithm>

#include <google/protobuf/stubs/common.h>
#include <google/protobuf/stubs/once.h>
#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/wire_format_lite_inl.h>
#include <google/protobuf/descriptor.h>
#include <google/protobuf/generated_message_reflection.h>
#include <google/protobuf/reflection_ops.h>
#include <google/protobuf/wire_format.h>
// @@protoc_insertion_point(includes)

namespace TT {

namespace {

const ::google::protobuf::Descriptor* IpsecTunnel_descriptor_ = NULL;
const ::google::protobuf::internal::GeneratedMessageReflection*
  IpsecTunnel_reflection_ = NULL;
const ::google::protobuf::EnumDescriptor* IpsecTunnel_TunnelDirection_descriptor_ = NULL;
const ::google::protobuf::Descriptor* IpsecTunnelsContainer_descriptor_ = NULL;
const ::google::protobuf::internal::GeneratedMessageReflection*
  IpsecTunnelsContainer_reflection_ = NULL;

}  // namespace


void protobuf_AssignDesc_IpsecTransport_2eproto() {
  protobuf_AddDesc_IpsecTransport_2eproto();
  const ::google::protobuf::FileDescriptor* file =
    ::google::protobuf::DescriptorPool::generated_pool()->FindFileByName(
      "IpsecTransport.proto");
  GOOGLE_CHECK(file != NULL);
  IpsecTunnel_descriptor_ = file->message_type(0);
  static const int IpsecTunnel_offsets_[6] = {
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(IpsecTunnel, interface_),
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(IpsecTunnel, rsa_),
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(IpsecTunnel, hmac_),
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(IpsecTunnel, key_),
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(IpsecTunnel, algo_),
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(IpsecTunnel, tun_),
  };
  IpsecTunnel_reflection_ =
    new ::google::protobuf::internal::GeneratedMessageReflection(
      IpsecTunnel_descriptor_,
      IpsecTunnel::default_instance_,
      IpsecTunnel_offsets_,
      GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(IpsecTunnel, _has_bits_[0]),
      GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(IpsecTunnel, _unknown_fields_),
      -1,
      ::google::protobuf::DescriptorPool::generated_pool(),
      ::google::protobuf::MessageFactory::generated_factory(),
      sizeof(IpsecTunnel));
  IpsecTunnel_TunnelDirection_descriptor_ = IpsecTunnel_descriptor_->enum_type(0);
  IpsecTunnelsContainer_descriptor_ = file->message_type(1);
  static const int IpsecTunnelsContainer_offsets_[1] = {
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(IpsecTunnelsContainer, ipsec_tunnel_),
  };
  IpsecTunnelsContainer_reflection_ =
    new ::google::protobuf::internal::GeneratedMessageReflection(
      IpsecTunnelsContainer_descriptor_,
      IpsecTunnelsContainer::default_instance_,
      IpsecTunnelsContainer_offsets_,
      GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(IpsecTunnelsContainer, _has_bits_[0]),
      GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(IpsecTunnelsContainer, _unknown_fields_),
      -1,
      ::google::protobuf::DescriptorPool::generated_pool(),
      ::google::protobuf::MessageFactory::generated_factory(),
      sizeof(IpsecTunnelsContainer));
}

namespace {

GOOGLE_PROTOBUF_DECLARE_ONCE(protobuf_AssignDescriptors_once_);
inline void protobuf_AssignDescriptorsOnce() {
  ::google::protobuf::GoogleOnceInit(&protobuf_AssignDescriptors_once_,
                 &protobuf_AssignDesc_IpsecTransport_2eproto);
}

void protobuf_RegisterTypes(const ::std::string&) {
  protobuf_AssignDescriptorsOnce();
  ::google::protobuf::MessageFactory::InternalRegisterGeneratedMessage(
    IpsecTunnel_descriptor_, &IpsecTunnel::default_instance());
  ::google::protobuf::MessageFactory::InternalRegisterGeneratedMessage(
    IpsecTunnelsContainer_descriptor_, &IpsecTunnelsContainer::default_instance());
}

}  // namespace

void protobuf_ShutdownFile_IpsecTransport_2eproto() {
  delete IpsecTunnel::default_instance_;
  delete IpsecTunnel_reflection_;
  delete IpsecTunnelsContainer::default_instance_;
  delete IpsecTunnelsContainer_reflection_;
}

void protobuf_AddDesc_IpsecTransport_2eproto() {
  static bool already_here = false;
  if (already_here) return;
  already_here = true;
  GOOGLE_PROTOBUF_VERIFY_VERSION;

  ::google::protobuf::DescriptorPool::InternalAddGeneratedFile(
    "\n\024IpsecTransport.proto\022\002TT\"\231\001\n\013IpsecTunn"
    "el\022\021\n\tinterface\030\001 \002(\t\022\013\n\003rsa\030\002 \002(\t\022\014\n\004hm"
    "ac\030\003 \001(\t\022\013\n\003key\030\004 \001(\t\022\014\n\004algo\030\005 \001(\t\022\013\n\003t"
    "un\030\006 \001(\t\"4\n\017TunnelDirection\022\010\n\004BOTH\020\000\022\013\n"
    "\007INGRESS\020\001\022\n\n\006EGRESS\020\002\">\n\025IpsecTunnelsCo"
    "ntainer\022%\n\014ipsec_tunnel\030\001 \003(\0132\017.TT.Ipsec"
    "Tunnel", 246);
  ::google::protobuf::MessageFactory::InternalRegisterGeneratedFile(
    "IpsecTransport.proto", &protobuf_RegisterTypes);
  IpsecTunnel::default_instance_ = new IpsecTunnel();
  IpsecTunnelsContainer::default_instance_ = new IpsecTunnelsContainer();
  IpsecTunnel::default_instance_->InitAsDefaultInstance();
  IpsecTunnelsContainer::default_instance_->InitAsDefaultInstance();
  ::google::protobuf::internal::OnShutdown(&protobuf_ShutdownFile_IpsecTransport_2eproto);
}

// Force AddDescriptors() to be called at static initialization time.
struct StaticDescriptorInitializer_IpsecTransport_2eproto {
  StaticDescriptorInitializer_IpsecTransport_2eproto() {
    protobuf_AddDesc_IpsecTransport_2eproto();
  }
} static_descriptor_initializer_IpsecTransport_2eproto_;

// ===================================================================

const ::google::protobuf::EnumDescriptor* IpsecTunnel_TunnelDirection_descriptor() {
  protobuf_AssignDescriptorsOnce();
  return IpsecTunnel_TunnelDirection_descriptor_;
}
bool IpsecTunnel_TunnelDirection_IsValid(int value) {
  switch(value) {
    case 0:
    case 1:
    case 2:
      return true;
    default:
      return false;
  }
}

#ifndef _MSC_VER
const IpsecTunnel_TunnelDirection IpsecTunnel::BOTH;
const IpsecTunnel_TunnelDirection IpsecTunnel::INGRESS;
const IpsecTunnel_TunnelDirection IpsecTunnel::EGRESS;
const IpsecTunnel_TunnelDirection IpsecTunnel::TunnelDirection_MIN;
const IpsecTunnel_TunnelDirection IpsecTunnel::TunnelDirection_MAX;
const int IpsecTunnel::TunnelDirection_ARRAYSIZE;
#endif  // _MSC_VER
#ifndef _MSC_VER
const int IpsecTunnel::kInterfaceFieldNumber;
const int IpsecTunnel::kRsaFieldNumber;
const int IpsecTunnel::kHmacFieldNumber;
const int IpsecTunnel::kKeyFieldNumber;
const int IpsecTunnel::kAlgoFieldNumber;
const int IpsecTunnel::kTunFieldNumber;
#endif  // !_MSC_VER

IpsecTunnel::IpsecTunnel()
  : ::google::protobuf::Message() {
  SharedCtor();
  // @@protoc_insertion_point(constructor:TT.IpsecTunnel)
}

void IpsecTunnel::InitAsDefaultInstance() {
}

IpsecTunnel::IpsecTunnel(const IpsecTunnel& from)
  : ::google::protobuf::Message() {
  SharedCtor();
  MergeFrom(from);
  // @@protoc_insertion_point(copy_constructor:TT.IpsecTunnel)
}

void IpsecTunnel::SharedCtor() {
  ::google::protobuf::internal::GetEmptyString();
  _cached_size_ = 0;
  interface_ = const_cast< ::std::string*>(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
  rsa_ = const_cast< ::std::string*>(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
  hmac_ = const_cast< ::std::string*>(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
  key_ = const_cast< ::std::string*>(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
  algo_ = const_cast< ::std::string*>(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
  tun_ = const_cast< ::std::string*>(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
  ::memset(_has_bits_, 0, sizeof(_has_bits_));
}

IpsecTunnel::~IpsecTunnel() {
  // @@protoc_insertion_point(destructor:TT.IpsecTunnel)
  SharedDtor();
}

void IpsecTunnel::SharedDtor() {
  if (interface_ != &::google::protobuf::internal::GetEmptyStringAlreadyInited()) {
    delete interface_;
  }
  if (rsa_ != &::google::protobuf::internal::GetEmptyStringAlreadyInited()) {
    delete rsa_;
  }
  if (hmac_ != &::google::protobuf::internal::GetEmptyStringAlreadyInited()) {
    delete hmac_;
  }
  if (key_ != &::google::protobuf::internal::GetEmptyStringAlreadyInited()) {
    delete key_;
  }
  if (algo_ != &::google::protobuf::internal::GetEmptyStringAlreadyInited()) {
    delete algo_;
  }
  if (tun_ != &::google::protobuf::internal::GetEmptyStringAlreadyInited()) {
    delete tun_;
  }
  if (this != default_instance_) {
  }
}

void IpsecTunnel::SetCachedSize(int size) const {
  GOOGLE_SAFE_CONCURRENT_WRITES_BEGIN();
  _cached_size_ = size;
  GOOGLE_SAFE_CONCURRENT_WRITES_END();
}
const ::google::protobuf::Descriptor* IpsecTunnel::descriptor() {
  protobuf_AssignDescriptorsOnce();
  return IpsecTunnel_descriptor_;
}

const IpsecTunnel& IpsecTunnel::default_instance() {
  if (default_instance_ == NULL) protobuf_AddDesc_IpsecTransport_2eproto();
  return *default_instance_;
}

IpsecTunnel* IpsecTunnel::default_instance_ = NULL;

IpsecTunnel* IpsecTunnel::New() const {
  return new IpsecTunnel;
}

void IpsecTunnel::Clear() {
  if (_has_bits_[0 / 32] & 63) {
    if (has_interface()) {
      if (interface_ != &::google::protobuf::internal::GetEmptyStringAlreadyInited()) {
        interface_->clear();
      }
    }
    if (has_rsa()) {
      if (rsa_ != &::google::protobuf::internal::GetEmptyStringAlreadyInited()) {
        rsa_->clear();
      }
    }
    if (has_hmac()) {
      if (hmac_ != &::google::protobuf::internal::GetEmptyStringAlreadyInited()) {
        hmac_->clear();
      }
    }
    if (has_key()) {
      if (key_ != &::google::protobuf::internal::GetEmptyStringAlreadyInited()) {
        key_->clear();
      }
    }
    if (has_algo()) {
      if (algo_ != &::google::protobuf::internal::GetEmptyStringAlreadyInited()) {
        algo_->clear();
      }
    }
    if (has_tun()) {
      if (tun_ != &::google::protobuf::internal::GetEmptyStringAlreadyInited()) {
        tun_->clear();
      }
    }
  }
  ::memset(_has_bits_, 0, sizeof(_has_bits_));
  mutable_unknown_fields()->Clear();
}

bool IpsecTunnel::MergePartialFromCodedStream(
    ::google::protobuf::io::CodedInputStream* input) {
#define DO_(EXPRESSION) if (!(EXPRESSION)) goto failure
  ::google::protobuf::uint32 tag;
  // @@protoc_insertion_point(parse_start:TT.IpsecTunnel)
  for (;;) {
    ::std::pair< ::google::protobuf::uint32, bool> p = input->ReadTagWithCutoff(127);
    tag = p.first;
    if (!p.second) goto handle_unusual;
    switch (::google::protobuf::internal::WireFormatLite::GetTagFieldNumber(tag)) {
      // required string interface = 1;
      case 1: {
        if (tag == 10) {
          DO_(::google::protobuf::internal::WireFormatLite::ReadString(
                input, this->mutable_interface()));
          ::google::protobuf::internal::WireFormat::VerifyUTF8StringNamedField(
            this->interface().data(), this->interface().length(),
            ::google::protobuf::internal::WireFormat::PARSE,
            "interface");
        } else {
          goto handle_unusual;
        }
        if (input->ExpectTag(18)) goto parse_rsa;
        break;
      }

      // required string rsa = 2;
      case 2: {
        if (tag == 18) {
         parse_rsa:
          DO_(::google::protobuf::internal::WireFormatLite::ReadString(
                input, this->mutable_rsa()));
          ::google::protobuf::internal::WireFormat::VerifyUTF8StringNamedField(
            this->rsa().data(), this->rsa().length(),
            ::google::protobuf::internal::WireFormat::PARSE,
            "rsa");
        } else {
          goto handle_unusual;
        }
        if (input->ExpectTag(26)) goto parse_hmac;
        break;
      }

      // optional string hmac = 3;
      case 3: {
        if (tag == 26) {
         parse_hmac:
          DO_(::google::protobuf::internal::WireFormatLite::ReadString(
                input, this->mutable_hmac()));
          ::google::protobuf::internal::WireFormat::VerifyUTF8StringNamedField(
            this->hmac().data(), this->hmac().length(),
            ::google::protobuf::internal::WireFormat::PARSE,
            "hmac");
        } else {
          goto handle_unusual;
        }
        if (input->ExpectTag(34)) goto parse_key;
        break;
      }

      // optional string key = 4;
      case 4: {
        if (tag == 34) {
         parse_key:
          DO_(::google::protobuf::internal::WireFormatLite::ReadString(
                input, this->mutable_key()));
          ::google::protobuf::internal::WireFormat::VerifyUTF8StringNamedField(
            this->key().data(), this->key().length(),
            ::google::protobuf::internal::WireFormat::PARSE,
            "key");
        } else {
          goto handle_unusual;
        }
        if (input->ExpectTag(42)) goto parse_algo;
        break;
      }

      // optional string algo = 5;
      case 5: {
        if (tag == 42) {
         parse_algo:
          DO_(::google::protobuf::internal::WireFormatLite::ReadString(
                input, this->mutable_algo()));
          ::google::protobuf::internal::WireFormat::VerifyUTF8StringNamedField(
            this->algo().data(), this->algo().length(),
            ::google::protobuf::internal::WireFormat::PARSE,
            "algo");
        } else {
          goto handle_unusual;
        }
        if (input->ExpectTag(50)) goto parse_tun;
        break;
      }

      // optional string tun = 6;
      case 6: {
        if (tag == 50) {
         parse_tun:
          DO_(::google::protobuf::internal::WireFormatLite::ReadString(
                input, this->mutable_tun()));
          ::google::protobuf::internal::WireFormat::VerifyUTF8StringNamedField(
            this->tun().data(), this->tun().length(),
            ::google::protobuf::internal::WireFormat::PARSE,
            "tun");
        } else {
          goto handle_unusual;
        }
        if (input->ExpectAtEnd()) goto success;
        break;
      }

      default: {
      handle_unusual:
        if (tag == 0 ||
            ::google::protobuf::internal::WireFormatLite::GetTagWireType(tag) ==
            ::google::protobuf::internal::WireFormatLite::WIRETYPE_END_GROUP) {
          goto success;
        }
        DO_(::google::protobuf::internal::WireFormat::SkipField(
              input, tag, mutable_unknown_fields()));
        break;
      }
    }
  }
success:
  // @@protoc_insertion_point(parse_success:TT.IpsecTunnel)
  return true;
failure:
  // @@protoc_insertion_point(parse_failure:TT.IpsecTunnel)
  return false;
#undef DO_
}

void IpsecTunnel::SerializeWithCachedSizes(
    ::google::protobuf::io::CodedOutputStream* output) const {
  // @@protoc_insertion_point(serialize_start:TT.IpsecTunnel)
  // required string interface = 1;
  if (has_interface()) {
    ::google::protobuf::internal::WireFormat::VerifyUTF8StringNamedField(
      this->interface().data(), this->interface().length(),
      ::google::protobuf::internal::WireFormat::SERIALIZE,
      "interface");
    ::google::protobuf::internal::WireFormatLite::WriteStringMaybeAliased(
      1, this->interface(), output);
  }

  // required string rsa = 2;
  if (has_rsa()) {
    ::google::protobuf::internal::WireFormat::VerifyUTF8StringNamedField(
      this->rsa().data(), this->rsa().length(),
      ::google::protobuf::internal::WireFormat::SERIALIZE,
      "rsa");
    ::google::protobuf::internal::WireFormatLite::WriteStringMaybeAliased(
      2, this->rsa(), output);
  }

  // optional string hmac = 3;
  if (has_hmac()) {
    ::google::protobuf::internal::WireFormat::VerifyUTF8StringNamedField(
      this->hmac().data(), this->hmac().length(),
      ::google::protobuf::internal::WireFormat::SERIALIZE,
      "hmac");
    ::google::protobuf::internal::WireFormatLite::WriteStringMaybeAliased(
      3, this->hmac(), output);
  }

  // optional string key = 4;
  if (has_key()) {
    ::google::protobuf::internal::WireFormat::VerifyUTF8StringNamedField(
      this->key().data(), this->key().length(),
      ::google::protobuf::internal::WireFormat::SERIALIZE,
      "key");
    ::google::protobuf::internal::WireFormatLite::WriteStringMaybeAliased(
      4, this->key(), output);
  }

  // optional string algo = 5;
  if (has_algo()) {
    ::google::protobuf::internal::WireFormat::VerifyUTF8StringNamedField(
      this->algo().data(), this->algo().length(),
      ::google::protobuf::internal::WireFormat::SERIALIZE,
      "algo");
    ::google::protobuf::internal::WireFormatLite::WriteStringMaybeAliased(
      5, this->algo(), output);
  }

  // optional string tun = 6;
  if (has_tun()) {
    ::google::protobuf::internal::WireFormat::VerifyUTF8StringNamedField(
      this->tun().data(), this->tun().length(),
      ::google::protobuf::internal::WireFormat::SERIALIZE,
      "tun");
    ::google::protobuf::internal::WireFormatLite::WriteStringMaybeAliased(
      6, this->tun(), output);
  }

  if (!unknown_fields().empty()) {
    ::google::protobuf::internal::WireFormat::SerializeUnknownFields(
        unknown_fields(), output);
  }
  // @@protoc_insertion_point(serialize_end:TT.IpsecTunnel)
}

::google::protobuf::uint8* IpsecTunnel::SerializeWithCachedSizesToArray(
    ::google::protobuf::uint8* target) const {
  // @@protoc_insertion_point(serialize_to_array_start:TT.IpsecTunnel)
  // required string interface = 1;
  if (has_interface()) {
    ::google::protobuf::internal::WireFormat::VerifyUTF8StringNamedField(
      this->interface().data(), this->interface().length(),
      ::google::protobuf::internal::WireFormat::SERIALIZE,
      "interface");
    target =
      ::google::protobuf::internal::WireFormatLite::WriteStringToArray(
        1, this->interface(), target);
  }

  // required string rsa = 2;
  if (has_rsa()) {
    ::google::protobuf::internal::WireFormat::VerifyUTF8StringNamedField(
      this->rsa().data(), this->rsa().length(),
      ::google::protobuf::internal::WireFormat::SERIALIZE,
      "rsa");
    target =
      ::google::protobuf::internal::WireFormatLite::WriteStringToArray(
        2, this->rsa(), target);
  }

  // optional string hmac = 3;
  if (has_hmac()) {
    ::google::protobuf::internal::WireFormat::VerifyUTF8StringNamedField(
      this->hmac().data(), this->hmac().length(),
      ::google::protobuf::internal::WireFormat::SERIALIZE,
      "hmac");
    target =
      ::google::protobuf::internal::WireFormatLite::WriteStringToArray(
        3, this->hmac(), target);
  }

  // optional string key = 4;
  if (has_key()) {
    ::google::protobuf::internal::WireFormat::VerifyUTF8StringNamedField(
      this->key().data(), this->key().length(),
      ::google::protobuf::internal::WireFormat::SERIALIZE,
      "key");
    target =
      ::google::protobuf::internal::WireFormatLite::WriteStringToArray(
        4, this->key(), target);
  }

  // optional string algo = 5;
  if (has_algo()) {
    ::google::protobuf::internal::WireFormat::VerifyUTF8StringNamedField(
      this->algo().data(), this->algo().length(),
      ::google::protobuf::internal::WireFormat::SERIALIZE,
      "algo");
    target =
      ::google::protobuf::internal::WireFormatLite::WriteStringToArray(
        5, this->algo(), target);
  }

  // optional string tun = 6;
  if (has_tun()) {
    ::google::protobuf::internal::WireFormat::VerifyUTF8StringNamedField(
      this->tun().data(), this->tun().length(),
      ::google::protobuf::internal::WireFormat::SERIALIZE,
      "tun");
    target =
      ::google::protobuf::internal::WireFormatLite::WriteStringToArray(
        6, this->tun(), target);
  }

  if (!unknown_fields().empty()) {
    target = ::google::protobuf::internal::WireFormat::SerializeUnknownFieldsToArray(
        unknown_fields(), target);
  }
  // @@protoc_insertion_point(serialize_to_array_end:TT.IpsecTunnel)
  return target;
}

int IpsecTunnel::ByteSize() const {
  int total_size = 0;

  if (_has_bits_[0 / 32] & (0xffu << (0 % 32))) {
    // required string interface = 1;
    if (has_interface()) {
      total_size += 1 +
        ::google::protobuf::internal::WireFormatLite::StringSize(
          this->interface());
    }

    // required string rsa = 2;
    if (has_rsa()) {
      total_size += 1 +
        ::google::protobuf::internal::WireFormatLite::StringSize(
          this->rsa());
    }

    // optional string hmac = 3;
    if (has_hmac()) {
      total_size += 1 +
        ::google::protobuf::internal::WireFormatLite::StringSize(
          this->hmac());
    }

    // optional string key = 4;
    if (has_key()) {
      total_size += 1 +
        ::google::protobuf::internal::WireFormatLite::StringSize(
          this->key());
    }

    // optional string algo = 5;
    if (has_algo()) {
      total_size += 1 +
        ::google::protobuf::internal::WireFormatLite::StringSize(
          this->algo());
    }

    // optional string tun = 6;
    if (has_tun()) {
      total_size += 1 +
        ::google::protobuf::internal::WireFormatLite::StringSize(
          this->tun());
    }

  }
  if (!unknown_fields().empty()) {
    total_size +=
      ::google::protobuf::internal::WireFormat::ComputeUnknownFieldsSize(
        unknown_fields());
  }
  GOOGLE_SAFE_CONCURRENT_WRITES_BEGIN();
  _cached_size_ = total_size;
  GOOGLE_SAFE_CONCURRENT_WRITES_END();
  return total_size;
}

void IpsecTunnel::MergeFrom(const ::google::protobuf::Message& from) {
  GOOGLE_CHECK_NE(&from, this);
  const IpsecTunnel* source =
    ::google::protobuf::internal::dynamic_cast_if_available<const IpsecTunnel*>(
      &from);
  if (source == NULL) {
    ::google::protobuf::internal::ReflectionOps::Merge(from, this);
  } else {
    MergeFrom(*source);
  }
}

void IpsecTunnel::MergeFrom(const IpsecTunnel& from) {
  GOOGLE_CHECK_NE(&from, this);
  if (from._has_bits_[0 / 32] & (0xffu << (0 % 32))) {
    if (from.has_interface()) {
      set_interface(from.interface());
    }
    if (from.has_rsa()) {
      set_rsa(from.rsa());
    }
    if (from.has_hmac()) {
      set_hmac(from.hmac());
    }
    if (from.has_key()) {
      set_key(from.key());
    }
    if (from.has_algo()) {
      set_algo(from.algo());
    }
    if (from.has_tun()) {
      set_tun(from.tun());
    }
  }
  mutable_unknown_fields()->MergeFrom(from.unknown_fields());
}

void IpsecTunnel::CopyFrom(const ::google::protobuf::Message& from) {
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

void IpsecTunnel::CopyFrom(const IpsecTunnel& from) {
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

bool IpsecTunnel::IsInitialized() const {
  if ((_has_bits_[0] & 0x00000003) != 0x00000003) return false;

  return true;
}

void IpsecTunnel::Swap(IpsecTunnel* other) {
  if (other != this) {
    std::swap(interface_, other->interface_);
    std::swap(rsa_, other->rsa_);
    std::swap(hmac_, other->hmac_);
    std::swap(key_, other->key_);
    std::swap(algo_, other->algo_);
    std::swap(tun_, other->tun_);
    std::swap(_has_bits_[0], other->_has_bits_[0]);
    _unknown_fields_.Swap(&other->_unknown_fields_);
    std::swap(_cached_size_, other->_cached_size_);
  }
}

::google::protobuf::Metadata IpsecTunnel::GetMetadata() const {
  protobuf_AssignDescriptorsOnce();
  ::google::protobuf::Metadata metadata;
  metadata.descriptor = IpsecTunnel_descriptor_;
  metadata.reflection = IpsecTunnel_reflection_;
  return metadata;
}


// ===================================================================

#ifndef _MSC_VER
const int IpsecTunnelsContainer::kIpsecTunnelFieldNumber;
#endif  // !_MSC_VER

IpsecTunnelsContainer::IpsecTunnelsContainer()
  : ::google::protobuf::Message() {
  SharedCtor();
  // @@protoc_insertion_point(constructor:TT.IpsecTunnelsContainer)
}

void IpsecTunnelsContainer::InitAsDefaultInstance() {
}

IpsecTunnelsContainer::IpsecTunnelsContainer(const IpsecTunnelsContainer& from)
  : ::google::protobuf::Message() {
  SharedCtor();
  MergeFrom(from);
  // @@protoc_insertion_point(copy_constructor:TT.IpsecTunnelsContainer)
}

void IpsecTunnelsContainer::SharedCtor() {
  _cached_size_ = 0;
  ::memset(_has_bits_, 0, sizeof(_has_bits_));
}

IpsecTunnelsContainer::~IpsecTunnelsContainer() {
  // @@protoc_insertion_point(destructor:TT.IpsecTunnelsContainer)
  SharedDtor();
}

void IpsecTunnelsContainer::SharedDtor() {
  if (this != default_instance_) {
  }
}

void IpsecTunnelsContainer::SetCachedSize(int size) const {
  GOOGLE_SAFE_CONCURRENT_WRITES_BEGIN();
  _cached_size_ = size;
  GOOGLE_SAFE_CONCURRENT_WRITES_END();
}
const ::google::protobuf::Descriptor* IpsecTunnelsContainer::descriptor() {
  protobuf_AssignDescriptorsOnce();
  return IpsecTunnelsContainer_descriptor_;
}

const IpsecTunnelsContainer& IpsecTunnelsContainer::default_instance() {
  if (default_instance_ == NULL) protobuf_AddDesc_IpsecTransport_2eproto();
  return *default_instance_;
}

IpsecTunnelsContainer* IpsecTunnelsContainer::default_instance_ = NULL;

IpsecTunnelsContainer* IpsecTunnelsContainer::New() const {
  return new IpsecTunnelsContainer;
}

void IpsecTunnelsContainer::Clear() {
  ipsec_tunnel_.Clear();
  ::memset(_has_bits_, 0, sizeof(_has_bits_));
  mutable_unknown_fields()->Clear();
}

bool IpsecTunnelsContainer::MergePartialFromCodedStream(
    ::google::protobuf::io::CodedInputStream* input) {
#define DO_(EXPRESSION) if (!(EXPRESSION)) goto failure
  ::google::protobuf::uint32 tag;
  // @@protoc_insertion_point(parse_start:TT.IpsecTunnelsContainer)
  for (;;) {
    ::std::pair< ::google::protobuf::uint32, bool> p = input->ReadTagWithCutoff(127);
    tag = p.first;
    if (!p.second) goto handle_unusual;
    switch (::google::protobuf::internal::WireFormatLite::GetTagFieldNumber(tag)) {
      // repeated .TT.IpsecTunnel ipsec_tunnel = 1;
      case 1: {
        if (tag == 10) {
         parse_ipsec_tunnel:
          DO_(::google::protobuf::internal::WireFormatLite::ReadMessageNoVirtual(
                input, add_ipsec_tunnel()));
        } else {
          goto handle_unusual;
        }
        if (input->ExpectTag(10)) goto parse_ipsec_tunnel;
        if (input->ExpectAtEnd()) goto success;
        break;
      }

      default: {
      handle_unusual:
        if (tag == 0 ||
            ::google::protobuf::internal::WireFormatLite::GetTagWireType(tag) ==
            ::google::protobuf::internal::WireFormatLite::WIRETYPE_END_GROUP) {
          goto success;
        }
        DO_(::google::protobuf::internal::WireFormat::SkipField(
              input, tag, mutable_unknown_fields()));
        break;
      }
    }
  }
success:
  // @@protoc_insertion_point(parse_success:TT.IpsecTunnelsContainer)
  return true;
failure:
  // @@protoc_insertion_point(parse_failure:TT.IpsecTunnelsContainer)
  return false;
#undef DO_
}

void IpsecTunnelsContainer::SerializeWithCachedSizes(
    ::google::protobuf::io::CodedOutputStream* output) const {
  // @@protoc_insertion_point(serialize_start:TT.IpsecTunnelsContainer)
  // repeated .TT.IpsecTunnel ipsec_tunnel = 1;
  for (int i = 0; i < this->ipsec_tunnel_size(); i++) {
    ::google::protobuf::internal::WireFormatLite::WriteMessageMaybeToArray(
      1, this->ipsec_tunnel(i), output);
  }

  if (!unknown_fields().empty()) {
    ::google::protobuf::internal::WireFormat::SerializeUnknownFields(
        unknown_fields(), output);
  }
  // @@protoc_insertion_point(serialize_end:TT.IpsecTunnelsContainer)
}

::google::protobuf::uint8* IpsecTunnelsContainer::SerializeWithCachedSizesToArray(
    ::google::protobuf::uint8* target) const {
  // @@protoc_insertion_point(serialize_to_array_start:TT.IpsecTunnelsContainer)
  // repeated .TT.IpsecTunnel ipsec_tunnel = 1;
  for (int i = 0; i < this->ipsec_tunnel_size(); i++) {
    target = ::google::protobuf::internal::WireFormatLite::
      WriteMessageNoVirtualToArray(
        1, this->ipsec_tunnel(i), target);
  }

  if (!unknown_fields().empty()) {
    target = ::google::protobuf::internal::WireFormat::SerializeUnknownFieldsToArray(
        unknown_fields(), target);
  }
  // @@protoc_insertion_point(serialize_to_array_end:TT.IpsecTunnelsContainer)
  return target;
}

int IpsecTunnelsContainer::ByteSize() const {
  int total_size = 0;

  // repeated .TT.IpsecTunnel ipsec_tunnel = 1;
  total_size += 1 * this->ipsec_tunnel_size();
  for (int i = 0; i < this->ipsec_tunnel_size(); i++) {
    total_size +=
      ::google::protobuf::internal::WireFormatLite::MessageSizeNoVirtual(
        this->ipsec_tunnel(i));
  }

  if (!unknown_fields().empty()) {
    total_size +=
      ::google::protobuf::internal::WireFormat::ComputeUnknownFieldsSize(
        unknown_fields());
  }
  GOOGLE_SAFE_CONCURRENT_WRITES_BEGIN();
  _cached_size_ = total_size;
  GOOGLE_SAFE_CONCURRENT_WRITES_END();
  return total_size;
}

void IpsecTunnelsContainer::MergeFrom(const ::google::protobuf::Message& from) {
  GOOGLE_CHECK_NE(&from, this);
  const IpsecTunnelsContainer* source =
    ::google::protobuf::internal::dynamic_cast_if_available<const IpsecTunnelsContainer*>(
      &from);
  if (source == NULL) {
    ::google::protobuf::internal::ReflectionOps::Merge(from, this);
  } else {
    MergeFrom(*source);
  }
}

void IpsecTunnelsContainer::MergeFrom(const IpsecTunnelsContainer& from) {
  GOOGLE_CHECK_NE(&from, this);
  ipsec_tunnel_.MergeFrom(from.ipsec_tunnel_);
  mutable_unknown_fields()->MergeFrom(from.unknown_fields());
}

void IpsecTunnelsContainer::CopyFrom(const ::google::protobuf::Message& from) {
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

void IpsecTunnelsContainer::CopyFrom(const IpsecTunnelsContainer& from) {
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

bool IpsecTunnelsContainer::IsInitialized() const {

  if (!::google::protobuf::internal::AllAreInitialized(this->ipsec_tunnel())) return false;
  return true;
}

void IpsecTunnelsContainer::Swap(IpsecTunnelsContainer* other) {
  if (other != this) {
    ipsec_tunnel_.Swap(&other->ipsec_tunnel_);
    std::swap(_has_bits_[0], other->_has_bits_[0]);
    _unknown_fields_.Swap(&other->_unknown_fields_);
    std::swap(_cached_size_, other->_cached_size_);
  }
}

::google::protobuf::Metadata IpsecTunnelsContainer::GetMetadata() const {
  protobuf_AssignDescriptorsOnce();
  ::google::protobuf::Metadata metadata;
  metadata.descriptor = IpsecTunnelsContainer_descriptor_;
  metadata.reflection = IpsecTunnelsContainer_reflection_;
  return metadata;
}


// @@protoc_insertion_point(namespace_scope)

}  // namespace TT

// @@protoc_insertion_point(global_scope)
