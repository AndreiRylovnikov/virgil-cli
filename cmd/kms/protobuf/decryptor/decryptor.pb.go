// Code generated by protoc-gen-go. DO NOT EDIT.
// source: decryptor.proto

package decryptor

import (
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

type Keypair struct {
	Version              uint32   `protobuf:"varint,1,opt,name=version,proto3" json:"version,omitempty"`
	Alias                string   `protobuf:"bytes,2,opt,name=alias,proto3" json:"alias,omitempty"`
	KeyVersion           uint32   `protobuf:"varint,3,opt,name=key_version,json=keyVersion,proto3" json:"key_version,omitempty"`
	PublicKey            []byte   `protobuf:"bytes,4,opt,name=public_key,json=publicKey,proto3" json:"public_key,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Keypair) Reset()         { *m = Keypair{} }
func (m *Keypair) String() string { return proto.CompactTextString(m) }
func (*Keypair) ProtoMessage()    {}
func (*Keypair) Descriptor() ([]byte, []int) {
	return fileDescriptor_96f3e0ebce23a210, []int{0}
}

func (m *Keypair) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Keypair.Unmarshal(m, b)
}
func (m *Keypair) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Keypair.Marshal(b, m, deterministic)
}
func (m *Keypair) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Keypair.Merge(m, src)
}
func (m *Keypair) XXX_Size() int {
	return xxx_messageInfo_Keypair.Size(m)
}
func (m *Keypair) XXX_DiscardUnknown() {
	xxx_messageInfo_Keypair.DiscardUnknown(m)
}

var xxx_messageInfo_Keypair proto.InternalMessageInfo

func (m *Keypair) GetVersion() uint32 {
	if m != nil {
		return m.Version
	}
	return 0
}

func (m *Keypair) GetAlias() string {
	if m != nil {
		return m.Alias
	}
	return ""
}

func (m *Keypair) GetKeyVersion() uint32 {
	if m != nil {
		return m.KeyVersion
	}
	return 0
}

func (m *Keypair) GetPublicKey() []byte {
	if m != nil {
		return m.PublicKey
	}
	return nil
}

type Keypairs struct {
	Keypairs             []*Keypair `protobuf:"bytes,1,rep,name=keypairs,proto3" json:"keypairs,omitempty"`
	XXX_NoUnkeyedLiteral struct{}   `json:"-"`
	XXX_unrecognized     []byte     `json:"-"`
	XXX_sizecache        int32      `json:"-"`
}

func (m *Keypairs) Reset()         { *m = Keypairs{} }
func (m *Keypairs) String() string { return proto.CompactTextString(m) }
func (*Keypairs) ProtoMessage()    {}
func (*Keypairs) Descriptor() ([]byte, []int) {
	return fileDescriptor_96f3e0ebce23a210, []int{1}
}

func (m *Keypairs) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Keypairs.Unmarshal(m, b)
}
func (m *Keypairs) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Keypairs.Marshal(b, m, deterministic)
}
func (m *Keypairs) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Keypairs.Merge(m, src)
}
func (m *Keypairs) XXX_Size() int {
	return xxx_messageInfo_Keypairs.Size(m)
}
func (m *Keypairs) XXX_DiscardUnknown() {
	xxx_messageInfo_Keypairs.DiscardUnknown(m)
}

var xxx_messageInfo_Keypairs proto.InternalMessageInfo

func (m *Keypairs) GetKeypairs() []*Keypair {
	if m != nil {
		return m.Keypairs
	}
	return nil
}

type KeypairRequest struct {
	Alias                string   `protobuf:"bytes,1,opt,name=alias,proto3" json:"alias,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *KeypairRequest) Reset()         { *m = KeypairRequest{} }
func (m *KeypairRequest) String() string { return proto.CompactTextString(m) }
func (*KeypairRequest) ProtoMessage()    {}
func (*KeypairRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_96f3e0ebce23a210, []int{2}
}

func (m *KeypairRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_KeypairRequest.Unmarshal(m, b)
}
func (m *KeypairRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_KeypairRequest.Marshal(b, m, deterministic)
}
func (m *KeypairRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_KeypairRequest.Merge(m, src)
}
func (m *KeypairRequest) XXX_Size() int {
	return xxx_messageInfo_KeypairRequest.Size(m)
}
func (m *KeypairRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_KeypairRequest.DiscardUnknown(m)
}

var xxx_messageInfo_KeypairRequest proto.InternalMessageInfo

func (m *KeypairRequest) GetAlias() string {
	if m != nil {
		return m.Alias
	}
	return ""
}

type DecryptRequest struct {
	Version              uint32   `protobuf:"varint,1,opt,name=version,proto3" json:"version,omitempty"`
	Alias                string   `protobuf:"bytes,2,opt,name=alias,proto3" json:"alias,omitempty"`
	Request              []byte   `protobuf:"bytes,3,opt,name=request,proto3" json:"request,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *DecryptRequest) Reset()         { *m = DecryptRequest{} }
func (m *DecryptRequest) String() string { return proto.CompactTextString(m) }
func (*DecryptRequest) ProtoMessage()    {}
func (*DecryptRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_96f3e0ebce23a210, []int{3}
}

func (m *DecryptRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_DecryptRequest.Unmarshal(m, b)
}
func (m *DecryptRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_DecryptRequest.Marshal(b, m, deterministic)
}
func (m *DecryptRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_DecryptRequest.Merge(m, src)
}
func (m *DecryptRequest) XXX_Size() int {
	return xxx_messageInfo_DecryptRequest.Size(m)
}
func (m *DecryptRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_DecryptRequest.DiscardUnknown(m)
}

var xxx_messageInfo_DecryptRequest proto.InternalMessageInfo

func (m *DecryptRequest) GetVersion() uint32 {
	if m != nil {
		return m.Version
	}
	return 0
}

func (m *DecryptRequest) GetAlias() string {
	if m != nil {
		return m.Alias
	}
	return ""
}

func (m *DecryptRequest) GetRequest() []byte {
	if m != nil {
		return m.Request
	}
	return nil
}

type DecryptResponse struct {
	Response             []byte   `protobuf:"bytes,1,opt,name=response,proto3" json:"response,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *DecryptResponse) Reset()         { *m = DecryptResponse{} }
func (m *DecryptResponse) String() string { return proto.CompactTextString(m) }
func (*DecryptResponse) ProtoMessage()    {}
func (*DecryptResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_96f3e0ebce23a210, []int{4}
}

func (m *DecryptResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_DecryptResponse.Unmarshal(m, b)
}
func (m *DecryptResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_DecryptResponse.Marshal(b, m, deterministic)
}
func (m *DecryptResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_DecryptResponse.Merge(m, src)
}
func (m *DecryptResponse) XXX_Size() int {
	return xxx_messageInfo_DecryptResponse.Size(m)
}
func (m *DecryptResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_DecryptResponse.DiscardUnknown(m)
}

var xxx_messageInfo_DecryptResponse proto.InternalMessageInfo

func (m *DecryptResponse) GetResponse() []byte {
	if m != nil {
		return m.Response
	}
	return nil
}

type UpdateTokenResponse struct {
	Version              uint32   `protobuf:"varint,1,opt,name=version,proto3" json:"version,omitempty"`
	UpdateToken          []byte   `protobuf:"bytes,2,opt,name=update_token,json=updateToken,proto3" json:"update_token,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *UpdateTokenResponse) Reset()         { *m = UpdateTokenResponse{} }
func (m *UpdateTokenResponse) String() string { return proto.CompactTextString(m) }
func (*UpdateTokenResponse) ProtoMessage()    {}
func (*UpdateTokenResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_96f3e0ebce23a210, []int{5}
}

func (m *UpdateTokenResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_UpdateTokenResponse.Unmarshal(m, b)
}
func (m *UpdateTokenResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_UpdateTokenResponse.Marshal(b, m, deterministic)
}
func (m *UpdateTokenResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_UpdateTokenResponse.Merge(m, src)
}
func (m *UpdateTokenResponse) XXX_Size() int {
	return xxx_messageInfo_UpdateTokenResponse.Size(m)
}
func (m *UpdateTokenResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_UpdateTokenResponse.DiscardUnknown(m)
}

var xxx_messageInfo_UpdateTokenResponse proto.InternalMessageInfo

func (m *UpdateTokenResponse) GetVersion() uint32 {
	if m != nil {
		return m.Version
	}
	return 0
}

func (m *UpdateTokenResponse) GetUpdateToken() []byte {
	if m != nil {
		return m.UpdateToken
	}
	return nil
}

func init() {
	proto.RegisterType((*Keypair)(nil), "decryptor.Keypair")
	proto.RegisterType((*Keypairs)(nil), "decryptor.Keypairs")
	proto.RegisterType((*KeypairRequest)(nil), "decryptor.KeypairRequest")
	proto.RegisterType((*DecryptRequest)(nil), "decryptor.DecryptRequest")
	proto.RegisterType((*DecryptResponse)(nil), "decryptor.DecryptResponse")
	proto.RegisterType((*UpdateTokenResponse)(nil), "decryptor.UpdateTokenResponse")
}

func init() { proto.RegisterFile("decryptor.proto", fileDescriptor_96f3e0ebce23a210) }

var fileDescriptor_96f3e0ebce23a210 = []byte{
	// 265 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x94, 0x91, 0x31, 0x4f, 0xc3, 0x30,
	0x10, 0x85, 0x65, 0x0a, 0x24, 0xb9, 0x84, 0x56, 0x32, 0x0c, 0x16, 0x12, 0x22, 0x78, 0x40, 0x59,
	0xc8, 0x00, 0x1b, 0x33, 0x5b, 0x37, 0x0b, 0x18, 0x58, 0xa2, 0xb4, 0xbd, 0x21, 0x4a, 0x15, 0x1b,
	0x3b, 0x41, 0xf2, 0xbf, 0x47, 0x38, 0xb6, 0xc3, 0xc2, 0xc0, 0x76, 0xef, 0xf4, 0xbe, 0xe7, 0x77,
	0x32, 0x6c, 0x0e, 0xb8, 0xd7, 0x56, 0x8d, 0x52, 0xd7, 0x4a, 0xcb, 0x51, 0xd2, 0x2c, 0x2e, 0xb8,
	0x85, 0x64, 0x8b, 0x56, 0xb5, 0x9d, 0xa6, 0x0c, 0x92, 0x2f, 0xd4, 0xa6, 0x93, 0x03, 0x23, 0x25,
	0xa9, 0x2e, 0x44, 0x90, 0xf4, 0x0a, 0xce, 0xda, 0x63, 0xd7, 0x1a, 0x76, 0x52, 0x92, 0x2a, 0x13,
	0xb3, 0xa0, 0xb7, 0x90, 0xf7, 0x68, 0x9b, 0xc0, 0xac, 0x1c, 0x03, 0x3d, 0xda, 0x77, 0x8f, 0xdd,
	0x00, 0xa8, 0x69, 0x77, 0xec, 0xf6, 0x4d, 0x8f, 0x96, 0x9d, 0x96, 0xa4, 0x2a, 0x44, 0x36, 0x6f,
	0xb6, 0x68, 0xf9, 0x33, 0xa4, 0xfe, 0x69, 0x43, 0x6b, 0x48, 0x7b, 0x3f, 0x33, 0x52, 0xae, 0xaa,
	0xfc, 0x91, 0xd6, 0x4b, 0x6b, 0x6f, 0x13, 0xd1, 0xc3, 0xef, 0x61, 0x1d, 0x96, 0xf8, 0x39, 0xa1,
	0x19, 0x97, 0x8e, 0xe4, 0x57, 0x47, 0xfe, 0x01, 0xeb, 0x97, 0x39, 0x26, 0xf8, 0xfe, 0x7b, 0x25,
	0x83, 0x44, 0xcf, 0xa8, 0xbb, 0xb0, 0x10, 0x41, 0xf2, 0x07, 0xd8, 0xc4, 0x6c, 0xa3, 0xe4, 0x60,
	0x90, 0x5e, 0x43, 0xaa, 0xfd, 0xec, 0xd2, 0x0b, 0x11, 0x35, 0x17, 0x70, 0xf9, 0xa6, 0x0e, 0xed,
	0x88, 0xaf, 0xb2, 0xc7, 0x21, 0x22, 0x7f, 0xf7, 0xb9, 0x83, 0x62, 0x72, 0x40, 0x33, 0xfe, 0x10,
	0xae, 0x56, 0x21, 0xf2, 0x69, 0x09, 0xd9, 0x9d, 0xbb, 0xff, 0x7c, 0xfa, 0x0e, 0x00, 0x00, 0xff,
	0xff, 0x85, 0x86, 0xb2, 0x11, 0xe2, 0x01, 0x00, 0x00,
}
