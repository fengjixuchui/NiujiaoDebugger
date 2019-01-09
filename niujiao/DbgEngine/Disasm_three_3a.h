#pragma once
/*
定义反汇编引擎的部分结构  ThreeByteCodeMap3A 是基于intel手册2525页的Three-byte Opcode Map进行整理的
*/
#include "Disasm_THREE_38.h"

static STR_MAP_CODE ThreeByteCodeMap3A[] =
{
	{ 0x00,"vpermq"     ,PACK_OPERAND(THREE_OPERAND,AT__V,OT__qq,AT__W,OT__qq,AT__I,OT__b,0,0),Disasm::Disasm_THREE3A_gernel },
	{ 0x01,"vpermpd"     ,PACK_OPERAND(THREE_OPERAND,AT__V,OT__qq,AT__W,OT__qq,AT__I,OT__b,0,0),Disasm::Disasm_THREE3A_gernel},
	{ 0x02,"vpblendd"     ,PACK_OPERAND(FOUR_OPERAND,AT__V,OT__x,AT__H,OT__x,AT__W,OT__x,AT__I,OT__b),Disasm::Disasm_THREE3A_gernel },
	{ 0x03,""     ,0,Disasm::Disasm_reserve },
	{ 0x04,"vpermilps"     ,PACK_OPERAND(THREE_OPERAND,AT__V,OT__x,AT__W,OT__x,AT__I,OT__b,0,0),Disasm::Disasm_THREE3A_gernel },
	{ 0x05,"vpermilpd"     ,PACK_OPERAND(THREE_OPERAND,AT__V,OT__x,AT__W,OT__x,AT__I,OT__b,0,0),Disasm::Disasm_THREE3A_gernel},
	{ 0x06,"vperm2f128"     ,PACK_OPERAND(FOUR_OPERAND,AT__V,OT__qq,AT__H,OT__qq,AT__W,OT__qq,AT__I,OT__b),Disasm::Disasm_THREE3A_gernel },
	{ 0x07,""     ,0,Disasm::Disasm_reserve },
	{ 0x08,"vroundps"     ,PACK_OPERAND(THREE_OPERAND,AT__V,OT__x,AT__W,OT__x,AT__I,OT__b,0,0),Disasm::Disasm_THREE3A_gernel },
	{ 0x09,"vroundpd"     ,PACK_OPERAND(THREE_OPERAND,AT__V,OT__x,AT__W,OT__x,AT__I,OT__b,0,0),Disasm::Disasm_THREE3A_gernel },
	{ 0x0a,"vroundss"     ,PACK_OPERAND(THREE_OPERAND,AT__V,OT__ss,AT__W,OT__ss,AT__I,OT__b,0,0),Disasm::Disasm_THREE3A_gernel },
	{ 0x0b,"vroundsd"     ,PACK_OPERAND(THREE_OPERAND,AT__V,OT__sd,AT__W,OT__sd,AT__I,OT__b,0,0),Disasm::Disasm_THREE3A_gernel },
	{ 0x0c,"vblendps"     ,PACK_OPERAND(FOUR_OPERAND,AT__V,OT__x,AT__H,OT__x,AT__W,OT__x,AT__I,OT__b),Disasm::Disasm_THREE3A_gernel },
	{ 0x0d,"vblendpd"     ,PACK_OPERAND(FOUR_OPERAND,AT__V,OT__x,AT__H,OT__x,AT__W,OT__x,AT__I,OT__b),Disasm::Disasm_THREE3A_gernel },
	{ 0x0e,"vpblendw"     ,PACK_OPERAND(FOUR_OPERAND,AT__V,OT__x,AT__H,OT__x,AT__W,OT__x,AT__I,OT__b),Disasm::Disasm_THREE3A_gernel },
	{ 0x0f,"vpalignr"     ,PACK_OPERAND(FOUR_OPERAND,AT__V,OT__x,AT__H,OT__x,AT__W,OT__x,AT__I,OT__b),Disasm::Disasm_THREE3A_0x0f },
	{ 0x10,""     ,0,Disasm::Disasm_reserve },
	{ 0x11,""     ,0,Disasm::Disasm_reserve },
	{ 0x12,""     ,0,Disasm::Disasm_reserve },
	{ 0x13,""     ,0,Disasm::Disasm_reserve },
	{ 0x14,"vpextrb"     ,PACK_OPERAND(THREE_OPERAND,AT__R,OT__d,AT__V,OT__dq,AT__I,OT__b,0,0),Disasm::Disasm_THREE3A_gernel},
	{ 0x15,"vpextrw"     ,PACK_OPERAND(THREE_OPERAND,AT__R,OT__d,AT__V,OT__dq,AT__I,OT__b,0,0),Disasm::Disasm_THREE3A_gernel},
	{ 0x16,"vpextrd"     ,PACK_OPERAND(THREE_OPERAND,AT__E,OT__y,AT__V,OT__dq,AT__I,OT__b,0,0),Disasm::Disasm_THREE3A_gernel },
	{ 0x17,"vextractps"     ,PACK_OPERAND(THREE_OPERAND,AT__E,OT__d,AT__V,OT__dq,AT__I,OT__b,0,0),Disasm::Disasm_THREE3A_gernel},
	{ 0x18,"vinsertf128"     ,PACK_OPERAND(FOUR_OPERAND,AT__V,OT__qq,AT__H,OT__qq,AT__W,OT__qq,AT__I,OT__b),Disasm::Disasm_THREE3A_gernel  },
	{ 0x19,"vextractf128"     ,PACK_OPERAND(THREE_OPERAND,AT__W,OT__qq,AT__V,OT__qq,AT__I,OT__b,0,0),Disasm::Disasm_THREE3A_gernel   },
	{ 0x1a,""     ,0,Disasm::Disasm_reserve },
	{ 0x1b,""     ,0,Disasm::Disasm_reserve },
	{ 0x1c,""     ,0,Disasm::Disasm_reserve },
	{ 0x1d,"vcvtps2ph"     ,PACK_OPERAND(THREE_OPERAND,AT__W,OT__x,AT__V,OT__x,AT__I,OT__b,0,0),Disasm::Disasm_THREE3A_gernel },
	{ 0x1e,""     ,0,Disasm::Disasm_reserve },
	{ 0x1f,""     ,0,Disasm::Disasm_reserve },
	{ 0x20,"vpinsrb"     ,PACK_OPERAND(FOUR_OPERAND,AT__V,OT__dq,AT__H,OT__dq,AT__M,OT__b,AT__I,OT__b),Disasm::Disasm_THREE3A_gernel  },
	{ 0x21,"vinsertps"     ,PACK_OPERAND(FOUR_OPERAND,AT__V,OT__dq,AT__H,OT__dq,AT__M,OT__d,AT__I,OT__b),Disasm::Disasm_THREE3A_gernel  },
	{ 0x22,"vpinsrd"     ,PACK_OPERAND(FOUR_OPERAND,AT__V,OT__dq,AT__H,OT__dq,AT__E,OT__y,AT__I,OT__b),Disasm::Disasm_THREE3A_gernel   },
	{ 0x23,""     ,0,Disasm::Disasm_reserve },
	{ 0x24,""     ,0,Disasm::Disasm_reserve },
	{ 0x25,""     ,0,Disasm::Disasm_reserve },
	{ 0x26,""     ,0,Disasm::Disasm_reserve },
	{ 0x27,""     ,0,Disasm::Disasm_reserve },
	{ 0x28,""     ,0,Disasm::Disasm_reserve },
	{ 0x29,""     ,0,Disasm::Disasm_reserve },
	{ 0x2a,""     ,0,Disasm::Disasm_reserve },
	{ 0x2b,""     ,0,Disasm::Disasm_reserve },
	{ 0x2c,""     ,0,Disasm::Disasm_reserve },
	{ 0x2d,""     ,0,Disasm::Disasm_reserve },
	{ 0x2e,""     ,0,Disasm::Disasm_reserve },
	{ 0x2f,""     ,0,Disasm::Disasm_reserve },
	{ 0x30,""     ,0,Disasm::Disasm_reserve },
	{ 0x31,""     ,0,Disasm::Disasm_reserve },
	{ 0x32,""     ,0,Disasm::Disasm_reserve },
	{ 0x33,""     ,0,Disasm::Disasm_reserve },
	{ 0x34,""     ,0,Disasm::Disasm_reserve },
	{ 0x35,""     ,0,Disasm::Disasm_reserve },
	{ 0x36,""     ,0,Disasm::Disasm_reserve },
	{ 0x37,""     ,0,Disasm::Disasm_reserve },
	{ 0x38,"vinserti128"     ,PACK_OPERAND(FOUR_OPERAND,AT__V,OT__qq,AT__H,OT__qq,AT__W,OT__qq,AT__I,OT__b),Disasm::Disasm_THREE3A_gernel  },
	{ 0x39,"vextracti128"     ,PACK_OPERAND(THREE_OPERAND,AT__V,OT__qq,AT__H,OT__qq,AT__I,OT__b,0,0),Disasm::Disasm_THREE3A_gernel  },
	{ 0x3a,""     ,0,Disasm::Disasm_reserve },
	{ 0x3b,""     ,0,Disasm::Disasm_reserve },
	{ 0x3c,""     ,0,Disasm::Disasm_reserve },
	{ 0x3d,""     ,0,Disasm::Disasm_reserve },
	{ 0x3e,""     ,0,Disasm::Disasm_reserve },
	{ 0x3f,""     ,0,Disasm::Disasm_reserve },
	{ 0x40,"vdpps"     ,PACK_OPERAND(FOUR_OPERAND,AT__V,OT__x,AT__H,OT__x,AT__W,OT__x,AT__I,OT__b),Disasm::Disasm_THREE3A_gernel  },
	{ 0x41,"vdppd"     ,PACK_OPERAND(FOUR_OPERAND,AT__V,OT__dq,AT__H,OT__dq,AT__W,OT__dq,AT__I,OT__b),Disasm::Disasm_THREE3A_gernel },
	{ 0x42,"vmpsadbw"     ,PACK_OPERAND(FOUR_OPERAND,AT__V,OT__x,AT__H,OT__x,AT__W,OT__x,AT__I,OT__b),Disasm::Disasm_THREE3A_gernel   },
	{ 0x43,""     ,0,Disasm::Disasm_reserve },
	{ 0x44,"vpclmulqdq"     ,PACK_OPERAND(FOUR_OPERAND,AT__V,OT__dq,AT__H,OT__dq,AT__W,OT__dq,AT__I,OT__b),Disasm::Disasm_THREE3A_gernel },
	{ 0x45,""     ,0,Disasm::Disasm_reserve },
	{ 0x46,"vperm2i128"     ,PACK_OPERAND(FOUR_OPERAND,AT__V,OT__dq,AT__H,OT__dq,AT__W,OT__dq,AT__I,OT__b),Disasm::Disasm_THREE3A_gernel },
	{ 0x47,""     ,0,Disasm::Disasm_reserve },
	{ 0x48,""     ,0,Disasm::Disasm_reserve },
	{ 0x49,""     ,0,Disasm::Disasm_reserve },
	{ 0x4a,"vblendvps"     ,PACK_OPERAND(FOUR_OPERAND,AT__V,OT__x,AT__H,OT__x,AT__W,OT__x,AT__L,OT__x),Disasm::Disasm_THREE3A_gernel},
	{ 0x4b,"vblendvpd"     ,PACK_OPERAND(FOUR_OPERAND,AT__V,OT__x,AT__H,OT__x,AT__W,OT__x,AT__L,OT__x),Disasm::Disasm_THREE3A_gernel},
	{ 0x4c,"vpblendvb"     ,PACK_OPERAND(FOUR_OPERAND,AT__V,OT__x,AT__H,OT__x,AT__W,OT__x,AT__L,OT__x),Disasm::Disasm_THREE3A_gernel},
	{ 0x4d,""     ,0,Disasm::Disasm_reserve },
	{ 0x4e,""     ,0,Disasm::Disasm_reserve },
	{ 0x4f,""     ,0,Disasm::Disasm_reserve },
	{ 0x50,""     ,0,Disasm::Disasm_reserve },
	{ 0x51,""     ,0,Disasm::Disasm_reserve },
	{ 0x52,""     ,0,Disasm::Disasm_reserve },
	{ 0x53,""     ,0,Disasm::Disasm_reserve },
	{ 0x54,""     ,0,Disasm::Disasm_reserve },
	{ 0x55,""     ,0,Disasm::Disasm_reserve },
	{ 0x56,""     ,0,Disasm::Disasm_reserve },
	{ 0x57,""     ,0,Disasm::Disasm_reserve },
	{ 0x58,""     ,0,Disasm::Disasm_reserve },
	{ 0x59,""     ,0,Disasm::Disasm_reserve },
	{ 0x5a,""     ,0,Disasm::Disasm_reserve },
	{ 0x5b,""     ,0,Disasm::Disasm_reserve },
	{ 0x5c,""     ,0,Disasm::Disasm_reserve },
	{ 0x5d,""     ,0,Disasm::Disasm_reserve },
	{ 0x5e,""     ,0,Disasm::Disasm_reserve },
	{ 0x5f,""     ,0,Disasm::Disasm_reserve },
	{ 0x60,"vpcmpestrm"     ,PACK_OPERAND(THREE_OPERAND,AT__V,OT__dq,AT__W,OT__dq,AT__I,OT__b,0,0),Disasm::Disasm_THREE3A_gernel },
	{ 0x61,"vpcmpestri"     ,PACK_OPERAND(THREE_OPERAND,AT__V,OT__dq,AT__W,OT__dq,AT__I,OT__b,0,0),Disasm::Disasm_THREE3A_gernel },
	{ 0x62,"vpcmpistrm"     ,PACK_OPERAND(THREE_OPERAND,AT__V,OT__dq,AT__W,OT__dq,AT__I,OT__b,0,0),Disasm::Disasm_THREE3A_gernel },
	{ 0x63,"vpcmpistri"     ,PACK_OPERAND(THREE_OPERAND,AT__V,OT__dq,AT__W,OT__dq,AT__I,OT__b,0,0),Disasm::Disasm_THREE3A_gernel },
	{ 0x64,""     ,0,Disasm::Disasm_reserve },
	{ 0x65,""     ,0,Disasm::Disasm_reserve },
	{ 0x66,""     ,0,Disasm::Disasm_reserve },
	{ 0x67,""     ,0,Disasm::Disasm_reserve },
	{ 0x68,""     ,0,Disasm::Disasm_reserve },
	{ 0x69,""     ,0,Disasm::Disasm_reserve },
	{ 0x6a,""     ,0,Disasm::Disasm_reserve },
	{ 0x6b,""     ,0,Disasm::Disasm_reserve },
	{ 0x6c,""     ,0,Disasm::Disasm_reserve },
	{ 0x6d,""     ,0,Disasm::Disasm_reserve },
	{ 0x6e,""     ,0,Disasm::Disasm_reserve },
	{ 0x6f,""     ,0,Disasm::Disasm_reserve },
	{ 0x70,""     ,0,Disasm::Disasm_reserve },
	{ 0x71,""     ,0,Disasm::Disasm_reserve },
	{ 0x72,""     ,0,Disasm::Disasm_reserve },
	{ 0x73,""     ,0,Disasm::Disasm_reserve },
	{ 0x74,""     ,0,Disasm::Disasm_reserve },
	{ 0x75,""     ,0,Disasm::Disasm_reserve },
	{ 0x76,""     ,0,Disasm::Disasm_reserve },
	{ 0x77,""     ,0,Disasm::Disasm_reserve },
	{ 0x78,""     ,0,Disasm::Disasm_reserve },
	{ 0x79,""     ,0,Disasm::Disasm_reserve },
	{ 0x7a,""     ,0,Disasm::Disasm_reserve },
	{ 0x7b,""     ,0,Disasm::Disasm_reserve },
	{ 0x7c,""     ,0,Disasm::Disasm_reserve },
	{ 0x7d,""     ,0,Disasm::Disasm_reserve },
	{ 0x7e,""     ,0,Disasm::Disasm_reserve },
	{ 0x7f,""     ,0,Disasm::Disasm_reserve },
	{ 0x80,""     ,0,Disasm::Disasm_reserve },
	{ 0x81,""     ,0,Disasm::Disasm_reserve },
	{ 0x82,""     ,0,Disasm::Disasm_reserve },
	{ 0x83,""     ,0,Disasm::Disasm_reserve },
	{ 0x84,""     ,0,Disasm::Disasm_reserve },
	{ 0x85,""     ,0,Disasm::Disasm_reserve },
	{ 0x86,""     ,0,Disasm::Disasm_reserve },
	{ 0x87,""     ,0,Disasm::Disasm_reserve },
	{ 0x88,""     ,0,Disasm::Disasm_reserve },
	{ 0x89,""     ,0,Disasm::Disasm_reserve },
	{ 0x8a,""     ,0,Disasm::Disasm_reserve },
	{ 0x8b,""     ,0,Disasm::Disasm_reserve },
	{ 0x8c,""     ,0,Disasm::Disasm_reserve },
	{ 0x8d,""     ,0,Disasm::Disasm_reserve },
	{ 0x8e,""     ,0,Disasm::Disasm_reserve },
	{ 0x8f,""     ,0,Disasm::Disasm_reserve },
	{ 0x90,""     ,0,Disasm::Disasm_reserve },
	{ 0x91,""     ,0,Disasm::Disasm_reserve },
	{ 0x92,""     ,0,Disasm::Disasm_reserve },
	{ 0x93,""     ,0,Disasm::Disasm_reserve },
	{ 0x94,""     ,0,Disasm::Disasm_reserve },
	{ 0x95,""     ,0,Disasm::Disasm_reserve },
	{ 0x96,""     ,0,Disasm::Disasm_reserve },
	{ 0x97,""     ,0,Disasm::Disasm_reserve },
	{ 0x98,""     ,0,Disasm::Disasm_reserve },
	{ 0x99,""     ,0,Disasm::Disasm_reserve },
	{ 0x9a,""     ,0,Disasm::Disasm_reserve },
	{ 0x9b,""     ,0,Disasm::Disasm_reserve },
	{ 0x9c,""     ,0,Disasm::Disasm_reserve },
	{ 0x9d,""     ,0,Disasm::Disasm_reserve },
	{ 0x9e,""     ,0,Disasm::Disasm_reserve },
	{ 0x9f,""     ,0,Disasm::Disasm_reserve },
	{ 0xa0,""     ,0,Disasm::Disasm_reserve },
	{ 0xa1,""     ,0,Disasm::Disasm_reserve },
	{ 0xa2,""     ,0,Disasm::Disasm_reserve },
	{ 0xa3,""     ,0,Disasm::Disasm_reserve },
	{ 0xa4,""     ,0,Disasm::Disasm_reserve },
	{ 0xa5,""     ,0,Disasm::Disasm_reserve },
	{ 0xa6,""     ,0,Disasm::Disasm_reserve },
	{ 0xa7,""     ,0,Disasm::Disasm_reserve },
	{ 0xa8,""     ,0,Disasm::Disasm_reserve },
	{ 0xa9,""     ,0,Disasm::Disasm_reserve },
	{ 0xaa,""     ,0,Disasm::Disasm_reserve },
	{ 0xab,""     ,0,Disasm::Disasm_reserve },
	{ 0xac,""     ,0,Disasm::Disasm_reserve },
	{ 0xad,""     ,0,Disasm::Disasm_reserve },
	{ 0xae,""     ,0,Disasm::Disasm_reserve },
	{ 0xaf,""     ,0,Disasm::Disasm_reserve },
	{ 0xb0,""     ,0,Disasm::Disasm_reserve },
	{ 0xb1,""     ,0,Disasm::Disasm_reserve },
	{ 0xb2,""     ,0,Disasm::Disasm_reserve },
	{ 0xb3,""     ,0,Disasm::Disasm_reserve },
	{ 0xb4,""     ,0,Disasm::Disasm_reserve },
	{ 0xb5,""     ,0,Disasm::Disasm_reserve },
	{ 0xb6,""     ,0,Disasm::Disasm_reserve },
	{ 0xb7,""     ,0,Disasm::Disasm_reserve },
	{ 0xb8,""     ,0,Disasm::Disasm_reserve },
	{ 0xb9,""     ,0,Disasm::Disasm_reserve },
	{ 0xba,""     ,0,Disasm::Disasm_reserve },
	{ 0xbb,""     ,0,Disasm::Disasm_reserve },
	{ 0xbc,""     ,0,Disasm::Disasm_reserve },
	{ 0xbd,""     ,0,Disasm::Disasm_reserve },
	{ 0xbe,""     ,0,Disasm::Disasm_reserve },
	{ 0xbf,""     ,0,Disasm::Disasm_reserve },
	{ 0xc0,""     ,0,Disasm::Disasm_reserve },
	{ 0xc1,""     ,0,Disasm::Disasm_reserve },
	{ 0xc2,""     ,0,Disasm::Disasm_reserve },
	{ 0xc3,""     ,0,Disasm::Disasm_reserve },
	{ 0xc4,""     ,0,Disasm::Disasm_reserve },
	{ 0xc5,""     ,0,Disasm::Disasm_reserve },
	{ 0xc6,""     ,0,Disasm::Disasm_reserve },
	{ 0xc7,""     ,0,Disasm::Disasm_reserve },
	{ 0xc8,""     ,0,Disasm::Disasm_reserve },
	{ 0xc9,""     ,0,Disasm::Disasm_reserve },
	{ 0xca,""     ,0,Disasm::Disasm_reserve },
	{ 0xcb,""     ,0,Disasm::Disasm_reserve },
	{ 0xcc,"sha1rnds4"     ,PACK_OPERAND(THREE_OPERAND,AT__V,OT__dq,AT__W,OT__dq,AT__I,OT__b,0,0),Disasm::Disasm_THREE3A_gernel },
	{ 0xcd,""     ,0,Disasm::Disasm_reserve },
	{ 0xce,""     ,0,Disasm::Disasm_reserve },
	{ 0xcf,""     ,0,Disasm::Disasm_reserve },
	{ 0xd0,""     ,0,Disasm::Disasm_reserve },
	{ 0xd1,""     ,0,Disasm::Disasm_reserve },
	{ 0xd2,""     ,0,Disasm::Disasm_reserve },
	{ 0xd3,""     ,0,Disasm::Disasm_reserve },
	{ 0xd4,""     ,0,Disasm::Disasm_reserve },
	{ 0xd5,""     ,0,Disasm::Disasm_reserve },
	{ 0xd6,""     ,0,Disasm::Disasm_reserve },
	{ 0xd7,""     ,0,Disasm::Disasm_reserve },
	{ 0xd8,""     ,0,Disasm::Disasm_reserve },
	{ 0xd9,""     ,0,Disasm::Disasm_reserve },
	{ 0xda,""     ,0,Disasm::Disasm_reserve },
	{ 0xdb,""     ,0,Disasm::Disasm_reserve },
	{ 0xdc,""     ,0,Disasm::Disasm_reserve },
	{ 0xdd,""     ,0,Disasm::Disasm_reserve },
	{ 0xde,""     ,0,Disasm::Disasm_reserve },
	{ 0xdf,"vaeskeygen"     ,PACK_OPERAND(THREE_OPERAND,AT__V,OT__dq,AT__W,OT__dq,AT__I,OT__b,0,0),Disasm::Disasm_THREE3A_gernel },
	{ 0xe0,""     ,0,Disasm::Disasm_reserve },
	{ 0xe1,""     ,0,Disasm::Disasm_reserve },
	{ 0xe2,""     ,0,Disasm::Disasm_reserve },
	{ 0xe3,""     ,0,Disasm::Disasm_reserve },
	{ 0xe4,""     ,0,Disasm::Disasm_reserve },
	{ 0xe5,""     ,0,Disasm::Disasm_reserve },
	{ 0xe6,""     ,0,Disasm::Disasm_reserve },
	{ 0xe7,""     ,0,Disasm::Disasm_reserve },
	{ 0xe8,""     ,0,Disasm::Disasm_reserve },
	{ 0xe9,""     ,0,Disasm::Disasm_reserve },
	{ 0xea,""     ,0,Disasm::Disasm_reserve },
	{ 0xeb,""     ,0,Disasm::Disasm_reserve },
	{ 0xec,""     ,0,Disasm::Disasm_reserve },
	{ 0xed,""     ,0,Disasm::Disasm_reserve },
	{ 0xee,""     ,0,Disasm::Disasm_reserve },
	{ 0xef,""     ,0,Disasm::Disasm_reserve },
	{ 0xf0,"rorx"     ,PACK_OPERAND(THREE_OPERAND,AT__G,OT__y,AT__E,OT__y,AT__I,OT__b,0,0),Disasm::Disasm_THREE3A_gernel },
	{ 0xf1,""     ,0,Disasm::Disasm_reserve },
	{ 0xf2,""     ,0,Disasm::Disasm_reserve },
	{ 0xf3,""     ,0,Disasm::Disasm_reserve },
	{ 0xf4,""     ,0,Disasm::Disasm_reserve },
	{ 0xf5,""     ,0,Disasm::Disasm_reserve },
	{ 0xf6,""     ,0,Disasm::Disasm_reserve },
	{ 0xf7,""     ,0,Disasm::Disasm_reserve },
	{ 0xf8,""     ,0,Disasm::Disasm_reserve },
	{ 0xf9,""     ,0,Disasm::Disasm_reserve },
	{ 0xfa,""     ,0,Disasm::Disasm_reserve },
	{ 0xfb,""     ,0,Disasm::Disasm_reserve },
	{ 0xfc,""     ,0,Disasm::Disasm_reserve },
	{ 0xfd,""     ,0,Disasm::Disasm_reserve },
	{ 0xfe,""     ,0,Disasm::Disasm_reserve },
	{ 0xff,""     ,0,Disasm::Disasm_reserve },
};
