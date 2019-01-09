#pragma once
/*
定义反汇编引擎的部分结构  TwoByteCodeMap 是基于intel手册2519页的Two-byte Opcode Map:进行整理的
*/
#include "Disasm_one.h"

static STR_MAP_CODE TwoByteCodeMap[] =
{
	{0x00,""     ,0,Disasm::Disasm_TWO_grp_0x00},
	{0x01,""     ,0,Disasm::Disasm_TWO_grp_0x01},
	{0x02,"lar"     ,PACK_OPERAND(TWO_OPERAND,AT__G,OT__v,AT__E,OT__w,0,0,0,0),Disasm::Disasm_ModRM},
	{0x03,"lsl"     ,PACK_OPERAND(TWO_OPERAND,AT__G,OT__v,AT__E,OT__w,0,0,0,0),Disasm::Disasm_ModRM},
	{0x04,""     ,0,Disasm::Disasm_reserve},
	{0x05,"syscall"     ,0,Disasm::Disasm_no_else},
	{0x06,"clts"     ,0,Disasm::Disasm_no_else},
	{0x07,"sysret"     ,0,Disasm::Disasm_no_else},
	{0x08,"invd"     ,0,Disasm::Disasm_no_else},
	{0x09,"wbinvd"     ,0,Disasm::Disasm_no_else},
	{0x0a,""     ,0,Disasm::Disasm_reserve},
	{0x0b,"#UD2"     ,0,Disasm::Disasm_no_else},
	{0x0c,""     ,0,Disasm::Disasm_reserve},
	{0x0d,"prefetchw"     ,PACK_OPERAND(ONE_OPERAND,AT__E,OT__v,0,0,0,0,0,0),Disasm::Disasm_ModRM},
	{0x0e,""     ,0,Disasm::Disasm_reserve},
	{0x0f,""     ,0,Disasm::Disasm_reserve},
	{ 0x10,""     ,0,Disasm::Disasm_TWO_0x10 },
	{ 0x11,""     ,0,Disasm::Disasm_TWO_0x11 },
	{ 0x12,""     ,0,Disasm::Disasm_TWO_0x12 },
	{ 0x13,""     ,PACK_OPERAND(TWO_OPERAND,AT__M,OT__q,AT__V,OT__q,0,0,0,0),Disasm::Disasm_TWO_0x13 },
	{ 0x14,""     ,PACK_OPERAND(THREE_OPERAND,AT__V,OT__x,AT__H,OT__x,AT__W,OT__x,0,0),Disasm::Disasm_TWO_0x14 },
	{ 0x15,""     ,PACK_OPERAND(THREE_OPERAND,AT__V,OT__x,AT__H,OT__x,AT__W,OT__x,0,0),Disasm::Disasm_TWO_0x15 },
	{ 0x16,""     ,0,Disasm::Disasm_TWO_0x16 },
	{ 0x17,""     ,PACK_OPERAND(TWO_OPERAND,AT__M,OT__q,AT__V,OT__q,0,0,0,0),Disasm::Disasm_TWO_0x17 },
	{ 0x18,""     ,0,Disasm::Disasm_TWO_grp_16 },
	{ 0x19,"nop"     ,0,Disasm::Disasm_no_else },
	{ 0x1a,""     ,0,Disasm::Disasm_TWO_0x1a },
	{ 0x1b,""     ,0,Disasm::Disasm_TWO_0x1b },
	{ 0x1c,"nop"     ,0,Disasm::Disasm_no_else },
	{ 0x1d,"nop"     ,0,Disasm::Disasm_no_else },
	{ 0x1e,"nop"     ,0,Disasm::Disasm_no_else },
	{ 0x1f,"nop"     ,PACK_OPERAND(ONE_OPERAND,AT__E,OT__v,0,0,0,0,0,0),Disasm::Disasm_ModRM },
	{ 0x20,"mov"     ,PACK_OPERAND(TWO_OPERAND,AT__R,OT__d,AT__C,OT__d,0,0,0,0),Disasm::Disasm_ModRM },
	{ 0x21,"mov"     ,PACK_OPERAND(TWO_OPERAND,AT__R,OT__d,AT__D,OT__d,0,0,0,0),Disasm::Disasm_ModRM },
	{ 0x22,"mov"     ,PACK_OPERAND(TWO_OPERAND,AT__C,OT__d,AT__R,OT__d,0,0,0,0),Disasm::Disasm_ModRM },
	{ 0x23,"mov"     ,PACK_OPERAND(TWO_OPERAND,AT__D,OT__d,AT__R,OT__d,0,0,0,0),Disasm::Disasm_ModRM },
	{ 0x24,""     ,0,Disasm::Disasm_reserve },
	{ 0x25,""     ,0,Disasm::Disasm_reserve },
	{ 0x26,""     ,0,Disasm::Disasm_reserve },
	{ 0x27,""     ,0,Disasm::Disasm_reserve },
	{ 0x28,""     ,0,Disasm::Disasm_TWO_0x28 },
	{ 0x29,""     ,0,Disasm::Disasm_TWO_0x29 },
	{ 0x2a,""     ,0,Disasm::Disasm_TWO_0x2a },
	{ 0x2b,""     ,0,Disasm::Disasm_TWO_0x2b },
	{ 0x2c,""     ,0,Disasm::Disasm_TWO_0x2c },
	{ 0x2d,""     ,0,Disasm::Disasm_TWO_0x2d },
	{ 0x2e,""     ,0,Disasm::Disasm_TWO_0x2e_0x2f },
	{ 0x2f,""     ,0,Disasm::Disasm_TWO_0x2e_0x2f },
	{ 0x30,"wrmsr"     ,0,Disasm::Disasm_no_else },
	{ 0x31,"rdtsc"     ,0,Disasm::Disasm_no_else },
	{ 0x32,"rdmsr"     ,0,Disasm::Disasm_no_else },
	{ 0x33,"rdpmc"     ,0,Disasm::Disasm_no_else },
	{ 0x34,"sysenter"     ,0,Disasm::Disasm_no_else },
	{ 0x35,"sysexit"     ,0,Disasm::Disasm_no_else },
	{ 0x36,""     ,0,Disasm::Disasm_reserve },
	{ 0x37,"getsec"     ,0,Disasm::Disasm_no_else },
	{ 0x38,""     ,0,Disasm::Disasm_TWO_three_opcode38 },
	{ 0x39,""     ,0,Disasm::Disasm_reserve },
	{ 0x3a,""     ,0,Disasm::Disasm_TWO_three_opcode3A },
	{ 0x3b,""     ,0,Disasm::Disasm_reserve },
	{ 0x3c,""     ,0,Disasm::Disasm_reserve },
	{ 0x3d,""     ,0,Disasm::Disasm_reserve },
	{ 0x3e,""     ,0,Disasm::Disasm_reserve },
	{ 0x3f,""     ,0,Disasm::Disasm_reserve },
	{ 0x40,"cmovo"     ,PACK_OPERAND(TWO_OPERAND,AT__G,OT__v,AT__E,OT__v,0,0,0,0),Disasm::Disasm_ModRM },
	{ 0x41,"cmovno"     ,PACK_OPERAND(TWO_OPERAND,AT__G,OT__v,AT__E,OT__v,0,0,0,0),Disasm::Disasm_ModRM },
	{ 0x42,"cmovb"     ,PACK_OPERAND(TWO_OPERAND,AT__G,OT__v,AT__E,OT__v,0,0,0,0),Disasm::Disasm_ModRM },
	{ 0x43,"cmovnb"     ,PACK_OPERAND(TWO_OPERAND,AT__G,OT__v,AT__E,OT__v,0,0,0,0),Disasm::Disasm_ModRM },
	{ 0x44,"cmove"     ,PACK_OPERAND(TWO_OPERAND,AT__G,OT__v,AT__E,OT__v,0,0,0,0),Disasm::Disasm_ModRM },
	{ 0x45,"cmovne"     ,PACK_OPERAND(TWO_OPERAND,AT__G,OT__v,AT__E,OT__v,0,0,0,0),Disasm::Disasm_ModRM },
	{ 0x46,"cmovbe"     ,PACK_OPERAND(TWO_OPERAND,AT__G,OT__v,AT__E,OT__v,0,0,0,0),Disasm::Disasm_ModRM },
	{ 0x47,"cmova"     ,PACK_OPERAND(TWO_OPERAND,AT__G,OT__v,AT__E,OT__v,0,0,0,0),Disasm::Disasm_ModRM },
	{ 0x48,"cmovs"     ,PACK_OPERAND(TWO_OPERAND,AT__G,OT__v,AT__E,OT__v,0,0,0,0),Disasm::Disasm_ModRM },
	{ 0x49,"cmovns"     ,PACK_OPERAND(TWO_OPERAND,AT__G,OT__v,AT__E,OT__v,0,0,0,0),Disasm::Disasm_ModRM },
	{ 0x4a,"cmovp"     ,PACK_OPERAND(TWO_OPERAND,AT__G,OT__v,AT__E,OT__v,0,0,0,0),Disasm::Disasm_ModRM },
	{ 0x4b,"cmovnp"     ,PACK_OPERAND(TWO_OPERAND,AT__G,OT__v,AT__E,OT__v,0,0,0,0),Disasm::Disasm_ModRM },
	{ 0x4c,"cmovl"     ,PACK_OPERAND(TWO_OPERAND,AT__G,OT__v,AT__E,OT__v,0,0,0,0),Disasm::Disasm_ModRM },
	{ 0x4d,"cmovnl"     ,PACK_OPERAND(TWO_OPERAND,AT__G,OT__v,AT__E,OT__v,0,0,0,0),Disasm::Disasm_ModRM },
	{ 0x4e,"cmovng"     ,PACK_OPERAND(TWO_OPERAND,AT__G,OT__v,AT__E,OT__v,0,0,0,0),Disasm::Disasm_ModRM },
	{ 0x4f,"cmovg"     ,PACK_OPERAND(TWO_OPERAND,AT__G,OT__v,AT__E,OT__v,0,0,0,0),Disasm::Disasm_ModRM },
	{ 0x50,""     ,0,Disasm::Disasm_TWO_0x50 },
	{ 0x51,""     ,0,Disasm::Disasm_TWO_0x51 },
	{ 0x52,""     ,0,Disasm::Disasm_TWO_0x52_0x53 },
	{ 0x53,""     ,0,Disasm::Disasm_TWO_0x52_0x53 },
	{ 0x54,""     ,0,Disasm::Disasm_TWO_0x54_0x55_0x56_0x57 },
	{ 0x55,""     ,0,Disasm::Disasm_TWO_0x54_0x55_0x56_0x57 },
	{ 0x56,""     ,0,Disasm::Disasm_TWO_0x54_0x55_0x56_0x57 },
	{ 0x57,""     ,0,Disasm::Disasm_TWO_0x54_0x55_0x56_0x57 },
	{ 0x58,""     ,0,Disasm::Disasm_TWO_0x58_0x59_0x5c_0x5d_0x5e_0x5f },
	{ 0x59,""     ,0,Disasm::Disasm_TWO_0x58_0x59_0x5c_0x5d_0x5e_0x5f },
	{ 0x5a,""     ,0,Disasm::Disasm_TWO_0x5a },
	{ 0x5b,""     ,0,Disasm::Disasm_TWO_0x5b },
	{ 0x5c,""     ,0,Disasm::Disasm_TWO_0x58_0x59_0x5c_0x5d_0x5e_0x5f },
	{ 0x5d,""     ,0,Disasm::Disasm_TWO_0x58_0x59_0x5c_0x5d_0x5e_0x5f },
	{ 0x5e,""     ,0,Disasm::Disasm_TWO_0x58_0x59_0x5c_0x5d_0x5e_0x5f },
	{ 0x5f,""     ,0,Disasm::Disasm_TWO_0x58_0x59_0x5c_0x5d_0x5e_0x5f },
	{ 0x60,""     ,0,Disasm::Disasm_TWO_0x6x_0xdx_0xex_0xfx },
	{ 0x61,""     ,0,Disasm::Disasm_TWO_0x6x_0xdx_0xex_0xfx },
	{ 0x62,""     ,0,Disasm::Disasm_TWO_0x6x_0xdx_0xex_0xfx },
	{ 0x63,""     ,0,Disasm::Disasm_TWO_0x6x_0xdx_0xex_0xfx },
	{ 0x64,""     ,0,Disasm::Disasm_TWO_0x6x_0xdx_0xex_0xfx },
	{ 0x65,""     ,0,Disasm::Disasm_TWO_0x6x_0xdx_0xex_0xfx },
	{ 0x66,""     ,0,Disasm::Disasm_TWO_0x6x_0xdx_0xex_0xfx },
	{ 0x67,""     ,0,Disasm::Disasm_TWO_0x6x_0xdx_0xex_0xfx },
	{ 0x68,""     ,0,Disasm::Disasm_TWO_0x6x_0xdx_0xex_0xfx },
	{ 0x69,""     ,0,Disasm::Disasm_TWO_0x6x_0xdx_0xex_0xfx },
	{ 0x6a,""     ,0,Disasm::Disasm_TWO_0x6x_0xdx_0xex_0xfx },
	{ 0x6b,""     ,0,Disasm::Disasm_TWO_0x6x_0xdx_0xex_0xfx },
	{ 0x6c,""     ,0,Disasm::Disasm_TWO_0x6x_0xdx_0xex_0xfx },
	{ 0x6d,""     ,0,Disasm::Disasm_TWO_0x6x_0xdx_0xex_0xfx },
	{ 0x6e,""     ,0,Disasm::Disasm_TWO_0x6x_0xdx_0xex_0xfx },
	{ 0x6f,""     ,0,Disasm::Disasm_TWO_0x6x_0xdx_0xex_0xfx },
	{ 0x70,""     ,0,Disasm::Disasm_TWO_0x70 },
	{ 0x71,""     ,0,Disasm::Disasm_TWO_grp12_grp13_grp14 },
	{ 0x72,""     ,0,Disasm::Disasm_TWO_grp12_grp13_grp14 },
	{ 0x73,""     ,0,Disasm::Disasm_TWO_grp12_grp13_grp14 },
	{ 0x74,""     ,0,Disasm::Disasm_TWO_0x74_0x75_0x76 },
	{ 0x75,""     ,0,Disasm::Disasm_TWO_0x74_0x75_0x76 },
	{ 0x76,""     ,0,Disasm::Disasm_TWO_0x74_0x75_0x76 },
	{ 0x77,""     ,0,Disasm::GernelDisasm },
	{ 0x78,"vmread"     ,PACK_OPERAND(TWO_OPERAND,AT__E,OT__v,AT__G,OT__y,0,0,0,0),Disasm::Disasm_ModRM },
	{ 0x79,"vmwrite"    ,PACK_OPERAND(TWO_OPERAND,AT__E,OT__v,AT__G,OT__y,0,0,0,0),Disasm::Disasm_ModRM },
	{ 0x7a,""     ,0,Disasm::Disasm_reserve },
	{ 0x7b,""     ,0,Disasm::Disasm_reserve },
	{ 0x7c,""     ,0,Disasm::Disasm_TWO_0x7c_0x7d },
	{ 0x7d,""     ,0,Disasm::Disasm_TWO_0x7c_0x7d },
	{ 0x7e,""     ,0,Disasm::Disasm_TWO_0x7e },
	{ 0x7f,""     ,0,Disasm::Disasm_TWO_0x7f },
	{ 0x80,"jo"     ,PACK_OPERAND(ONE_OPERAND,AT__J,OT__z,0,0,0,0,0,0),Disasm::Disasm_reg_or_imm },
	{ 0x81,"jno"    ,PACK_OPERAND(ONE_OPERAND,AT__J,OT__z,0,0,0,0,0,0),Disasm::Disasm_reg_or_imm },
	{ 0x82,"jb"     ,PACK_OPERAND(ONE_OPERAND,AT__J,OT__z,0,0,0,0,0,0),Disasm::Disasm_reg_or_imm },
	{ 0x83,"jae"    ,PACK_OPERAND(ONE_OPERAND,AT__J,OT__z,0,0,0,0,0,0),Disasm::Disasm_reg_or_imm },
	{ 0x84,"je"     ,PACK_OPERAND(ONE_OPERAND,AT__J,OT__z,0,0,0,0,0,0),Disasm::Disasm_reg_or_imm },
	{ 0x85,"jne"    ,PACK_OPERAND(ONE_OPERAND,AT__J,OT__z,0,0,0,0,0,0),Disasm::Disasm_reg_or_imm },
	{ 0x86,"jbe"    ,PACK_OPERAND(ONE_OPERAND,AT__J,OT__z,0,0,0,0,0,0),Disasm::Disasm_reg_or_imm },
	{ 0x87,"ja"     ,PACK_OPERAND(ONE_OPERAND,AT__J,OT__z,0,0,0,0,0,0),Disasm::Disasm_reg_or_imm },
	{ 0x88,"js"     ,PACK_OPERAND(ONE_OPERAND,AT__J,OT__z,0,0,0,0,0,0),Disasm::Disasm_reg_or_imm },
	{ 0x89,"jns"    ,PACK_OPERAND(ONE_OPERAND,AT__J,OT__z,0,0,0,0,0,0),Disasm::Disasm_reg_or_imm },
	{ 0x8a,"jp"     ,PACK_OPERAND(ONE_OPERAND,AT__J,OT__z,0,0,0,0,0,0),Disasm::Disasm_reg_or_imm },
	{ 0x8b,"jnp"    ,PACK_OPERAND(ONE_OPERAND,AT__J,OT__z,0,0,0,0,0,0),Disasm::Disasm_reg_or_imm },
	{ 0x8c,"jl"     ,PACK_OPERAND(ONE_OPERAND,AT__J,OT__z,0,0,0,0,0,0),Disasm::Disasm_reg_or_imm },
	{ 0x8d,"jnl"    ,PACK_OPERAND(ONE_OPERAND,AT__J,OT__z,0,0,0,0,0,0),Disasm::Disasm_reg_or_imm },
	{ 0x8e,"jle"    ,PACK_OPERAND(ONE_OPERAND,AT__J,OT__z,0,0,0,0,0,0),Disasm::Disasm_reg_or_imm },
	{ 0x8f,"jg"     ,PACK_OPERAND(ONE_OPERAND,AT__J,OT__z,0,0,0,0,0,0),Disasm::Disasm_reg_or_imm },
	{ 0x90,"seto"     ,PACK_OPERAND(ONE_OPERAND,AT__E,OT__b,0,0,0,0,0,0),Disasm::Disasm_ModRM },
	{ 0x91,"setno"     ,PACK_OPERAND(ONE_OPERAND,AT__E,OT__b,0,0,0,0,0,0),Disasm::Disasm_ModRM },
	{ 0x92,"setb"     ,PACK_OPERAND(ONE_OPERAND,AT__E,OT__b,0,0,0,0,0,0),Disasm::Disasm_ModRM },
	{ 0x93,"setnb"     ,PACK_OPERAND(ONE_OPERAND,AT__E,OT__b,0,0,0,0,0,0),Disasm::Disasm_ModRM },
	{ 0x94,"sete"     ,PACK_OPERAND(ONE_OPERAND,AT__E,OT__b,0,0,0,0,0,0),Disasm::Disasm_ModRM },
	{ 0x95,"setne"     ,PACK_OPERAND(ONE_OPERAND,AT__E,OT__b,0,0,0,0,0,0),Disasm::Disasm_ModRM },
	{ 0x96,"setbe"     ,PACK_OPERAND(ONE_OPERAND,AT__E,OT__b,0,0,0,0,0,0),Disasm::Disasm_ModRM },
	{ 0x97,"seta"     ,PACK_OPERAND(ONE_OPERAND,AT__E,OT__b,0,0,0,0,0,0),Disasm::Disasm_ModRM },
	{ 0x98,"sets"     ,PACK_OPERAND(ONE_OPERAND,AT__E,OT__b,0,0,0,0,0,0),Disasm::Disasm_ModRM },
	{ 0x99,"setns"     ,PACK_OPERAND(ONE_OPERAND,AT__E,OT__b,0,0,0,0,0,0),Disasm::Disasm_ModRM },
	{ 0x9a,"setp"     ,PACK_OPERAND(ONE_OPERAND,AT__E,OT__b,0,0,0,0,0,0),Disasm::Disasm_ModRM },
	{ 0x9b,"setnp"     ,PACK_OPERAND(ONE_OPERAND,AT__E,OT__b,0,0,0,0,0,0),Disasm::Disasm_ModRM },
	{ 0x9c,"setl"     ,PACK_OPERAND(ONE_OPERAND,AT__E,OT__b,0,0,0,0,0,0),Disasm::Disasm_ModRM },
	{ 0x9d,"setnl"     ,PACK_OPERAND(ONE_OPERAND,AT__E,OT__b,0,0,0,0,0,0),Disasm::Disasm_ModRM },
	{ 0x9e,"setle"     ,PACK_OPERAND(ONE_OPERAND,AT__E,OT__b,0,0,0,0,0,0),Disasm::Disasm_ModRM },
	{ 0x9f,"setg"     ,PACK_OPERAND(ONE_OPERAND,AT__E,OT__b,0,0,0,0,0,0),Disasm::Disasm_ModRM },
	{ 0xa0,"push"     ,PACK_OPERAND(ONE_OPERAND,AT_XX,RG__FS,0,0,0,0,0,0),Disasm::Disasm_reg_or_imm },
	{ 0xa1,"pop"     ,PACK_OPERAND(ONE_OPERAND,AT_XX,RG__FS,0,0,0,0,0,0),Disasm::Disasm_reg_or_imm },
	{ 0xa2,"cpuid"     ,0,Disasm::Disasm_no_else },
	{ 0xa3,"bt"     ,PACK_OPERAND(TWO_OPERAND,AT__E,OT__v,AT__G,OT__v,0,0,0,0),Disasm::Disasm_ModRM },
	{ 0xa4,"shld"     ,PACK_OPERAND(THREE_OPERAND,AT__E,OT__v,AT__G,OT__v,AT__I,OT__b,0,0),Disasm::GernelDisasm },
	{ 0xa5,"shld"     ,PACK_OPERAND(THREE_OPERAND,AT__E,OT__v,AT__G,OT__v,AT__REG8,RG8__CL,0,0),Disasm::GernelDisasm },
	{ 0xa6,""     ,0,Disasm::Disasm_reserve },
	{ 0xa7,""     ,0,Disasm::Disasm_reserve },
	{ 0xa8,"push"     ,PACK_OPERAND(ONE_OPERAND,AT_XX,RG__GS,0,0,0,0,0,0),Disasm::Disasm_reg_or_imm },
	{ 0xa9,"pop"     ,PACK_OPERAND(ONE_OPERAND,AT_XX,RG__GS,0,0,0,0,0,0),Disasm::Disasm_reg_or_imm },
	{ 0xaa,"rsm"     ,0,Disasm::Disasm_no_else },
	{ 0xab,"bts"     ,PACK_OPERAND(TWO_OPERAND,AT__E,OT__v,AT__G,OT__v,0,0,0,0),Disasm::Disasm_ModRM },
	{ 0xac,"shrd"     ,PACK_OPERAND(THREE_OPERAND,AT__E,OT__v,AT__G,OT__v,AT__I,OT__b,0,0),Disasm::GernelDisasm },
	{ 0xad,"shrd"     ,PACK_OPERAND(THREE_OPERAND,AT__E,OT__v,AT__G,OT__v,AT__REG8,RG8__CL,0,0),Disasm::GernelDisasm },
	{ 0xae,""     ,0,Disasm::Disasm_TWO_grp_0xae },
	{ 0xaf,"imul"     ,PACK_OPERAND(TWO_OPERAND,AT__G,OT__v,AT__E,OT__v,0,0,0,0),Disasm::Disasm_ModRM },
	{ 0xb0,"cmpxchg"     ,PACK_OPERAND(TWO_OPERAND,AT__E,OT__b,AT__G,OT__b,0,0,0,0),Disasm::Disasm_ModRM },
	{ 0xb1,"cmpxchg"     ,PACK_OPERAND(TWO_OPERAND,AT__E,OT__v,AT__G,OT__v,0,0,0,0),Disasm::Disasm_ModRM },
	{ 0xb2,"lss"     ,PACK_OPERAND(TWO_OPERAND,AT__G,OT__v,AT__M,OT__p,0,0,0,0),Disasm::GernelDisasm },
	{ 0xb3,"btr"     ,PACK_OPERAND(TWO_OPERAND,AT__E,OT__v,AT__G,OT__v,0,0,0,0),Disasm::Disasm_ModRM },
	{ 0xb4,"lfs"     ,PACK_OPERAND(TWO_OPERAND,AT__G,OT__v,AT__M,OT__p,0,0,0,0),Disasm::GernelDisasm },
	{ 0xb5,"lgs"     ,PACK_OPERAND(TWO_OPERAND,AT__G,OT__v,AT__M,OT__p,0,0,0,0),Disasm::GernelDisasm },
	{ 0xb6,"movzx"     ,PACK_OPERAND(TWO_OPERAND,AT__G,OT__v,AT__E,OT__b,0,0,0,0),Disasm::Disasm_ModRM },
	{ 0xb7,"movzx"     ,PACK_OPERAND(TWO_OPERAND,AT__G,OT__v,AT__E,OT__w,0,0,0,0),Disasm::Disasm_ModRM },
	{ 0xb8,""     ,PACK_OPERAND(TWO_OPERAND,AT__E,OT__v,AT__G,OT__v,0,0,0,0),Disasm::GernelDisasm },
	{ 0xb9,"#UD1"     ,0,Disasm::Disasm_no_else },
	{ 0xba,""     ,0,Disasm::GernelDisasm },
	{ 0xbb,""     ,PACK_OPERAND(TWO_OPERAND,AT__E,OT__v,AT__G,OT__v,0,0,0,0),Disasm::GernelDisasm },
	{ 0xbc,""     ,PACK_OPERAND(TWO_OPERAND,AT__E,OT__v,AT__G,OT__v,0,0,0,0),Disasm::GernelDisasm },
	{ 0xbd,""     ,PACK_OPERAND(TWO_OPERAND,AT__E,OT__v,AT__G,OT__v,0,0,0,0),Disasm::GernelDisasm },
	{ 0xbe,"movsx"     ,PACK_OPERAND(TWO_OPERAND,AT__G,OT__v,AT__E,OT__b,0,0,0,0),Disasm::Disasm_ModRM },
	{ 0xbf,"movsx"     ,PACK_OPERAND(TWO_OPERAND,AT__G,OT__v,AT__E,OT__w,0,0,0,0),Disasm::Disasm_ModRM },
	{ 0xc0,"xadd"     ,PACK_OPERAND(TWO_OPERAND,AT__E,OT__b,AT__G,OT__b,0,0,0,0),Disasm::Disasm_TWO_0xc0_0xc1_0xc3 },
	{ 0xc1,"xadd"     ,PACK_OPERAND(TWO_OPERAND,AT__E,OT__v,AT__G,OT__v,0,0,0,0),Disasm::Disasm_TWO_0xc0_0xc1_0xc3 },
	{ 0xc2,""     ,0,Disasm::Disasm_TWO_0xc2 },
	{ 0xc3,"movnti"     ,0,Disasm::Disasm_TWO_0xc0_0xc1_0xc3 },
	{ 0xc4,""     ,0,Disasm::Disasm_TWO_0xc4 },
	{ 0xc5,""     ,0,Disasm::Disasm_TWO_0xc5 },
	{ 0xc6,""     ,0,Disasm::Disasm_TWO_0xc6 },
	{ 0xc7,""     ,0,Disasm::Disasm_TWO_grp9 },
	{ 0xc8,"bswap"     ,PACK_OPERAND(ONE_OPERAND,AT_rXX,RG__AX,0,0,0,0,0,0),Disasm::Disasm_TWO_0xc8_0xcf },
	{ 0xc9,"bswap"     ,PACK_OPERAND(ONE_OPERAND,AT_rXX,RG__CX,0,0,0,0,0,0),Disasm::Disasm_TWO_0xc8_0xcf },
	{ 0xca,"bswap"     ,PACK_OPERAND(ONE_OPERAND,AT_rXX,RG__DX,0,0,0,0,0,0),Disasm::Disasm_TWO_0xc8_0xcf },
	{ 0xcb,"bswap"     ,PACK_OPERAND(ONE_OPERAND,AT_rXX,RG__BX,0,0,0,0,0,0),Disasm::Disasm_TWO_0xc8_0xcf },
	{ 0xcc,"bswap"     ,PACK_OPERAND(ONE_OPERAND,AT_rXX,RG__SP,0,0,0,0,0,0),Disasm::Disasm_TWO_0xc8_0xcf },
	{ 0xcd,"bswap"     ,PACK_OPERAND(ONE_OPERAND,AT_rXX,RG__BP,0,0,0,0,0,0),Disasm::Disasm_TWO_0xc8_0xcf },
	{ 0xce,"bswap"     ,PACK_OPERAND(ONE_OPERAND,AT_rXX,RG__SI,0,0,0,0,0,0),Disasm::Disasm_TWO_0xc8_0xcf },
	{ 0xcf,"bswap"     ,PACK_OPERAND(ONE_OPERAND,AT_rXX,RG__DI,0,0,0,0,0,0),Disasm::Disasm_TWO_0xc8_0xcf },
	{ 0xd0,""     ,0,Disasm::Disasm_TWO_0x6x_0xdx_0xex_0xfx },
	{ 0xd1,""     ,0,Disasm::Disasm_TWO_0x6x_0xdx_0xex_0xfx },
	{ 0xd2,""     ,0,Disasm::Disasm_TWO_0x6x_0xdx_0xex_0xfx },
	{ 0xd3,""     ,0,Disasm::Disasm_TWO_0x6x_0xdx_0xex_0xfx },
	{ 0xd4,""     ,0,Disasm::Disasm_TWO_0x6x_0xdx_0xex_0xfx },
	{ 0xd5,""     ,0,Disasm::Disasm_TWO_0x6x_0xdx_0xex_0xfx },
	{ 0xd6,""     ,0,Disasm::Disasm_TWO_0x6x_0xdx_0xex_0xfx },
	{ 0xd7,""     ,0,Disasm::Disasm_TWO_0x6x_0xdx_0xex_0xfx },
	{ 0xd8,""     ,0,Disasm::Disasm_TWO_0x6x_0xdx_0xex_0xfx },
	{ 0xd9,""     ,0,Disasm::Disasm_TWO_0x6x_0xdx_0xex_0xfx },
	{ 0xda,""     ,0,Disasm::Disasm_TWO_0x6x_0xdx_0xex_0xfx },
	{ 0xdb,""     ,0,Disasm::Disasm_TWO_0x6x_0xdx_0xex_0xfx },
	{ 0xdc,""     ,0,Disasm::Disasm_TWO_0x6x_0xdx_0xex_0xfx },
	{ 0xdd,""     ,0,Disasm::Disasm_TWO_0x6x_0xdx_0xex_0xfx },
	{ 0xde,""     ,0,Disasm::Disasm_TWO_0x6x_0xdx_0xex_0xfx },
	{ 0xdf,""     ,0,Disasm::Disasm_TWO_0x6x_0xdx_0xex_0xfx },
	{ 0xe0,""     ,0,Disasm::Disasm_TWO_0x6x_0xdx_0xex_0xfx },
	{ 0xe1,""     ,0,Disasm::Disasm_TWO_0x6x_0xdx_0xex_0xfx },
	{ 0xe2,""     ,0,Disasm::Disasm_TWO_0x6x_0xdx_0xex_0xfx },
	{ 0xe3,""     ,0,Disasm::Disasm_TWO_0x6x_0xdx_0xex_0xfx },
	{ 0xe4,""     ,0,Disasm::Disasm_TWO_0x6x_0xdx_0xex_0xfx },
	{ 0xe5,""     ,0,Disasm::Disasm_TWO_0x6x_0xdx_0xex_0xfx },
	{ 0xe6,""     ,0,Disasm::Disasm_TWO_0x6x_0xdx_0xex_0xfx },
	{ 0xe7,""     ,0,Disasm::Disasm_TWO_0x6x_0xdx_0xex_0xfx },
	{ 0xe8,""     ,0,Disasm::Disasm_TWO_0x6x_0xdx_0xex_0xfx },
	{ 0xe9,""     ,0,Disasm::Disasm_TWO_0x6x_0xdx_0xex_0xfx },
	{ 0xea,""     ,0,Disasm::Disasm_TWO_0x6x_0xdx_0xex_0xfx },
	{ 0xeb,""     ,0,Disasm::Disasm_TWO_0x6x_0xdx_0xex_0xfx },
	{ 0xec,""     ,0,Disasm::Disasm_TWO_0x6x_0xdx_0xex_0xfx },
	{ 0xed,""     ,0,Disasm::Disasm_TWO_0x6x_0xdx_0xex_0xfx },
	{ 0xee,""     ,0,Disasm::Disasm_TWO_0x6x_0xdx_0xex_0xfx },
	{ 0xef,""     ,0,Disasm::Disasm_TWO_0x6x_0xdx_0xex_0xfx },
	{ 0xf0,""     ,0,Disasm::Disasm_TWO_0x6x_0xdx_0xex_0xfx },
	{ 0xf1,""     ,0,Disasm::Disasm_TWO_0x6x_0xdx_0xex_0xfx },
	{ 0xf2,""     ,0,Disasm::Disasm_TWO_0x6x_0xdx_0xex_0xfx },
	{ 0xf3,""     ,0,Disasm::Disasm_TWO_0x6x_0xdx_0xex_0xfx },
	{ 0xf4,""     ,0,Disasm::Disasm_TWO_0x6x_0xdx_0xex_0xfx },
	{ 0xf5,""     ,0,Disasm::Disasm_TWO_0x6x_0xdx_0xex_0xfx },
	{ 0xf6,""     ,0,Disasm::Disasm_TWO_0x6x_0xdx_0xex_0xfx },
	{ 0xf7,""     ,0,Disasm::Disasm_TWO_0x6x_0xdx_0xex_0xfx },
	{ 0xf8,""     ,0,Disasm::Disasm_TWO_0x6x_0xdx_0xex_0xfx },
	{ 0xf9,""     ,0,Disasm::Disasm_TWO_0x6x_0xdx_0xex_0xfx },
	{ 0xfa,""     ,0,Disasm::Disasm_TWO_0x6x_0xdx_0xex_0xfx },
	{ 0xfb,""     ,0,Disasm::Disasm_TWO_0x6x_0xdx_0xex_0xfx },
	{ 0xfc,""     ,0,Disasm::Disasm_TWO_0x6x_0xdx_0xex_0xfx },
	{ 0xfd,""     ,0,Disasm::Disasm_TWO_0x6x_0xdx_0xex_0xfx },
	{ 0xfe,""     ,0,Disasm::Disasm_TWO_0x6x_0xdx_0xex_0xfx },
	{ 0xff,"#UD0"     ,0,Disasm::Disasm_no_else },
};
