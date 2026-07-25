// TRANSPOSE8 converts eight ZMM rows into eight ZMM columns. Inputs R0..R7
// are destroyed; outputs O0..O7 must not alias scratch T0..T7.
#define TRANSPOSE8(R0, R1, R2, R3, R4, R5, R6, R7, O0, O1, O2, O3, O4, O5, O6, O7, T0, T1, T2, T3, T4, T5, T6, T7) \
	VSHUFI64X2 $0x88, R2, R0, T0; \
	VSHUFI64X2 $0x88, R3, R1, T1; \
	VSHUFI64X2 $0xdd, R2, R0, T2; \
	VSHUFI64X2 $0xdd, R3, R1, T3; \
	VSHUFI64X2 $0x88, R6, R4, T4; \
	VSHUFI64X2 $0x88, R7, R5, T5; \
	VSHUFI64X2 $0xdd, R6, R4, T6; \
	VSHUFI64X2 $0xdd, R7, R5, T7; \
	VSHUFI64X2 $0x88, T4, T0, R0; \
	VSHUFI64X2 $0x88, T5, T1, R1; \
	VSHUFI64X2 $0x88, T6, T2, R2; \
	VSHUFI64X2 $0x88, T7, T3, R3; \
	VSHUFI64X2 $0xdd, T4, T0, R4; \
	VSHUFI64X2 $0xdd, T5, T1, R5; \
	VSHUFI64X2 $0xdd, T6, T2, R6; \
	VSHUFI64X2 $0xdd, T7, T3, R7; \
	VPUNPCKLQDQ R1, R0, O0;       \
	VPUNPCKHQDQ R1, R0, O1;       \
	VPUNPCKLQDQ R3, R2, O2;       \
	VPUNPCKHQDQ R3, R2, O3;       \
	VPUNPCKLQDQ R5, R4, O4;       \
	VPUNPCKHQDQ R5, R4, O5;       \
	VPUNPCKLQDQ R7, R6, O6;       \
	VPUNPCKHQDQ R7, R6, O7
