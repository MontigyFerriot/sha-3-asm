; SHA-3 is a member of family of cryptograhic hash standards "Secure Hash Algorithm".
; Underneath it is based on the Keccak algorithm - a versatile cryptographic function.
; It can be used for authentication, (authenticated) encryption and pseudo-random number generation.
; Its structure is the extremely simple sponge construction and internally
; it uses the innovative Keccak-f cryptographic permutation.
.data
keccakf_piln:
        dd   10
        dd   7
        dd   11
        dd   17
        dd   18
        dd   3
        dd   5
        dd   16
        dd   8
        dd   21
        dd   24
        dd   4
        dd   15
        dd   23
        dd   19
        dd   13
        dd   12
        dd   2
        dd   20
        dd   14
        dd   22
        dd   9
        dd   6
        dd   1
keccakf_rotc:
        dd   1
        dd   3
        dd   6
        dd   10
        dd   15
        dd   21
        dd   28
        dd   36
        dd   45
        dd   55
        dd   2
        dd   14
        dd   27
        dd   41
        dd   56
        dd   8
        dd   25
        dd   43
        dd   62
        dd   18
        dd   39
        dd   61
        dd   20
        dd   44
keccakf_rndc:
        dq   1
        dq   32898
        dq   -9223372036854742902
        dq   -9223372034707259392
        dq   32907
        dq   2147483649
        dq   -9223372034707259263
        dq   -9223372036854743031
        dq   138
        dq   136
        dq   2147516425
        dq   2147483658
        dq   2147516555
        dq   -9223372036854775669
        dq   -9223372036854742903
        dq   -9223372036854743037
        dq   -9223372036854743038
        dq   -9223372036854775680
        dq   32778
        dq   -9223372034707292150
        dq   -9223372034707259263
        dq   -9223372036854742912
        dq   2147483649
        dq   -9223372034707259384
.code

; mod5(n) - optimized modulo computation
; reg1 - input value n
; reg2 - return value is stored here
; rdi - must hold 0xcccccccd div 10 constant
;
; for a % b modulo optimization is:
; a - (a / b) * b
;
; for (x + 4) % 5:
; ->	(x + 4) - ((x + 4) / 5) * 5
; ->	(x + 4) - (((x + 4) * 0xcccccccd) >> 34) * 5
mod5 macro reg1, reg2
	mov reg2, reg1
	imul reg1, rdi               ; N * 0xcccccccd
	shr reg1, 34		     ; (3N * 0xcccccccd) >> 34
	;lea rcx, [rcx + 4 * rcx]    ; 5 * (3N * 0xcccccccd) >> 34
	imul reg1, 5
	sub reg2, reg1               ; N - 5 * 5 * (3N * 0xcccccccd) >> 34
				     ; which finally is N % 5
endm

; mod5_sse(n) - 32 bit sse version of mod5() method
; reg1 - first input value. Result is stored in the same register.
; reg2 - second input value. Result is stored in the same register.
; rdi - required for computations inside function.
mod5_sse macro reg1,reg2
    	; store arguments in xmm0
    	pinsrq xmm0, reg1, 1
	pinsrq xmm0, reg2, 0

    	; store division constant 0xcccd twice in xmm1 for mul operation
	mov rdi, 52429
	pinsrq xmm1, rdi, 1
	pinsrq xmm1, rdi, 0

    	; store value 18 twice in xmm2 for shift right operation
	mov rdi, 18
	pinsrq xmm2, rdi, 1
	pinsrq xmm2, rdi, 0

	pmuldq	xmm0, xmm1              ; N * 0xcccd

    	; store value 5 twice in xmm3 for mul operation
	mov rdi, 5
	pinsrq xmm3, rdi, 1
	pinsrq xmm3, rdi, 0

	psrad	xmm0, xmm2              ; (N * 0xcccd) >> 34

	pmuldq	xmm0, xmm3              ; 5 * ((N * 0xcccd) >> 34)

    	; store arguments in xmm0 for subtraction
	pinsrq xmm1, reg1, 1
	pinsrq xmm1, reg2, 0

	psubq	xmm1, xmm0              ; N - 5 * ((N * 0xcccd) >> 34)

    	; store results back into the registers
	pextrq reg1, xmm1, 1
	pextrq reg2, xmm1, 0
endm

; keccakf(ulong *state) - keccak-f permutation function. The provided state is permuted.
; arguments:
; rcx - pointer to the state array
; return: none
; modified registers: rax, rdx, r8
keccakf proc EXPORT
        push    r15
        push    r14
        push    r13
        push    r12
        push    rbp
        push    rbx
        mov     r9, rcx 		        ; r9  = &state[0]
        lea     r10, [rcx+40] 		    	; r10 = &state[5]
        lea     r11, [keccakf_rndc+8] 		; r11 = &keccakf_rndc[1]
        lea     r13, [keccakf_rndc+192] 	; r13 = &keccakf_rndc[24]
        lea     r12, [rcx+8] 		    	; r12 = &state[1]
        lea     rbp, [rcx+200] 		    	; rbp = &state[25] (out of loop)
        mov     rbx, 1 			        ; rbx = keccakf_rndc[0]
rounds:
        mov     rcx, r9                 ; &state[0] into rcx
        lea     rsi, [rsp-56]           ; load &bc[0] into rsi
        mov     r8, r9                  ; mov &state[0] into r8
first_theta_loop:
	; bc[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        mov     rax, [rcx]                      ; rax = state[x]
        xor     rax, [rcx+40]                   ; xor with state[x + 5]
        xor     rax, [rcx+80]                   ; xor with state[x + 10]
        xor     rax, [rcx+120]                  ; xor with state[x + 15]
        xor     rax, [rcx+160]                  ; xor with state[x + 20]
        mov     [rsi], rax                      ; bc[x] = state[x]
        cmp     r10, rcx                        ; check if out of array (state_ptr == &state[5])
        je      out_of_first_theta_loop
        add     rsi, 8                          ; bc_ptr += 1
        add     rcx, 8                          ; state_ptr += 1
        jmp     first_theta_loop
out_of_first_theta_loop:

        mov     rsi, rbp                        ; rsi = &state[25]
        xor     r14, r14                        ; int x = 0;
second_theta_loop:
 	; uint64_t t = bc[(x + 4) % 5] ^ rol64(bc[(x + 1) % 5], 1);
        lea       rax, [r14+4]                ; rax = x + 4
        lea       r14, [r14+1]                ; increment counter as x + 1 is performed
        mov       rcx, r14                    ; rcx = x + 1
        mod5_sse  rcx, rax                    ; rcx = (x + 1) % 5
                                              ; rax = (x + 4) % 5

        mov     rcx, [rsp-56+rcx*8]         ; rcx = bc[(x + 1) % 5]
        rol     rcx, 1                      ; rcx = rol64(bc[(x + 1) % 5], 1)
        xor     rcx, [rsp-56+rax*8]         ; rcx is t = bc[(x + 4) % 5] ^ rol64(bc[(x + 1) % 5], 1)

	; for (int y = 0; y < 5; y++)
	; 	state[x + 5 * y] ^= t;
	; here 5 * y is: 0, 5, 10, 15
	; in bytes:      0, 40, 80, 120
        lea     rax, [rsi-200]                  ; rax = &state[x]
nested_theta_loop:
        mov     rdx, [rax]                      ; rdx = state[x + y], y is <0, 5)
        xor     rdx, rcx                        ; rdx = state[x + y] ^ t
        mov     [rax], rdx                      ; state[x + y] ^= t
        add     rax, 40                         ; y = &state[y] + 5
        cmp     rsi, rax                        ; if equal to &state[25], go out of the loop
        jne     nested_theta_loop
out_of_nested_second_theta_loop:
        add     rsi, 8                          ; from state[x] into state[x + 1], x is <0, 5)
        cmp     r14, 5                          ;  x is <0, 5)
        je      out_of_second_theta_loop
        jmp     second_theta_loop
out_of_second_theta_loop:
	; loop preparations
	; for (int i = 0; i < 24; i++);
        ; This loop is done in with integer accessing hence (step is 4):
        ; for (int i = 0; i < 96; i += 4);
        ; array have byte access
	; access to 32bit integer value is done in step 4:
	; arr + 0, arr + 4, arr + 8
        xor     rax, rax                        ; i = 0;

        mov     rsi, [r9+8]                     ; bc[0] = state[1]
        mov     cl, 1                           ; rcx = keccakf_rotc[0]
        mov     rdx, 10                         ; rdx = keccakf_piln[0]

rho_pi_loop:
        lea     rdx, [r9+rdx*8]                 ; rdx = &state[j];
        rol     rsi, cl                         ; rsi = rol64(bc[0], keccakf_rotc[x])
        mov     r14, [rdx]                      ; r14 = state[j]; SWAP HERE
        mov     [rdx], rsi                      ; state[j] = rol64(bc[0], keccakf_rotc[x])
        add     rax, 4                          ; i += 4 (access next integer in the array)
        cmp     rax, 96                         ; limit 96, as the step is 4

        lea     r15, [keccakf_piln]
        movsx   rdx, WORD PTR [r15 + rax]       ; int j variable, rdx = keccakf_piln[i]
        lea     r15, [keccakf_rotc]
        mov     cl, BYTE PTR [r15 + rax]        ; ecx = keccakf_rotc[i]
        mov     rsi, r14                        ; rsi = state[j]; SWAP HERE
        jne     rho_pi_loop

        ;	preparations for chi loop
        xor     r14, r14                        ; int x = 0
chi_loop:
	; for (int x = 0; x < 5; x++)
    	; 	bc[x] = state[y + x];
	;
	; means copying the state[y+x] - state[x+0, ..., x+4] into bc[0,4]
        movdqu  xmm0, XMMWORD PTR [r8]          ; state[y+0] and state[y+1] into xmm0
        movups  XMMWORD PTR [rsp-56], xmm0      ; bc[0], bc[1] = state[y+0], state[y+1]

        movdqu  xmm1, XMMWORD PTR [r8+16]       ; state[2] and state[3] into xmm1
        movups  XMMWORD PTR [rsp-40], xmm1      ; bc[2], bc[3] = state[y+2], state[y+3];

        mov     rax, [r8+32]                    ; state[y+4] into rax;
        mov     [rsp-24], rax                   ; state[y+4] into bc[4];

        mov     rsi, r8                         ; &state[y+x] into rsi
        xor     rdx, rdx                        ; rdx = 0
nested_chi_loop:
        lea     rdx, [rdx+1]                    ; increment counter as x + 1 is used
        mov     rcx, rdx                        ; rcx = x + 1
        lea     rax, [rdx+1]                    ; rax = x + 2
        mod5_sse rcx, rax                       ; rcx = (x + 1) % 5
                                                ; rax = (x + 2) % 5

        mov     rcx, [rsp-56+rcx*8]             ; rcx =  bc[(x + 1) % 5]
        not     rcx                             ; rcx = ~bc[(x + 1) % 5]

        and     rcx, [rsp-56+rax*8]             ; rcx = ~bc[(x + 1) % 5] & bc[(x + 2) % 5]
        xor     [rsi], rcx                      ; state[y + x] ^= bc[(x + 1) % 5] & bc[(x + 2) % 5]
        add     rsi, 8                          ; &state[x] into &state[x + 1];
        cmp     rdx, 5                          ; check if x < 5
        jne     nested_chi_loop
        add     r14, 5                          ; x += 5
        add     r8, 40                          ; &state[x] into &state[x + 5]
        cmp     r14, 25                         ; from 0 to 25 by step 5 with cond: x < 25
        jne     chi_loop

        ; iota state
        xor     rbx, [r9]                       ; rbx = state[0] ^ keccakf_rndc[x]
        mov     [r9], rbx                       ; state[0] ^= keccakf_rndc[x];
        mov     rdx, rbx                        ; rdx = state[0] ^ keccakf_rndc[x]

        ; === end of rounds ===
        cmp     r13, r11                        ; r13 = end of loop, r11 = current ptr
        je      out_of_rounds
        mov     rbx, [r11]                      ; load next round const from keccakf_rndc_ptr: keccakf_rnd[x + 1] into rbx
        add     r11, 8                          ; keccakf_rndc_ptr = &keccakf_rndc[x + 1];
        jmp     rounds
out_of_rounds:
        pop     rbx
        pop     rbp
        pop     r12
        pop     r13
        pop     r14
        pop     r15
        ret
keccakf endp
end
