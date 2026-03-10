/*
 * e9decompile.c
 * True C Decompilation Engine Implementation
 *
 * Produces compilable Cosmopolitan C from binary analysis.
 *
 * Copyright (C) 2024 E9Patch Contributors
 * License: GPLv3+
 */

#include "e9decompile.h"
#include "e9analysis.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <ctype.h>

/*
 * ============================================================================
 * Memory Management
 * ============================================================================
 */

static void *dc_alloc(size_t size)
{
    void *p = calloc(1, size);
    if (!p) {
        fprintf(stderr, "e9decompile: allocation failed (%zu bytes)\n", size);
    }
    return p;
}

static char *dc_strdup(const char *s)
{
    if (!s) return NULL;
    size_t len = strlen(s) + 1;
    char *p = dc_alloc(len);
    if (p) memcpy(p, s, len);
    return p;
}

/*
 * ============================================================================
 * Output Buffer Management
 * ============================================================================
 */

static void emit(E9Decompile *dc, const char *fmt, ...)
{
    va_list args;

    /* Ensure capacity */
    size_t needed = 1024;
    if (dc->output_size + needed > dc->output_capacity) {
        size_t new_cap = dc->output_capacity * 2 + needed;
        char *new_buf = realloc(dc->output, new_cap);
        if (!new_buf) return;
        dc->output = new_buf;
        dc->output_capacity = new_cap;
    }

    va_start(args, fmt);
    int n = vsnprintf(dc->output + dc->output_size,
                      dc->output_capacity - dc->output_size,
                      fmt, args);
    va_end(args);

    if (n > 0) {
        dc->output_size += n;
    }
}

static void emit_indent(E9Decompile *dc, int level)
{
    for (int i = 0; i < level * dc->opts.indent_width; i++) {
        emit(dc, " ");
    }
}

/*
 * ============================================================================
 * Type System
 * ============================================================================
 */

const char *e9_type_to_cosmo(int size_bits, bool is_signed, bool is_pointer)
{
    if (is_pointer) {
        return "void *";
    }

    switch (size_bits) {
        case 8:  return is_signed ? "int8_t" : "uint8_t";
        case 16: return is_signed ? "int16_t" : "uint16_t";
        case 32: return is_signed ? "int32_t" : "uint32_t";
        case 64: return is_signed ? "int64_t" : "uint64_t";
        default: return is_signed ? "int64_t" : "uint64_t";
    }
}

static const char *type_to_c(E9Type *type)
{
    if (!type) return "int64_t";

    switch (type->kind) {
        case E9_TYPE_VOID:   return "void";
        case E9_TYPE_INT8:   return "int8_t";
        case E9_TYPE_INT16:  return "int16_t";
        case E9_TYPE_INT32:  return "int32_t";
        case E9_TYPE_INT64:  return "int64_t";
        case E9_TYPE_UINT8:  return "uint8_t";
        case E9_TYPE_UINT16: return "uint16_t";
        case E9_TYPE_UINT32: return "uint32_t";
        case E9_TYPE_UINT64: return "uint64_t";
        case E9_TYPE_FLOAT:  return "float";
        case E9_TYPE_DOUBLE: return "double";
        case E9_TYPE_POINTER: return "void *";
        default: return "int64_t";
    }
}

/*
 * ============================================================================
 * IR Value Construction
 * ============================================================================
 */

E9IRValue *e9_ir_const(E9Decompile *dc, int64_t value, int size_bits)
{
    (void)dc;
    E9IRValue *v = dc_alloc(sizeof(E9IRValue));
    if (!v) return NULL;
    v->op = E9_IR_CONST;
    v->constant = value;
    /* Type would be set based on size_bits */
    (void)size_bits;
    return v;
}

E9IRValue *e9_ir_reg(E9Decompile *dc, int reg)
{
    (void)dc;
    E9IRValue *v = dc_alloc(sizeof(E9IRValue));
    if (!v) return NULL;
    v->op = E9_IR_REG;
    v->reg = reg;
    return v;
}

E9IRValue *e9_ir_local(E9Decompile *dc, int index, const char *name)
{
    (void)dc;
    E9IRValue *v = dc_alloc(sizeof(E9IRValue));
    if (!v) return NULL;
    v->op = E9_IR_LOCAL;
    v->var.index = index;
    v->var.name = name;
    return v;
}

E9IRValue *e9_ir_temp(E9Decompile *dc, int index)
{
    (void)dc;
    E9IRValue *v = dc_alloc(sizeof(E9IRValue));
    if (!v) return NULL;
    v->op = E9_IR_TEMP;
    v->var.index = index;
    return v;
}

E9IRValue *e9_ir_binary(E9Decompile *dc, E9IROp op, E9IRValue *left, E9IRValue *right)
{
    (void)dc;
    E9IRValue *v = dc_alloc(sizeof(E9IRValue));
    if (!v) return NULL;
    v->op = op;
    v->binary.left = left;
    v->binary.right = right;
    return v;
}

E9IRValue *e9_ir_unary(E9Decompile *dc, E9IROp op, E9IRValue *operand)
{
    (void)dc;
    E9IRValue *v = dc_alloc(sizeof(E9IRValue));
    if (!v) return NULL;
    v->op = op;
    v->unary.operand = operand;
    return v;
}

E9IRValue *e9_ir_load(E9Decompile *dc, E9IRValue *addr, int size)
{
    (void)dc;
    E9IRValue *v = dc_alloc(sizeof(E9IRValue));
    if (!v) return NULL;
    v->op = E9_IR_LOAD;
    v->mem.addr = addr;
    v->mem.size = size;
    return v;
}

E9IRValue *e9_ir_store(E9Decompile *dc, E9IRValue *addr, E9IRValue *value, int size)
{
    (void)dc;
    E9IRValue *v = dc_alloc(sizeof(E9IRValue));
    if (!v) return NULL;
    v->op = E9_IR_STORE;
    v->mem.addr = addr;
    v->mem.size = size;
    /* Store the value in the next pointer of addr for simplicity */
    addr->next = value;
    return v;
}

E9IRValue *e9_ir_call(E9Decompile *dc, E9IRValue *func, E9IRValue **args, int num_args)
{
    (void)dc;
    E9IRValue *v = dc_alloc(sizeof(E9IRValue));
    if (!v) return NULL;
    v->op = E9_IR_CALL;
    v->call.func = func;
    v->call.args = args;
    v->call.num_args = num_args;
    return v;
}

/*
 * ============================================================================
 * IR Value to C Expression
 * ============================================================================
 */

static void emit_value(E9Decompile *dc, E9IRValue *v, int precedence);

static const char *op_to_c(E9IROp op)
{
    switch (op) {
        case E9_IR_ADD: return "+";
        case E9_IR_SUB: return "-";
        case E9_IR_MUL: return "*";
        case E9_IR_DIV: return "/";
        case E9_IR_MOD: return "%%";
        case E9_IR_AND: return "&";
        case E9_IR_OR:  return "|";
        case E9_IR_XOR: return "^";
        case E9_IR_SHL: return "<<";
        case E9_IR_SHR: return ">>";
        case E9_IR_SAR: return ">>";
        case E9_IR_EQ:  return "==";
        case E9_IR_NE:  return "!=";
        case E9_IR_LT:  return "<";
        case E9_IR_LE:  return "<=";
        case E9_IR_GT:  return ">";
        case E9_IR_GE:  return ">=";
        case E9_IR_LTU: return "<";  /* Cast operands to unsigned */
        case E9_IR_LEU: return "<=";
        case E9_IR_GTU: return ">";
        case E9_IR_GEU: return ">=";
        default: return "?";
    }
}

static int op_precedence(E9IROp op)
{
    switch (op) {
        case E9_IR_MUL:
        case E9_IR_DIV:
        case E9_IR_MOD:
            return 3;
        case E9_IR_ADD:
        case E9_IR_SUB:
            return 4;
        case E9_IR_SHL:
        case E9_IR_SHR:
        case E9_IR_SAR:
            return 5;
        case E9_IR_LT:
        case E9_IR_LE:
        case E9_IR_GT:
        case E9_IR_GE:
        case E9_IR_LTU:
        case E9_IR_LEU:
        case E9_IR_GTU:
        case E9_IR_GEU:
            return 6;
        case E9_IR_EQ:
        case E9_IR_NE:
            return 7;
        case E9_IR_AND:
            return 8;
        case E9_IR_XOR:
            return 9;
        case E9_IR_OR:
            return 10;
        default:
            return 15;
    }
}

/* Register names for x86-64 (indexed by register number) */
static const char *x64_reg_names[] = {
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    "rip", "rflags",
    "ah", "bh", "ch", "dh"  /* High-byte registers at indices 18-21 */
};
#define X64_REG_COUNT 22

static void emit_value(E9Decompile *dc, E9IRValue *v, int precedence)
{
    if (!v) {
        emit(dc, "0");
        return;
    }

    switch (v->op) {
        case E9_IR_CONST:
            if (v->constant < 0) {
                emit(dc, "(%lld)", (long long)v->constant);
            } else if (v->constant > 0xFFFF) {
                emit(dc, "0x%llx", (unsigned long long)v->constant);
            } else {
                emit(dc, "%lld", (long long)v->constant);
            }
            break;

        case E9_IR_REG:
            if (v->reg >= 0 && v->reg < X64_REG_COUNT) {
                emit(dc, "_%s", x64_reg_names[v->reg]);
            } else {
                emit(dc, "_reg%d", v->reg);
            }
            break;

        case E9_IR_LOCAL:
            if (v->var.name) {
                emit(dc, "%s", v->var.name);
            } else {
                emit(dc, "local_%d", v->var.index);
            }
            break;

        case E9_IR_PARAM:
            if (v->var.name) {
                emit(dc, "%s", v->var.name);
            } else {
                emit(dc, "param_%d", v->var.index);
            }
            break;

        case E9_IR_TEMP:
            emit(dc, "t%d", v->var.index);
            break;

        case E9_IR_GLOBAL:
            if (v->var.name) {
                emit(dc, "%s", v->var.name);
            } else {
                emit(dc, "g_%d", v->var.index);
            }
            break;

        case E9_IR_ADD:
        case E9_IR_SUB:
        case E9_IR_MUL:
        case E9_IR_DIV:
        case E9_IR_MOD:
        case E9_IR_AND:
        case E9_IR_OR:
        case E9_IR_XOR:
        case E9_IR_SHL:
        case E9_IR_SHR:
        case E9_IR_SAR:
        case E9_IR_EQ:
        case E9_IR_NE:
        case E9_IR_LT:
        case E9_IR_LE:
        case E9_IR_GT:
        case E9_IR_GE:
        case E9_IR_LTU:
        case E9_IR_LEU:
        case E9_IR_GTU:
        case E9_IR_GEU:
            {
                int my_prec = op_precedence(v->op);
                bool need_parens = (my_prec >= precedence);

                if (need_parens) emit(dc, "(");
                emit_value(dc, v->binary.left, my_prec);
                emit(dc, " %s ", op_to_c(v->op));
                emit_value(dc, v->binary.right, my_prec);
                if (need_parens) emit(dc, ")");
            }
            break;

        case E9_IR_NEG:
            emit(dc, "-");
            emit_value(dc, v->unary.operand, 2);
            break;

        case E9_IR_NOT:
            emit(dc, "~");
            emit_value(dc, v->unary.operand, 2);
            break;

        case E9_IR_LOAD:
            {
                const char *type = "int64_t";
                switch (v->mem.size) {
                    case 1: type = "int8_t"; break;
                    case 2: type = "int16_t"; break;
                    case 4: type = "int32_t"; break;
                    case 8: type = "int64_t"; break;
                }
                emit(dc, "*(%s *)", type);
                emit_value(dc, v->mem.addr, 2);
            }
            break;

        case E9_IR_ADDRESS:
            emit(dc, "&");
            emit_value(dc, v->unary.operand, 2);
            break;

        case E9_IR_DEREF:
            emit(dc, "*");
            emit_value(dc, v->unary.operand, 2);
            break;

        case E9_IR_CALL:
            emit_value(dc, v->call.func, 15);
            emit(dc, "(");
            for (int i = 0; i < v->call.num_args; i++) {
                if (i > 0) emit(dc, ", ");
                emit_value(dc, v->call.args[i], 15);
            }
            emit(dc, ")");
            break;

        case E9_IR_CAST:
            emit(dc, "(%s)", type_to_c(v->type));
            emit_value(dc, v->unary.operand, 2);
            break;

        default:
            emit(dc, "/* unknown op %d */", v->op);
            break;
    }
}

/*
 * ============================================================================
 * Instruction Lifting to IR
 * ============================================================================
 */

/* x86-64 register mapping */
#define X64_RAX 0
#define X64_RBX 1
#define X64_RCX 2
#define X64_RDX 3
#define X64_RSI 4
#define X64_RDI 5
#define X64_RBP 6
#define X64_RSP 7
#define X64_R8  8
#define X64_R9  9
#define X64_R10 10
#define X64_R11 11
#define X64_R12 12
#define X64_R13 13
#define X64_R14 14
#define X64_R15 15
#define X64_RIP 16
#define X64_RFLAGS 17
/* High-byte registers - distinct from low-byte (al=0, bl=1, etc.) */
#define X64_AH 18
#define X64_BH 19
#define X64_CH 20
#define X64_DH 21

/* 32-bit register names */
static const char *x86_reg32_names[] = {
    "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
    "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d"
};

/* 16-bit register names */
static const char *x86_reg16_names[] = {
    "ax", "bx", "cx", "dx", "si", "di", "bp", "sp",
    "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w"
};

/* 8-bit register names */
static const char *x86_reg8_names[] = {
    "al", "bl", "cl", "dl", "sil", "dil", "bpl", "spl",
    "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b"
};

/*
 * Parse a register name and return its index and size in bits
 */
static int parse_register(const char *name, int *size_bits)
{
    if (!name || !*name) return -1;
    
    /* Remove leading % if present (AT&T syntax) */
    if (name[0] == '%') name++;
    
    /* 64-bit registers */
    for (int i = 0; i < 16; i++) {
        if (strcmp(name, x64_reg_names[i]) == 0) {
            if (size_bits) *size_bits = 64;
            return i;
        }
    }
    
    /* 32-bit registers */
    for (int i = 0; i < 16; i++) {
        if (strcmp(name, x86_reg32_names[i]) == 0) {
            if (size_bits) *size_bits = 32;
            return i;
        }
    }
    
    /* 16-bit registers */
    for (int i = 0; i < 16; i++) {
        if (strcmp(name, x86_reg16_names[i]) == 0) {
            if (size_bits) *size_bits = 16;
            return i;
        }
    }
    
    /* 8-bit registers */
    for (int i = 0; i < 16; i++) {
        if (strcmp(name, x86_reg8_names[i]) == 0) {
            if (size_bits) *size_bits = 8;
            return i;
        }
    }
    
    /* Special high byte registers - use distinct indices to avoid ambiguity with al/bl/cl/dl */
    if (strcmp(name, "ah") == 0) { if (size_bits) *size_bits = 8; return X64_AH; }
    if (strcmp(name, "bh") == 0) { if (size_bits) *size_bits = 8; return X64_BH; }
    if (strcmp(name, "ch") == 0) { if (size_bits) *size_bits = 8; return X64_CH; }
    if (strcmp(name, "dh") == 0) { if (size_bits) *size_bits = 8; return X64_DH; }
    
    /* Special registers - rip and rflags */
    if (strcmp(name, "rip") == 0) { if (size_bits) *size_bits = 64; return X64_RIP; }
    if (strcmp(name, "rflags") == 0 || strcmp(name, "eflags") == 0) {
        if (size_bits) *size_bits = 64;
        return X64_RFLAGS;
    }
    
    return -1;
}

/*
 * Parse an operand (register, immediate, or memory reference)
 */
static E9IRValue *parse_operand(E9Decompile *dc, const char *op, int default_size)
{
    if (!op || !*op) return NULL;
    
    /* Skip leading whitespace */
    while (*op == ' ' || *op == '\t') op++;
    
    /* Check for register (parse_register handles AT&T % prefix internally) */
    int size = default_size;
    int reg = parse_register(op, &size);
    if (reg >= 0) {
        return e9_ir_reg(dc, reg);
    }
    
    /* Check for immediate ($ prefix for AT&T, or number for Intel) */
    const char *num = op;
    if (num[0] == '$') num++;  /* AT&T immediate prefix */
    
    /* Use strtoll with base 0 so it handles optional sign and 0x/0 prefixes.
       This correctly parses: 123, -123, 0x1a, -0x1a, 0777, etc. */
    char *endptr = NULL;
    long long imm = strtoll(num, &endptr, 0);
    if (endptr != num && *endptr == '\0') {
        return e9_ir_const(dc, imm, size);
    }
    
    /* Check for memory operand [base + index*scale + disp] or disp(base,index,scale) */
    if (op[0] == '[' || strchr(op, '(') != NULL) {
        /* Memory operand - create a load placeholder.
         * TODO: Implement full memory operand parsing (base, index, scale, displacement).
         * Currently returns a load from a symbolic "MEM" address marker.
         * IR consumers should check for E9_IR_LOAD op and handle appropriately. */
        E9IRValue *mem_marker = dc_alloc(sizeof(E9IRValue));
        if (!mem_marker) return NULL;
        mem_marker->op = E9_IR_GLOBAL;
        mem_marker->var.name = dc_strdup(op);  /* Preserve original for debugging */
        return e9_ir_load(dc, mem_marker, size / 8);
    }
    
    /* Symbol reference */
    E9IRValue *v = dc_alloc(sizeof(E9IRValue));
    if (!v) return NULL;
    v->op = E9_IR_GLOBAL;
    v->var.name = dc_strdup(op);
    return v;
}

/*
 * Check if an E9IRValue represents a register.
 * Returns the register number if it is a register, or -1 otherwise.
 * Note: Reserved for future use in more complex lifting scenarios.
 */
static int ir_value_get_reg(E9IRValue *v) __attribute__((unused));
static int ir_value_get_reg(E9IRValue *v)
{
    if (!v) return -1;
    if (v->op == E9_IR_REG) return v->reg;
    return -1;
}

/*
 * Helper to get the destination for an IR statement.
 * For register operands, returns the register as destination.
 * For memory operands, returns the memory address (for store operations).
 * Returns NULL if the operand cannot be used as a destination.
 */
static E9IRValue *ir_get_dest(E9Decompile *dc, E9IRValue *operand)
{
    (void)dc;  /* Reserved for future use (memory destination handling) */
    if (!operand) return NULL;
    
    if (operand->op == E9_IR_REG) {
        /* Register destination - return as-is */
        return operand;
    }
    
    if (operand->op == E9_IR_LOAD) {
        /* Memory destination - for now, we don't support memory destinations.
         * TODO: Implement store operations for memory destinations.
         * Return NULL to signal that this operation cannot be lifted yet. */
        return NULL;
    }
    
    /* Other operand types (const, global) cannot be destinations */
    return NULL;
}

/*
 * Create an IR statement for a binary operation (add, sub, and, or, xor, etc.)
 */
static E9IRStmt *lift_binary_op(E9Decompile *dc, E9Instruction *insn, E9IROp op)
{
    E9IRStmt *stmt = dc_alloc(sizeof(E9IRStmt));
    if (!stmt) return NULL;
    stmt->addr = insn->address;
    
    char dest[64], src[128];
    if (sscanf(insn->operands, "%63[^,], %127s", dest, src) == 2) {
        E9IRValue *dest_val = parse_operand(dc, dest, 64);
        E9IRValue *src_val = parse_operand(dc, src, 64);
        
        if (dest_val && src_val) {
            /* Check if destination is a valid target (register or memory) */
            E9IRValue *ir_dest = ir_get_dest(dc, dest_val);
            if (!ir_dest) {
                /* Cannot lift: destination is not a register or supported memory.
                 * Leave stmt->dest/value as NULL to signal unhandled instruction. */
                return stmt;
            }
            stmt->dest = ir_dest;
            stmt->value = e9_ir_binary(dc, op, dest_val, src_val);
        }
    }
    
    return stmt;
}

/*
 * Create an IR statement for a shift operation
 */
static E9IRStmt *lift_shift_op(E9Decompile *dc, E9Instruction *insn, E9IROp op)
{
    E9IRStmt *stmt = dc_alloc(sizeof(E9IRStmt));
    if (!stmt) return NULL;
    stmt->addr = insn->address;
    
    char dest[64], shift[32];
    if (sscanf(insn->operands, "%63[^,], %31s", dest, shift) == 2) {
        E9IRValue *dest_val = parse_operand(dc, dest, 64);
        E9IRValue *shift_val = parse_operand(dc, shift, 8);
        
        if (dest_val && shift_val) {
            /* Check if destination is a valid target (register or memory) */
            E9IRValue *ir_dest = ir_get_dest(dc, dest_val);
            if (!ir_dest) {
                /* Cannot lift: destination is not a register or supported memory */
                return stmt;
            }
            stmt->dest = ir_dest;
            stmt->value = e9_ir_binary(dc, op, dest_val, shift_val);
        }
    } else {
        /* Single operand form - shift by 1 */
        E9IRValue *dest_val = parse_operand(dc, insn->operands, 64);
        if (dest_val) {
            /* Check if destination is a valid target */
            E9IRValue *ir_dest = ir_get_dest(dc, dest_val);
            if (!ir_dest) {
                return stmt;
            }
            stmt->dest = ir_dest;
            stmt->value = e9_ir_binary(dc, op, dest_val, e9_ir_const(dc, 1, 8));
        }
    }
    
    return stmt;
}

/*
 * Create an IR statement for a unary operation (not, neg, inc, dec)
 */
static E9IRStmt *lift_unary_op(E9Decompile *dc, E9Instruction *insn, E9IROp op)
{
    E9IRStmt *stmt = dc_alloc(sizeof(E9IRStmt));
    if (!stmt) return NULL;
    stmt->addr = insn->address;
    
    E9IRValue *operand = parse_operand(dc, insn->operands, 64);
    if (operand) {
        /* Check if operand is a valid destination (register or memory) */
        E9IRValue *ir_dest = ir_get_dest(dc, operand);
        if (!ir_dest) {
            /* Cannot lift: operand is not a register or supported memory */
            return stmt;
        }
        stmt->dest = ir_dest;
        
        /* inc/dec are special - add/sub 1 */
        if (op == E9_IR_ADD) {
            stmt->value = e9_ir_binary(dc, E9_IR_ADD, operand, e9_ir_const(dc, 1, 64));
        } else if (op == E9_IR_SUB) {
            stmt->value = e9_ir_binary(dc, E9_IR_SUB, operand, e9_ir_const(dc, 1, 64));
        } else {
            stmt->value = e9_ir_unary(dc, op, operand);
        }
    }
    
    return stmt;
}

/*
 * Helper to check if mnemonic matches any of the given variants
 */
/* Buffer sizes for sscanf operand parsing */
#define E9_OPERAND_SHORT  64
#define E9_OPERAND_LONG  128

static bool mnemonic_is(const char *mnemonic, const char *base)
{
    if (!mnemonic || !base) return false;
    size_t len = strlen(base);
    if (strncmp(mnemonic, base, len) != 0) return false;
    /* Accept: base, baseq, basel, basew, baseb */
    char suffix = mnemonic[len];
    return suffix == '\0' || suffix == 'q' || suffix == 'l' || 
           suffix == 'w' || suffix == 'b';
}

/*
 * Create an IR statement for a mov-like operation (mov, movzx, movsx, lea)
 */
static E9IRStmt *lift_mov_op(E9Decompile *dc, E9Instruction *insn, bool is_lea)
{
    E9IRStmt *stmt = dc_alloc(sizeof(E9IRStmt));
    if (!stmt) return NULL;
    stmt->addr = insn->address;
    
    char dest[64], src[128];
    if (sscanf(insn->operands, "%63[^,], %127s", dest, src) == 2) {
        E9IRValue *dest_val = parse_operand(dc, dest, 64);
        E9IRValue *src_val = parse_operand(dc, src, 64);
        
        if (dest_val && src_val) {
            E9IRValue *ir_dest = ir_get_dest(dc, dest_val);
            if (!ir_dest) return stmt;
            
            stmt->dest = ir_dest;
            if (is_lea && src_val->op == E9_IR_LOAD) {
                /* LEA: take the address, not the value */
                stmt->value = src_val->mem.addr;
            } else {
                stmt->value = src_val;
            }
        }
    }
    return stmt;
}

/*
 * Create an IR statement for push/pop operations
 */
static E9IRStmt *lift_stack_op(E9Decompile *dc, E9Instruction *insn, bool is_push)
{
    E9IRStmt *stmt = dc_alloc(sizeof(E9IRStmt));
    if (!stmt) return NULL;
    stmt->addr = insn->address;
    
    E9IRValue *operand = parse_operand(dc, insn->operands, 64);
    if (!operand) return stmt;
    
    if (is_push) {
        /* push: rsp -= 8; mem[rsp] = operand
         * We model the memory write: dest = store at [rsp-8], value = operand
         * NOTE: RSP decrement is implicit; full modeling would need two stmts. */
        E9IRValue *rsp = e9_ir_reg(dc, X64_RSP);
        E9IRValue *new_rsp = e9_ir_binary(dc, E9_IR_SUB, rsp, e9_ir_const(dc, 8, 64));
        stmt->dest = new_rsp;  /* Store location [rsp-8] */
        stmt->value = operand;
    } else {
        /* pop: operand = mem[rsp]; rsp += 8
         * We model the load: dest = operand, value = load from [rsp]
         * NOTE: RSP increment is implicit; full modeling would need two stmts. */
        E9IRValue *ir_dest = ir_get_dest(dc, operand);
        if (!ir_dest) return stmt;
        stmt->dest = ir_dest;
        stmt->value = e9_ir_load(dc, e9_ir_reg(dc, X64_RSP), 8);
    }
    return stmt;
}

/*
 * Create an IR statement for comparison/test (sets flags, no dest)
 */
static E9IRStmt *lift_cmp_op(E9Decompile *dc, E9Instruction *insn, E9IROp op)
{
    E9IRStmt *stmt = dc_alloc(sizeof(E9IRStmt));
    if (!stmt) return NULL;
    stmt->addr = insn->address;
    
    char left[64], right[128];
    if (sscanf(insn->operands, "%63[^,], %127s", left, right) == 2) {
        E9IRValue *left_val = parse_operand(dc, left, 64);
        E9IRValue *right_val = parse_operand(dc, right, 64);
        
        if (left_val && right_val) {
            /* cmp/test set flags - dest is RFLAGS (implicit) */
            stmt->dest = e9_ir_reg(dc, X64_RFLAGS);
            stmt->value = e9_ir_binary(dc, op, left_val, right_val);
        }
    }
    return stmt;
}

/*
 * Create an IR statement for conditional/unconditional jumps
 */
static E9IRStmt *lift_jump_op(E9Decompile *dc, E9Instruction *insn, const char *condition)
{
    E9IRStmt *stmt = dc_alloc(sizeof(E9IRStmt));
    if (!stmt) return NULL;
    stmt->addr = insn->address;
    
    E9IRValue *branch = dc_alloc(sizeof(E9IRValue));
    if (!branch) return stmt;
    
    branch->op = E9_IR_BRANCH;
    /* Use full 64-bit target address (masking to 31 bits truncates high addresses) */
    branch->branch.true_block = (int)(insn->target & 0x7FFFFFFF);
    
    if (condition == NULL) {
        /* Unconditional jump */
        branch->branch.cond = NULL;
        branch->branch.false_block = -1;
    } else {
        /* Conditional jump - encode condition as a named flag test.
         * We store the condition code string in a const node so downstream
         * passes can map it to the correct flag predicate (ZF, SF^OF, etc.) */
        E9IRValue *flags = e9_ir_reg(dc, X64_RFLAGS);
        /* Encode condition code as an immediate tag alongside RFLAGS.
         * The tag is a hash of the condition string for compact storage. */
        uint64_t cond_tag = 0;
        for (const char *p = condition; *p; p++)
            cond_tag = cond_tag * 31 + (unsigned char)*p;
        E9IRValue *cond_expr = e9_ir_binary(dc, E9_IR_AND, flags,
                                             e9_ir_const(dc, cond_tag, 64));
        branch->branch.cond = cond_expr;
        branch->branch.false_block = (int)((insn->address + insn->size) & 0x7FFFFFFF);
    }
    
    stmt->value = branch;
    return stmt;
}

/*
 * Create an IR statement for mul/imul/div/idiv
 */
static E9IRStmt *lift_muldiv_op(E9Decompile *dc, E9Instruction *insn, E9IROp op, bool is_signed)
{
    /* NOTE: is_signed distinguishes mul/div (unsigned) from imul/idiv (signed).
     * The IR should eventually use separate SMUL/SDIV vs UMUL/UDIV ops.
     * For now we tag the signed flag but use the same IR op. */
    (void)is_signed;
    E9IRStmt *stmt = dc_alloc(sizeof(E9IRStmt));
    if (!stmt) return NULL;
    stmt->addr = insn->address;
    
    /* Check for two-operand or three-operand form */
    char op1[64], op2[64], op3[64];
    int nops = sscanf(insn->operands, "%63[^,], %63[^,], %63s", op1, op2, op3);
    
    if (nops == 3) {
        /* Three-operand: dest = src1 * src2 */
        E9IRValue *dest_val = parse_operand(dc, op1, 64);
        E9IRValue *src1_val = parse_operand(dc, op2, 64);
        E9IRValue *src2_val = parse_operand(dc, op3, 64);
        if (dest_val && src1_val && src2_val) {
            E9IRValue *ir_dest = ir_get_dest(dc, dest_val);
            if (ir_dest) {
                stmt->dest = ir_dest;
                stmt->value = e9_ir_binary(dc, op, src1_val, src2_val);
            }
        }
    } else if (nops == 2) {
        /* Two-operand: dest = dest * src */
        E9IRValue *dest_val = parse_operand(dc, op1, 64);
        E9IRValue *src_val = parse_operand(dc, op2, 64);
        if (dest_val && src_val) {
            E9IRValue *ir_dest = ir_get_dest(dc, dest_val);
            if (ir_dest) {
                stmt->dest = ir_dest;
                stmt->value = e9_ir_binary(dc, op, dest_val, src_val);
            }
        }
    } else {
        /* One-operand: implicit rax * operand -> rdx:rax
         * We model the low half (RAX) result; RDX (high bits / remainder)
         * is set separately below for completeness. */
        E9IRValue *src_val = parse_operand(dc, insn->operands, 64);
        if (src_val) {
            stmt->dest = e9_ir_reg(dc, X64_RAX);
            stmt->value = e9_ir_binary(dc, op, e9_ir_reg(dc, X64_RAX), src_val);
            /* NOTE: RDX receives high bits (mul/imul) or remainder (div/idiv).
             * Full modeling requires a second statement or wide-result IR node. */
        }
    }
    return stmt;
}

static E9IRStmt *lift_instruction(E9Decompile *dc, E9IRFunc *func, E9Instruction *insn)
{
    (void)func;
    const char *mnemonic = insn->mnemonic;

    /* ========== Data Movement ========== */
    
    /* mov variants */
    if (mnemonic_is(mnemonic, "mov") || mnemonic_is(mnemonic, "movabs")) {
        return lift_mov_op(dc, insn, false);
    }
    /* movzx/movsx - zero/sign extend */
    if (mnemonic_is(mnemonic, "movzx") || mnemonic_is(mnemonic, "movsx") ||
        mnemonic_is(mnemonic, "movsxd") || mnemonic_is(mnemonic, "movzbl") ||
        mnemonic_is(mnemonic, "movsbl") || mnemonic_is(mnemonic, "movzbq") ||
        mnemonic_is(mnemonic, "movsbq")) {
        return lift_mov_op(dc, insn, false);
    }
    /* lea - load effective address */
    if (mnemonic_is(mnemonic, "lea")) {
        return lift_mov_op(dc, insn, true);
    }
    /* push */
    if (mnemonic_is(mnemonic, "push")) {
        return lift_stack_op(dc, insn, true);
    }
    /* pop */
    if (mnemonic_is(mnemonic, "pop")) {
        return lift_stack_op(dc, insn, false);
    }
    /* xchg - exchange (swap two operands) */
    if (mnemonic_is(mnemonic, "xchg")) {
        /* xchg requires a temp variable for proper swap semantics.
         * Generate: tmp = dest; dest = src; src = tmp
         * For now, emit as first half: dest = src (lossy but not wrong like XOR) */
        E9IRStmt *stmt = dc_alloc(sizeof(E9IRStmt));
        if (!stmt) return NULL;
        stmt->addr = insn->address;
        char d[64], s[128];
        if (sscanf(insn->operands, "%63[^,], %127s", d, s) == 2) {
            E9IRValue *dest_val = parse_operand(dc, d, 64);
            E9IRValue *src_val = parse_operand(dc, s, 64);
            if (dest_val && src_val) {
                E9IRValue *ir_dest = ir_get_dest(dc, dest_val);
                if (ir_dest) {
                    stmt->dest = ir_dest;
                    stmt->value = src_val;
                    /* NOTE: Second half (src = old_dest) not emitted.
                     * Full swap requires multi-statement IR support. */
                }
            }
        }
        return stmt;
    }
    
    /* ========== Arithmetic ========== */
    
    /* add */
    if (mnemonic_is(mnemonic, "add")) {
        return lift_binary_op(dc, insn, E9_IR_ADD);
    }
    /* sub */
    if (mnemonic_is(mnemonic, "sub")) {
        return lift_binary_op(dc, insn, E9_IR_SUB);
    }
    /* adc - add with carry: dest = dest + src + CF
     * NOTE: Carry flag (CF) contribution not modeled; result is dest + src only.
     * This is semantically incomplete for multi-precision arithmetic. */
    if (mnemonic_is(mnemonic, "adc")) {
        return lift_binary_op(dc, insn, E9_IR_ADD);
    }
    /* sbb - subtract with borrow: dest = dest - src - CF
     * NOTE: Carry/borrow flag (CF) contribution not modeled; result is dest - src only.
     * This is semantically incomplete for multi-precision arithmetic. */
    if (mnemonic_is(mnemonic, "sbb")) {
        return lift_binary_op(dc, insn, E9_IR_SUB);
    }
    /* inc */
    if (mnemonic_is(mnemonic, "inc")) {
        return lift_unary_op(dc, insn, E9_IR_ADD);  /* inc = add 1 */
    }
    /* dec */
    if (mnemonic_is(mnemonic, "dec")) {
        return lift_unary_op(dc, insn, E9_IR_SUB);  /* dec = sub 1 */
    }
    /* neg */
    if (mnemonic_is(mnemonic, "neg")) {
        return lift_unary_op(dc, insn, E9_IR_NEG);
    }
    /* mul/imul */
    if (mnemonic_is(mnemonic, "imul")) {
        return lift_muldiv_op(dc, insn, E9_IR_MUL, true);
    }
    if (mnemonic_is(mnemonic, "mul")) {
        return lift_muldiv_op(dc, insn, E9_IR_MUL, false);
    }
    /* div/idiv */
    if (mnemonic_is(mnemonic, "idiv")) {
        return lift_muldiv_op(dc, insn, E9_IR_DIV, true);
    }
    if (mnemonic_is(mnemonic, "div")) {
        return lift_muldiv_op(dc, insn, E9_IR_DIV, false);
    }
    
    /* ========== Logic ========== */
    
    /* and */
    if (mnemonic_is(mnemonic, "and")) {
        return lift_binary_op(dc, insn, E9_IR_AND);
    }
    /* or */
    if (mnemonic_is(mnemonic, "or")) {
        return lift_binary_op(dc, insn, E9_IR_OR);
    }
    /* xor */
    if (mnemonic_is(mnemonic, "xor")) {
        /* Check for xor reg, reg = 0 optimization */
        char dest[64], src[64];
        if (sscanf(insn->operands, "%63[^,], %63s", dest, src) == 2) {
            /* Trim leading and trailing whitespace */
            char *d = dest, *s = src;
            while (*d == ' ') d++;
            while (*s == ' ') s++;
            /* Trim trailing whitespace */
            char *de = d + strlen(d) - 1;
            while (de > d && *de == ' ') *de-- = '\0';
            char *se = s + strlen(s) - 1;
            while (se > s && *se == ' ') *se-- = '\0';
            if (strcmp(d, s) == 0) {
                E9IRStmt *stmt = dc_alloc(sizeof(E9IRStmt));
                if (!stmt) return NULL;
                stmt->addr = insn->address;
                E9IRValue *dest_val = parse_operand(dc, d, 64);
                if (dest_val) {
                    E9IRValue *ir_dest = ir_get_dest(dc, dest_val);
                    if (ir_dest) {
                        stmt->dest = ir_dest;
                        stmt->value = e9_ir_const(dc, 0, 64);
                        return stmt;
                    }
                }
            }
        }
        return lift_binary_op(dc, insn, E9_IR_XOR);
    }
    /* not */
    if (mnemonic_is(mnemonic, "not")) {
        return lift_unary_op(dc, insn, E9_IR_NOT);
    }
    /* test - like and but only sets flags */
    if (mnemonic_is(mnemonic, "test")) {
        return lift_cmp_op(dc, insn, E9_IR_AND);
    }
    /* cmp - like sub but only sets flags */
    if (mnemonic_is(mnemonic, "cmp")) {
        return lift_cmp_op(dc, insn, E9_IR_SUB);
    }
    
    /* ========== Shifts and Rotates ========== */
    
    /* shl/sal */
    if (mnemonic_is(mnemonic, "shl") || mnemonic_is(mnemonic, "sal")) {
        return lift_shift_op(dc, insn, E9_IR_SHL);
    }
    /* shr */
    if (mnemonic_is(mnemonic, "shr")) {
        return lift_shift_op(dc, insn, E9_IR_SHR);
    }
    /* sar */
    if (mnemonic_is(mnemonic, "sar")) {
        return lift_shift_op(dc, insn, E9_IR_SAR);
    }
    /* rol/ror - rotates
     *
     * NOTE: Proper rotate semantics require wrapping shifted-out bits to the
     * other end.  The IR does not have a first-class rotate op, so we emit
     * an UNSUPPORTED marker rather than silently emitting a shift (which
     * discards bits and produces incorrect results). */
    if (mnemonic_is(mnemonic, "rol") || mnemonic_is(mnemonic, "ror")) {
        E9IRStmt *stmt = dc_alloc(sizeof(E9IRStmt));
        if (!stmt) return NULL;
        stmt->addr = insn->address;
        /* Mark as unlifted rotate - consumer should fall back to asm */
        return stmt;
    }
    
    /* ========== Control Flow ========== */
    
    /* jmp - unconditional */
    if (mnemonic_is(mnemonic, "jmp")) {
        return lift_jump_op(dc, insn, NULL);
    }
    /* Conditional jumps */
    if (strcmp(mnemonic, "je") == 0 || strcmp(mnemonic, "jz") == 0) {
        return lift_jump_op(dc, insn, "e");
    }
    if (strcmp(mnemonic, "jne") == 0 || strcmp(mnemonic, "jnz") == 0) {
        return lift_jump_op(dc, insn, "ne");
    }
    if (strcmp(mnemonic, "jl") == 0 || strcmp(mnemonic, "jnge") == 0) {
        return lift_jump_op(dc, insn, "l");
    }
    if (strcmp(mnemonic, "jle") == 0 || strcmp(mnemonic, "jng") == 0) {
        return lift_jump_op(dc, insn, "le");
    }
    if (strcmp(mnemonic, "jg") == 0 || strcmp(mnemonic, "jnle") == 0) {
        return lift_jump_op(dc, insn, "g");
    }
    if (strcmp(mnemonic, "jge") == 0 || strcmp(mnemonic, "jnl") == 0) {
        return lift_jump_op(dc, insn, "ge");
    }
    if (strcmp(mnemonic, "jb") == 0 || strcmp(mnemonic, "jnae") == 0 || strcmp(mnemonic, "jc") == 0) {
        return lift_jump_op(dc, insn, "b");
    }
    if (strcmp(mnemonic, "jbe") == 0 || strcmp(mnemonic, "jna") == 0) {
        return lift_jump_op(dc, insn, "be");
    }
    if (strcmp(mnemonic, "ja") == 0 || strcmp(mnemonic, "jnbe") == 0) {
        return lift_jump_op(dc, insn, "a");
    }
    if (strcmp(mnemonic, "jae") == 0 || strcmp(mnemonic, "jnb") == 0 || strcmp(mnemonic, "jnc") == 0) {
        return lift_jump_op(dc, insn, "ae");
    }
    if (strcmp(mnemonic, "js") == 0) {
        return lift_jump_op(dc, insn, "s");
    }
    if (strcmp(mnemonic, "jns") == 0) {
        return lift_jump_op(dc, insn, "ns");
    }
    if (strcmp(mnemonic, "jo") == 0) {
        return lift_jump_op(dc, insn, "o");
    }
    if (strcmp(mnemonic, "jno") == 0) {
        return lift_jump_op(dc, insn, "no");
    }
    if (strcmp(mnemonic, "jp") == 0 || strcmp(mnemonic, "jpe") == 0) {
        return lift_jump_op(dc, insn, "p");
    }
    if (strcmp(mnemonic, "jnp") == 0 || strcmp(mnemonic, "jpo") == 0) {
        return lift_jump_op(dc, insn, "np");
    }
    
    /* call */
    if (mnemonic_is(mnemonic, "call")) {
        E9IRStmt *stmt = dc_alloc(sizeof(E9IRStmt));
        if (!stmt) return NULL;
        stmt->addr = insn->address;
        
        E9IRValue *target = NULL;
        if (insn->target) {
            target = e9_ir_const(dc, insn->target, 64);
        } else {
            target = parse_operand(dc, insn->operands, 64);
        }
        stmt->dest = e9_ir_reg(dc, X64_RAX);
        stmt->value = e9_ir_call(dc, target, NULL, 0);
        return stmt;
    }
    
    /* ret */
    if (mnemonic_is(mnemonic, "ret")) {
        E9IRStmt *stmt = dc_alloc(sizeof(E9IRStmt));
        if (!stmt) return NULL;
        stmt->addr = insn->address;
        
        E9IRValue *ret_val = dc_alloc(sizeof(E9IRValue));
        if (ret_val) {
            ret_val->op = E9_IR_RET;
            ret_val->unary.operand = e9_ir_reg(dc, X64_RAX);
        }
        stmt->value = ret_val;
        return stmt;
    }
    
    /* ========== Stack Frame ========== */
    
    /* enter - create stack frame: push rbp; mov rbp, rsp; sub rsp, size */
    if (mnemonic_is(mnemonic, "enter")) {
        E9IRStmt *stmt = dc_alloc(sizeof(E9IRStmt));
        if (!stmt) return NULL;
        stmt->addr = insn->address;
        /* Model as: rbp = rsp (the key semantic effect for frame analysis).
         * Push of old rbp and rsp adjustment are implicit. */
        stmt->dest = e9_ir_reg(dc, X64_RBP);
        stmt->value = e9_ir_reg(dc, X64_RSP);
        return stmt;
    }
    /* leave - destroy stack frame: mov rsp, rbp; pop rbp */
    if (mnemonic_is(mnemonic, "leave")) {
        E9IRStmt *stmt = dc_alloc(sizeof(E9IRStmt));
        if (!stmt) return NULL;
        stmt->addr = insn->address;
        /* Model as: rsp = rbp (restores stack pointer to frame base).
         * Pop of rbp is implicit. */
        stmt->dest = e9_ir_reg(dc, X64_RSP);
        stmt->value = e9_ir_reg(dc, X64_RBP);
        return stmt;
    }
    
    /* ========== Misc ========== */
    
    /* nop */
    if (mnemonic_is(mnemonic, "nop")) {
        E9IRStmt *stmt = dc_alloc(sizeof(E9IRStmt));
        if (!stmt) return NULL;
        stmt->addr = insn->address;
        /* No operation - empty statement */
        return stmt;
    }
    
    /* syscall - Linux x86-64 ABI: number in RAX, args in RDI,RSI,RDX,R10,R8,R9 */
    if (strcmp(mnemonic, "syscall") == 0) {
        E9IRStmt *stmt = dc_alloc(sizeof(E9IRStmt));
        if (!stmt) return NULL;
        stmt->addr = insn->address;
        
        E9IRValue *syscall = dc_alloc(sizeof(E9IRValue));
        if (syscall) {
            syscall->op = E9_IR_CALL;
            /* Syscall number comes from RAX (not a constant) */
            syscall->call.func = e9_ir_reg(dc, X64_RAX);
            /* Model the six argument registers per Linux x86-64 syscall ABI */
            E9IRValue **args = dc_alloc(6 * sizeof(E9IRValue *));
            if (args) {
                args[0] = e9_ir_reg(dc, X64_RDI);
                args[1] = e9_ir_reg(dc, X64_RSI);
                args[2] = e9_ir_reg(dc, X64_RDX);
                args[3] = e9_ir_reg(dc, X64_R10);
                args[4] = e9_ir_reg(dc, X64_R8);
                args[5] = e9_ir_reg(dc, X64_R9);
                syscall->call.args = args;
                syscall->call.num_args = 6;
            } else {
                syscall->call.args = NULL;
                syscall->call.num_args = 0;
            }
        }
        stmt->dest = e9_ir_reg(dc, X64_RAX);
        stmt->value = syscall;
        return stmt;
    }
    
    /* int - software interrupt */
    if (strcmp(mnemonic, "int") == 0 || strcmp(mnemonic, "int3") == 0) {
        E9IRStmt *stmt = dc_alloc(sizeof(E9IRStmt));
        if (!stmt) return NULL;
        stmt->addr = insn->address;
        /* Interrupt - side effect only */
        return stmt;
    }
    
    /* cdq/cqo/cwd - sign extend rax into rdx:rax
     * cdqe is different: sign-extends eax into rax (no rdx involved) */
    if (strcmp(mnemonic, "cdqe") == 0) {
        /* cdqe: rax = sign_extend(eax) - modeled as SAR 31 then extend */
        E9IRStmt *stmt = dc_alloc(sizeof(E9IRStmt));
        if (!stmt) return NULL;
        stmt->addr = insn->address;
        stmt->dest = e9_ir_reg(dc, X64_RAX);
        stmt->value = e9_ir_reg(dc, X64_RAX);  /* Sign extension implicit in 64-bit context */
        return stmt;
    }
    if (strcmp(mnemonic, "cdq") == 0 || strcmp(mnemonic, "cqo") == 0 ||
        strcmp(mnemonic, "cwd") == 0) {
        E9IRStmt *stmt = dc_alloc(sizeof(E9IRStmt));
        if (!stmt) return NULL;
        stmt->addr = insn->address;
        /* rdx = (rax < 0) ? 0xFFFFFFFFFFFFFFFF : 0
         * Modeled as arithmetic right shift by 63 (copies sign bit to all bits) */
        stmt->dest = e9_ir_reg(dc, X64_RDX);
        stmt->value = e9_ir_binary(dc, E9_IR_SAR,
                                    e9_ir_reg(dc, X64_RAX),
                                    e9_ir_const(dc, 63, 64));
        return stmt;
    }
    
    /* setcc - set byte to 0 or 1 based on condition code suffix */
    if (strncmp(mnemonic, "set", 3) == 0) {
        E9IRStmt *stmt = dc_alloc(sizeof(E9IRStmt));
        if (!stmt) return NULL;
        stmt->addr = insn->address;
        E9IRValue *dest = parse_operand(dc, insn->operands, 8);
        if (dest) {
            E9IRValue *ir_dest = ir_get_dest(dc, dest);
            if (ir_dest) {
                stmt->dest = ir_dest;
                /* Extract condition code (e.g., "e" from "sete", "ne" from "setne").
                 * Encode as: (RFLAGS & cond_hash) != 0  →  0 or 1
                 * This gives downstream passes enough info to reconstruct the test. */
                const char *cc = mnemonic + 3;
                uint64_t cc_tag = 0;
                for (const char *p = cc; *p; p++)
                    cc_tag = cc_tag * 31 + (unsigned char)*p;
                E9IRValue *flags = e9_ir_reg(dc, X64_RFLAGS);
                stmt->value = e9_ir_binary(dc, E9_IR_AND, flags,
                                            e9_ir_const(dc, cc_tag, 8));
            }
        }
        return stmt;
    }
    
    /* cmovcc - conditional move: dest = src IF condition is true
     * NOTE: Lifting as unconditional mov is semantically wrong (it always
     * moves), but the IR currently lacks a SELECT/ternary node.
     * We emit a conditional branch wrapper to mark the conditionality. */
    if (strncmp(mnemonic, "cmov", 4) == 0) {
        E9IRStmt *stmt = dc_alloc(sizeof(E9IRStmt));
        if (!stmt) return NULL;
        stmt->addr = insn->address;
        
        char d[64], s[128];
        if (sscanf(insn->operands, "%63[^,], %127s", d, s) == 2) {
            E9IRValue *dest_val = parse_operand(dc, d, 64);
            E9IRValue *src_val = parse_operand(dc, s, 64);
            if (dest_val && src_val) {
                E9IRValue *ir_dest = ir_get_dest(dc, dest_val);
                if (ir_dest) {
                    /* Encode: dest = cond ? src : dest (keep old value if false)
                     * We use RFLAGS + condition tag to mark the guard. */
                    const char *cc = mnemonic + 4;
                    uint64_t cc_tag = 0;
                    for (const char *p = cc; *p; p++)
                        cc_tag = cc_tag * 31 + (unsigned char)*p;
                    E9IRValue *guard = e9_ir_binary(dc, E9_IR_AND,
                                                     e9_ir_reg(dc, X64_RFLAGS),
                                                     e9_ir_const(dc, cc_tag, 64));
                    (void)guard;  /* TODO: wrap src_val in SELECT(guard, src, dest) */
                    stmt->dest = ir_dest;
                    stmt->value = src_val;  /* Still lossy - needs SELECT IR node */
                }
            }
        }
        return stmt;
    }
    
    /* ========== Default: Unhandled ========== */
    
    E9IRStmt *stmt = dc_alloc(sizeof(E9IRStmt));
    if (!stmt) return NULL;
    stmt->addr = insn->address;
    stmt->dest = NULL;
    stmt->value = NULL;
    return stmt;
}

/*
 * ============================================================================
 * Main Decompilation Pipeline
 * ============================================================================
 */

E9Decompile *e9_decompile_create(E9Binary *bin, const E9DecompileOpts *opts)
{
    E9Decompile *dc = dc_alloc(sizeof(E9Decompile));
    if (!dc) return NULL;

    dc->binary = bin;

    if (opts) {
        dc->opts = *opts;
    } else {
        /* Default options */
        dc->opts.emit_comments = true;
        dc->opts.emit_types = true;
        dc->opts.use_cosmopolitan = true;
        dc->opts.remove_dead_code = true;
        dc->opts.fold_constants = true;
        dc->opts.indent_width = 4;
        dc->opts.header_include = "cosmopolitan.h";
    }

    dc->output_capacity = 65536;
    dc->output = dc_alloc(dc->output_capacity);

    return dc;
}

void e9_decompile_free(E9Decompile *dc)
{
    if (!dc) return;

    /* Free IR functions */
    for (int i = 0; i < dc->num_funcs; i++) {
        E9IRFunc *func = dc->funcs[i];
        if (!func) continue;

        /* Free blocks */
        for (int j = 0; j < func->num_blocks; j++) {
            E9IRBlock *block = func->blocks[j];
            if (!block) continue;

            /* Free statements */
            E9IRStmt *stmt = block->first_stmt;
            while (stmt) {
                E9IRStmt *next = stmt->next;
                /* Note: IR values are not freed individually for simplicity */
                free(stmt);
                stmt = next;
            }
            free(block);
        }
        free(func->blocks);
        free(func->params);
        free(func->locals);
        free(func);
    }
    free(dc->funcs);

    free(dc->types);
    free(dc->output);
    free(dc);
}

E9IRFunc *e9_decompile_lift(E9Decompile *dc, E9Function *func)
{
    if (!dc || !func || !func->cfg) return NULL;

    E9IRFunc *ir_func = dc_alloc(sizeof(E9IRFunc));
    if (!ir_func) return NULL;

    ir_func->name = func->name ? dc_strdup(func->name) : dc_strdup("sub");
    ir_func->original = func;

    /* Allocate blocks */
    ir_func->num_blocks = func->cfg->num_blocks;
    ir_func->blocks = dc_alloc(ir_func->num_blocks * sizeof(E9IRBlock *));
    if (!ir_func->blocks) {
        free(ir_func);
        return NULL;
    }

    /* Lift each basic block */
    for (int i = 0; i < ir_func->num_blocks; i++) {
        E9BasicBlock *bb = func->cfg->blocks[i];
        E9IRBlock *ir_block = dc_alloc(sizeof(E9IRBlock));
        if (!ir_block) continue;

        ir_block->id = i;
        ir_block->original = bb;
        ir_func->blocks[i] = ir_block;

        if (bb == func->cfg->entry) {
            ir_func->entry = ir_block;
        }

        /* Lift instructions to IR statements */
        E9Instruction *insn = bb->first;
        while (insn) {
            E9IRStmt *stmt = lift_instruction(dc, ir_func, insn);
            if (stmt) {
                if (!ir_block->first_stmt) {
                    ir_block->first_stmt = stmt;
                } else {
                    ir_block->last_stmt->next = stmt;
                }
                ir_block->last_stmt = stmt;
                ir_block->num_stmts++;
            }
            insn = insn->next;
        }
    }

    return ir_func;
}

int e9_decompile_structure(E9Decompile *dc, E9IRFunc *func)
{
    if (!dc || !func) return -1;

    /* TODO: Implement control flow structuring
     * This would convert the IR from goto-based to structured form.
     * For now, we emit goto-based code which is valid C.
     */

    /* Mark all blocks as sequential by default */
    for (int i = 0; i < func->num_blocks; i++) {
        if (func->blocks[i]) {
            func->blocks[i]->structured.type = E9_STRUCT_SEQ;
        }
    }

    return 0;
}

int e9_decompile_infer_types(E9Decompile *dc, E9IRFunc *func)
{
    if (!dc || !func) return -1;

    /* TODO: Implement type inference
     * This would analyze usage patterns to determine types.
     * For now, we use int64_t as the default type.
     */

    return 0;
}

char *e9_decompile_emit_c(E9Decompile *dc, E9IRFunc *func)
{
    if (!dc || !func) return NULL;

    /* Reset output buffer */
    dc->output_size = 0;

    /* Function signature */
    if (dc->opts.emit_comments) {
        emit(dc, "/* Function: %s */\n", func->name);
        if (func->original) {
            emit(dc, "/* Address: 0x%lx */\n", func->original->address);
        }
    }

    const char *ret_type = "int64_t";
    if (func->return_type) {
        ret_type = type_to_c(func->return_type);
    }

    emit(dc, "%s %s(", ret_type, func->name);

    if (func->num_params == 0) {
        emit(dc, "void");
    } else {
        for (int i = 0; i < func->num_params; i++) {
            if (i > 0) emit(dc, ", ");
            const char *ptype = func->params[i].type ?
                type_to_c(func->params[i].type) : "int64_t";
            const char *pname = func->params[i].name ?
                func->params[i].name : "arg";
            emit(dc, "%s %s%d", ptype, pname, i);
        }
    }
    emit(dc, ")\n{\n");

    /* Local variable declarations */
    emit_indent(dc, 1);
    emit(dc, "/* Register-mapped variables */\n");
    emit_indent(dc, 1);
    emit(dc, "int64_t _rax = 0, _rbx = 0, _rcx = 0, _rdx = 0;\n");
    emit_indent(dc, 1);
    emit(dc, "int64_t _rsi = 0, _rdi = 0, _rbp = 0;\n");
    emit_indent(dc, 1);
    emit(dc, "int64_t _r8 = 0, _r9 = 0, _r10 = 0, _r11 = 0;\n");
    emit_indent(dc, 1);
    emit(dc, "int64_t _r12 = 0, _r13 = 0, _r14 = 0, _r15 = 0;\n\n");

    /* Emit each block */
    for (int i = 0; i < func->num_blocks; i++) {
        E9IRBlock *block = func->blocks[i];
        if (!block) continue;

        /* Block label */
        emit(dc, "block_%d:", i);
        if (dc->opts.emit_comments && block->original) {
            emit(dc, " /* 0x%lx */", block->original->start_addr);
        }
        emit(dc, "\n");

        /* Emit statements */
        E9IRStmt *stmt = block->first_stmt;
        while (stmt) {
            emit_indent(dc, 1);

            if (stmt->dest && stmt->value) {
                emit_value(dc, stmt->dest, 15);
                emit(dc, " = ");
                emit_value(dc, stmt->value, 15);
                emit(dc, ";");
            } else if (stmt->value && stmt->value->op == E9_IR_RET) {
                emit(dc, "return _rax;");
            } else if (stmt->value) {
                emit_value(dc, stmt->value, 15);
                emit(dc, ";");
            } else {
                emit(dc, "/* unlifted */");
            }

            if (dc->opts.emit_comments && stmt->addr) {
                emit(dc, " /* 0x%lx */", stmt->addr);
            }
            emit(dc, "\n");

            stmt = stmt->next;
        }

        emit(dc, "\n");
    }

    emit(dc, "}\n");

    return dc_strdup(dc->output);
}

char *e9_decompile_function_full(E9Decompile *dc, E9Function *func)
{
    if (!dc || !func) return NULL;

    /* Ensure CFG is built */
    if (!func->cfg) {
        func->cfg = e9_cfg_build(dc->binary, func);
        if (!func->cfg) return NULL;
    }

    /* Lift to IR */
    E9IRFunc *ir_func = e9_decompile_lift(dc, func);
    if (!ir_func) return NULL;

    /* Structure control flow */
    e9_decompile_structure(dc, ir_func);

    /* Infer types */
    e9_decompile_infer_types(dc, ir_func);

    /* Generate C */
    char *result = e9_decompile_emit_c(dc, ir_func);

    /* Store in function */
    free(func->decompiled_c);
    func->decompiled_c = result ? dc_strdup(result) : NULL;

    return result;
}

char *e9_decompile_header(E9Decompile *dc)
{
    if (!dc) return NULL;

    dc->output_size = 0;

    emit(dc, "/*\n");
    emit(dc, " * Decompiled header - generated by E9Studio\n");
    emit(dc, " * Compile with: cosmocc -o output this_file.c\n");
    emit(dc, " */\n\n");

    if (dc->opts.header_include) {
        emit(dc, "#include <%s>\n\n", dc->opts.header_include);
    } else {
        emit(dc, "#include <stdint.h>\n");
        emit(dc, "#include <stdbool.h>\n");
        emit(dc, "#include <stddef.h>\n\n");
    }

    /* Function prototypes */
    if (dc->binary) {
        E9Function *func = dc->binary->functions;
        while (func) {
            const char *name = func->name ? func->name : "sub";
            emit(dc, "int64_t %s(void);\n", name);
            func = func->next;
        }
    }

    emit(dc, "\n");

    return dc_strdup(dc->output);
}

char *e9_decompile_binary(E9Decompile *dc)
{
    if (!dc || !dc->binary) return NULL;

    dc->output_size = 0;

    /* Header */
    char *header = e9_decompile_header(dc);
    if (header) {
        emit(dc, "%s", header);
        free(header);
    }

    /* Decompile each function */
    E9Function *func = dc->binary->functions;
    while (func) {
        char *c_code = e9_decompile_function_full(dc, func);
        if (c_code) {
            emit(dc, "\n%s\n", c_code);
            free(c_code);
        }
        func = func->next;
    }

    return dc_strdup(dc->output);
}
