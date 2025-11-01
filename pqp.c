#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdbool.h>
#include <ctype.h>

// Definições da arquitetura PicoQuickProcessor
#define MEMORY_SIZE 256
#define NUM_REGISTERS 16
#define INSTRUCTION_SIZE 4

// JIT Configuration
#define JIT_MEMORY_SIZE 4096
#define JIT_BLOCK_SIZE 16
#define JIT_NUM_BLOCKS (JIT_MEMORY_SIZE / JIT_BLOCK_SIZE)
#define JIT_THRESHOLD 2

// Estrutura para cache de blocos JIT
typedef struct {
    uint32_t pc;
    void* jit_code;
    uint32_t execution_count;
    bool is_compiled;
    uint8_t original_instruction[4];
    bool is_loop_header;
    uint32_t loop_end_pc;
} JITBlock;

// Estrutura do processador simplificada
typedef struct {
    uint32_t registers[NUM_REGISTERS];
    uint8_t memory[MEMORY_SIZE];
    uint32_t pc;
    uint32_t eflags;
    uint64_t cycle_count;
    uint32_t instruction_count[16];
    
    // JIT components
    uint8_t* jit_memory;
    JITBlock jit_blocks[JIT_NUM_BLOCKS];
    uint32_t jit_block_count;
} PicoProcessor;

typedef void (*jit_function_t)(uint32_t* registers, uint32_t* instruction_count, uint32_t* eflags, uint32_t pc); 

enum {
    MOV_IMM = 0x00,   // mov rx, i16
    MOV_REG = 0x01,   // mov rx, ry
    MOV_LOAD = 0x02,  // mov rx, [ry]
    MOV_STORE = 0x03, // mov [rx], ry
    CMP = 0x04,       // cmp rx, ry
    JMP = 0x05,       // jmp i16
    JG = 0x06,        // jg i16
    JL = 0x07,        // jl i16
    JE = 0x08,        // je i16
    ADD = 0x09,       // add rx, ry
    SUB = 0x0A,       // sub rx, ry
    AND = 0x0B,       // and rx, ry
    OR = 0x0C,        // or rx, ry
    XOR = 0x0D,       // xor rx, ry
    SAL = 0x0E,       // sal rx, i5
    SAR = 0x0F        // sar rx, i5
};

// Variáveis globais para controlar jumps condicionais
uint32_t last_jump_target = 0;
uint32_t last_conditional_jump_type = 0; // 1=JE, 2=JG, 3=JL

// Funções de decodificação
uint8_t get_opcode(uint32_t instruction) {
    return instruction & 0xFF;
}

uint8_t get_rx(uint32_t instruction) {
    return (instruction >> 12) & 0xF;
}

uint8_t get_ry(uint32_t instruction) {
    return (instruction >> 8) & 0xF;
}

int16_t get_i16(uint32_t instruction) {
    return (int16_t)((instruction >> 16) & 0xFFFF);
}

uint8_t get_i5(uint32_t instruction) {
    return (instruction >> 24) & 0x1F;
}

uint32_t load_instruction(uint8_t* memory, uint32_t pc) {
    if (pc + 3 >= MEMORY_SIZE) {
        return 0;
    }
    return memory[pc] | (memory[pc+1] << 8) | (memory[pc+2] << 16) | (memory[pc+3] << 24);
}

uint32_t load_word(uint8_t* memory, uint32_t addr) {
    if (addr + 3 >= MEMORY_SIZE) {
        return 0;
    }
    return memory[addr] | (memory[addr+1] << 8) | (memory[addr+2] << 16) | (memory[addr+3] << 24);
}

void store_word(uint8_t* memory, uint32_t addr, uint32_t value) {
    if (addr + 3 >= MEMORY_SIZE) {
        return;
    }
    memory[addr] = value & 0xFF;
    memory[addr+1] = (value >> 8) & 0xFF;
    memory[addr+2] = (value >> 16) & 0xFF;
    memory[addr+3] = (value >> 24) & 0xFF;
}

// Inicialização JIT
int init_jit(PicoProcessor* cpu) {
    cpu->jit_memory = mmap(NULL, JIT_MEMORY_SIZE, 
                          PROT_READ | PROT_WRITE | PROT_EXEC,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    
    if (cpu->jit_memory == MAP_FAILED) {
        return -1;
    }
    
    memset(cpu->jit_blocks, 0, sizeof(cpu->jit_blocks));
    cpu->jit_block_count = 0;
    
    // Preencher cada bloco com RET + NOPs
    for (int i = 0; i < JIT_NUM_BLOCKS; i++) {
        uint8_t* block = cpu->jit_memory + (i * JIT_BLOCK_SIZE);
        
        uint8_t bytecode[] = {
            0xC3,                                    // RET
            0x90, 0x90, 0x90, 0x90, 0x90,           // 5 NOPs
            0x90, 0x90, 0x90, 0x90, 0x90,           // 5 NOPs  
            0x90, 0x90, 0x90, 0x90, 0x90            // 5 NOPs
        };
        
        memcpy(block, bytecode, sizeof(bytecode));
    }
    
    return 0;
}

void execute_case(PicoProcessor* cpu, uint8_t* bytecode, int tamanho, uint32_t pc){
    memcpy(cpu->jit_memory + pc*4, bytecode, tamanho);
    jit_function_t exec_case = (jit_function_t)(cpu->jit_memory + pc*4);
    exec_case(cpu->registers, cpu->instruction_count, &cpu->eflags, cpu->pc);
    return;
}

void cleanup_jit(PicoProcessor* cpu) {
    if (cpu->jit_memory != NULL && cpu->jit_memory != MAP_FAILED) {
        munmap(cpu->jit_memory, JIT_MEMORY_SIZE);
    }
}

// Função para verificar se o jump condicional deve ser tomado
bool should_take_conditional_jump(uint32_t eflags, uint32_t jump_type) {
    uint8_t zero_flag = (eflags & (1 << 6)) ? 1 : 0;      // ZF bit 6
    uint8_t sign_flag = (eflags & (1 << 7)) ? 1 : 0;      // SF bit 7  
    uint8_t overflow_flag = (eflags & (1 << 11)) ? 1 : 0; // OF bit 11
    
    switch (jump_type) {
        case 1: // JE
            return zero_flag == 1;
        case 2: // JG  
            return (zero_flag == 0 && sign_flag == overflow_flag);
        case 3: // JL
            return (sign_flag != overflow_flag);
        default:
            return false;
    }
}

// Função de compilação JIT completa para todas as instruções
void compile_jit_block(PicoProcessor* cpu, uint32_t pc, FILE* output_file) {
    uint32_t block_index = (pc / 4) % JIT_NUM_BLOCKS;
    
    JITBlock* block = &cpu->jit_blocks[block_index];
    if (block->is_compiled && block->pc == pc) return;
    
    block->pc = pc;
    block->is_compiled = true;
    
    uint32_t instruction = load_instruction(cpu->memory, pc);
    uint8_t opcode = get_opcode(instruction);
    uint8_t rx = get_rx(instruction);
    uint8_t ry = get_ry(instruction);
    int16_t i16 = get_i16(instruction);
    uint8_t i5 = get_i5(instruction);
    
    switch (opcode) {
        case MOV_IMM: {
            int32_t dado = (int32_t)(int16_t)i16;
            uint8_t* ponteiro_pra_i16 = (uint8_t*)&dado;
            
            uint8_t bytecode[] = { 
                0xc7, 0x47, (rx*4), 
                ponteiro_pra_i16[0], ponteiro_pra_i16[1], 
                ponteiro_pra_i16[2], ponteiro_pra_i16[3],
                0xFF, 0x86, (opcode*4), 0x00, 0x00, 0x00,
                0x90, 0x90, 0x90
            };
            
            execute_case(cpu, bytecode, sizeof(bytecode), pc);
        
            fprintf(output_file, "0x%04X->MOV_R%d=0x%08X\n", pc, rx, (uint32_t)dado);
            fflush(output_file);
            break;
        }
        
        case MOV_REG: {
            uint8_t bytecode[] = {
                0x8b, 0x47, (ry*4),
                0x89, 0x47, (rx*4),
                0xFF, 0x86, (opcode*4), 0x00, 0x00, 0x00,
                0x90, 0x90, 0x90, 0x90
            };
            execute_case(cpu, bytecode, sizeof(bytecode), pc);
            
            uint32_t copied_value = cpu->registers[rx];
            fprintf(output_file, "0x%04X->MOV_R%d=R%d=0x%08X\n", pc, rx, ry, copied_value);
            fflush(output_file);
            break;
        }
        
        case MOV_LOAD: {
            uint8_t bytecode[16] = {
                0x8b, 0x47, (ry*4),              // mov eax, [rdi + ry*4] - 3 bytes
                0x83, 0xe0, 0xff,                // and eax, 0xff - 3 bytes
                0x8b, 0x44, 0x07, 0x40,          // mov eax, [rdi + rax + 0x40] - 4 bytes
                0x89, 0x47, (rx*4),              // mov [rdi + rx*4], eax - 3 bytes  
                0xFF, 0x46, (0x02*4),            // inc byte [rsi + 8] - 3 bytes
            };
                        
            execute_case(cpu, bytecode, sizeof(bytecode), pc);
            
            uint32_t address = cpu->registers[ry] & 0xFF;
            uint8_t mem0 = (address < MEMORY_SIZE) ? cpu->memory[address] : 0;
            uint8_t mem1 = (address + 1 < MEMORY_SIZE) ? cpu->memory[address + 1] : 0;
            uint8_t mem2 = (address + 2 < MEMORY_SIZE) ? cpu->memory[address + 2] : 0;
            uint8_t mem3 = (address + 3 < MEMORY_SIZE) ? cpu->memory[address + 3] : 0;
            
            fprintf(output_file, "0x%04X->MOV_R%d=MEM[0x%02X,0x%02X,0x%02X,0x%02X]=[0x%02X,0x%02X,0x%02X,0x%02X]\n", 
                    pc, rx, address, address+1, address+2, address+3, mem0, mem1, mem2, mem3);
            break;
        }
        
        case MOV_STORE: {
            uint8_t bytecode[16] = {
                0x8b, 0x47, (rx*4),              // mov eax, [rdi + rx*4] - 3 bytes
                0x8b, 0x4f, (ry*4),              // mov ecx, [rdi + ry*4] - 3 bytes
                0x83, 0xe0, 0xff,                // and eax, 0xff - 3 bytes
                0x89, 0x4c, 0x07, 0x40,          // mov [rdi + rax + 0x40], ecx - 4 bytes
                0xFF, 0x46, (0x03*4),            // inc byte [rsi + 12] - 3 bytes
            };
            
            execute_case(cpu, bytecode, sizeof(bytecode), pc);
            
            uint32_t address = cpu->registers[rx] & 0xFF;
            uint32_t stored_value = cpu->registers[ry];
            
            uint8_t byte0 = stored_value & 0xFF;
            uint8_t byte1 = (stored_value >> 8) & 0xFF;
            uint8_t byte2 = (stored_value >> 16) & 0xFF;
            uint8_t byte3 = (stored_value >> 24) & 0xFF;
            
            fprintf(output_file, "0x%04X->MOV_MEM[0x%02X,0x%02X,0x%02X,0x%02X]=R%d=[0x%02X,0x%02X,0x%02X,0x%02X]\n", 
                    pc, address, address+1, address+2, address+3, ry, byte0, byte1, byte2, byte3);
            break;
        }
                
        case CMP: {
            uint8_t bytecode[16] = {
                0x8B, 0x47, (rx*4),             // mov eax, [rdi + rx*4]
                0x3B, 0x47, (ry*4),             // cmp eax, [rdi + ry*4]
                0x9C,                           // pushfq
                0x58,                           // pop rax
                0x89, 0x02,                     // mov [rdx], eax
                0xFF, 0x86, (opcode*4), 0x00, 0x00, 0x00,  // inc dword [rsi + opcode*4]
            };
            
            execute_case(cpu, bytecode, sizeof(bytecode), pc);
            
            uint32_t eflags = cpu->eflags;
            uint8_t zero_flag = (eflags & (1 << 6)) ? 1 : 0;      // ZF bit 6
            uint8_t sign_flag = (eflags & (1 << 7)) ? 1 : 0;      // SF bit 7  
            uint8_t overflow_flag = (eflags & (1 << 11)) ? 1 : 0; // OF bit 11

            uint8_t equal = zero_flag;
            uint8_t greater = (!zero_flag && (sign_flag == overflow_flag)) ? 1 : 0;
            uint8_t less = (sign_flag != overflow_flag && !zero_flag) ? 1 : 0;
                    
            fprintf(output_file, "0x%04X->CMP_R%d<=>R%d(G=%d,L=%d,E=%d)\n", 
                    pc, rx, ry, greater, less, equal);
            break;
        }
        
        case JMP: {
            uint32_t current_pc = pc;
            int16_t relative_offset = i16;
            uint32_t target_pc = current_pc + (int32_t)relative_offset + 4;             
            
            int32_t jmp_offset = target_pc * 4 - (current_pc * 4 + 8);
            uint8_t* ptr_offset = (uint8_t*)&jmp_offset;

            if (target_pc >= MEMORY_SIZE) {
                jmp_offset = 4080 - (current_pc * 4 + 8);
            }
            
            uint8_t bytecode[16] = {
                0xFF, 0x46, (opcode*4),
                0xE9, ptr_offset[0], ptr_offset[1], ptr_offset[2], ptr_offset[3],
                0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90
            };
            
            execute_case(cpu, bytecode, sizeof(bytecode), pc);
            cpu->pc = target_pc;
            
            fprintf(output_file, "0x%04X->JMP_0x%04X\n", current_pc, target_pc);
            return;
        }

        case JE: {
            uint32_t current_pc = pc;
            int16_t relative_offset = i16;
            uint32_t target_pc = current_pc + (int32_t)relative_offset + 4;
            
            // Salvar informações do jump condicional
            last_jump_target = target_pc;
            last_conditional_jump_type = 1; // JE
            
            int32_t deslocamento_jmp = target_pc * 4 - (current_pc * 4 + 16);
            if (target_pc >= MEMORY_SIZE) {
                deslocamento_jmp = 4080 - (current_pc * 4 + 16);
            }
            uint8_t bytecode[] = {
                0xFF, 0x46, (opcode * 4),              // inc dword ptr [rsi + opcode*4]
                0x8B, 0x02,                            // mov eax, [rcx]
                0xA9, 0x40, 0x00, 0x00, 0x00,         // test eax, 0x40
                0x0F, 0x85,                            // jnz rel32
                (deslocamento_jmp & 0xFF),
                ((deslocamento_jmp >> 8) & 0xFF),
                ((deslocamento_jmp >> 16) & 0xFF),
                ((deslocamento_jmp >> 24) & 0xFF)
            };
            
            execute_case(cpu, bytecode, sizeof(bytecode), pc);

            fprintf(output_file, "0x%04X->JE_0x%04X\n", current_pc, target_pc & 0xFFFF); 
            return;
        }

        case JG: {
            uint32_t current_pc = pc;
            int16_t relative_offset = i16;
            uint32_t target_pc = current_pc + (int32_t)relative_offset + 4;
            
            // Salvar informações do jump condicional
            last_jump_target = target_pc;
            last_conditional_jump_type = 2; // JG
            
            int32_t deslocamento_jmp = target_pc * 4 - (current_pc * 4 + 16);
            if (target_pc >= MEMORY_SIZE) {
                deslocamento_jmp = 4080 - (current_pc * 4 + 16);
            }
            
            uint8_t bytecode[] = {
                0xFF, 0x46, (opcode * 4),          // inc dword ptr [rsi + opcode*4]
                0x8B, 0x02,                        // mov eax, [rcx]
                0xA9, 0xC0, 0x00, 0x00, 0x00,     // test eax, 0xC0
                0x0F, 0x84,                        // jz rel32
                (deslocamento_jmp & 0xFF),
                ((deslocamento_jmp >> 8) & 0xFF),
                ((deslocamento_jmp >> 16) & 0xFF),
                ((deslocamento_jmp >> 24) & 0xFF)
            };
            
            execute_case(cpu, bytecode, sizeof(bytecode), pc);
            
            fprintf(output_file, "0x%04X->JG_0x%04X\n", current_pc, target_pc); 
            return;
        }

        case JL: {
            uint32_t current_pc = pc;
            int16_t relative_offset = i16;
            uint32_t target_pc = current_pc + (int32_t)relative_offset + 4;
            
            // Salvar informações do jump condicional
            last_jump_target = target_pc;
            last_conditional_jump_type = 3; // JL
            
            int32_t deslocamento_jmp = target_pc * 4 - (current_pc * 4 + 16);
            if (target_pc >= MEMORY_SIZE) {
                deslocamento_jmp = 4080 - (current_pc * 4 + 16);
            }
            
            uint8_t bytecode[] = {
                0xFF, 0x46, (opcode * 4),              // inc dword ptr [rsi + opcode*4]
                0x8B, 0x02,                            // mov eax, [rcx]
                0xA9, 0x80, 0x00, 0x00, 0x00,         // test eax, 0x80
                0x0F, 0x85,                            // jnz rel32
                (deslocamento_jmp & 0xFF),
                ((deslocamento_jmp >> 8) & 0xFF),
                ((deslocamento_jmp >> 16) & 0xFF),
                ((deslocamento_jmp >> 24) & 0xFF)
            };
            
            execute_case(cpu, bytecode, sizeof(bytecode), pc);
            
            fprintf(output_file, "0x%04X->JL_0x%04X\n", current_pc, (int16_t) target_pc); 
            return;
        }            
        case ADD: {
            uint32_t old_value = cpu->registers[rx];
            uint32_t operand_value = cpu->registers[ry];
            
            uint8_t bytecode[16] = {
                0x8B, 0x47, (ry*4),
                0x01, 0x47, (rx*4),
                0xFF, 0x86, (opcode*4), 0x00, 0x00, 0x00,
                0x90,
                0x90, 0x90, 0x90
            };
            
            execute_case(cpu, bytecode, sizeof(bytecode), pc);
            
            uint32_t result = cpu->registers[rx];
            fprintf(output_file, "0x%04X->ADD_R%d+=R%d=0x%08X+0x%08X=0x%08X\n", 
                    pc, rx, ry, old_value, operand_value, result);
            break;
        }
        
        case SUB: {
            uint32_t old_value = cpu->registers[rx];
            uint32_t operand_value = cpu->registers[ry];
            
            uint8_t bytecode[16] = {
                0x8B, 0x47, (ry*4),
                0x29, 0x47, (rx*4),
                0xFF, 0x86, (opcode*4), 0x00, 0x00, 0x00,
                0x90,
                0x90, 0x90, 0x90
            };
            
            execute_case(cpu, bytecode, sizeof(bytecode), pc);
            
            uint32_t result = cpu->registers[rx];
            fprintf(output_file, "0x%04X->SUB_R%d-=R%d=0x%08X-0x%08X=0x%08X\n", 
                    pc, rx, ry, old_value, operand_value, result);
            break;
        }
        
        case AND: {
            uint32_t old_value = cpu->registers[rx];
            uint32_t operand_value = cpu->registers[ry];
            
            uint8_t bytecode[16] = {
                0x8B, 0x47, (ry*4),
                0x21, 0x47, (rx*4),
                0xFF, 0x86, (opcode*4), 0x00, 0x00, 0x00,
                0x90,
                0x90, 0x90, 0x90
            };
            
            execute_case(cpu, bytecode, sizeof(bytecode), pc);
            
            uint32_t result = cpu->registers[rx];
            fprintf(output_file, "0x%04X->AND_R%d&=R%d=0x%08X&0x%08X=0x%08X\n", 
                    pc, rx, ry, old_value, operand_value, result);
            break;
        }
        
        case OR: {
            uint32_t old_value = cpu->registers[rx];
            uint32_t operand_value = cpu->registers[ry];
            
            uint8_t bytecode[16] = {
                0x8B, 0x47, (ry*4),
                0x09, 0x47, (rx*4),
                0xFF, 0x86, (opcode*4), 0x00, 0x00, 0x00,
                0x90,
                0x90, 0x90, 0x90
            };
            
            execute_case(cpu, bytecode, sizeof(bytecode), pc);
            
            uint32_t result = cpu->registers[rx];
            fprintf(output_file, "0x%04X->OR_R%d|=R%d=0x%08X|0x%08X=0x%08X\n", 
                    pc, rx, ry, old_value, operand_value, result);
            break;
        }
        
        case XOR: {
            uint32_t old_value = cpu->registers[rx];
            uint32_t operand_value = cpu->registers[ry];
            
            uint8_t bytecode[16] = {
                0x8B, 0x47, (ry*4),
                0x31, 0x47, (rx*4),
                0xFF, 0x86, (opcode*4), 0x00, 0x00, 0x00,
                0x90,
                0x90, 0x90, 0x90
            };
            
            execute_case(cpu, bytecode, sizeof(bytecode), pc);
            
            uint32_t result = cpu->registers[rx];
            fprintf(output_file, "0x%04X->XOR_R%d^=R%d=0x%08X^0x%08X=0x%08X\n", 
                    pc, rx, ry, old_value, operand_value, result);
            break;
        }
        
        case SAL: {
            uint32_t old_value = cpu->registers[rx];
            
            uint8_t bytecode[16] = {
                0xC1, 0x67, (rx*4), i5,
                0xFF, 0x46, (opcode * 4),       // inc dword ptr [rsi + opcode]
                        0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00 // 9 NOPS
            };
            
            execute_case(cpu, bytecode, sizeof(bytecode), pc);
            cpu->pc = pc + 4;

            uint32_t result = cpu->registers[rx];
            fprintf(output_file, "0x%04X->SAL_R%d<<=%d=0x%08X<<%d=0x%08X\n", 
                    pc, rx, i5, old_value, i5, result);
            break;
        }
        
        case SAR: {
            uint32_t old_value = cpu->registers[rx];
            
            uint8_t bytecode[16] = {
                0xC1, 0x7F, (rx*4), i5,
                0xFF, 0x86, (opcode*4), 0x00, 0x00, 0x00,
                0x90,
                0x90, 0x90, 0x90, 0x90, 0x90
            };
            
            execute_case(cpu, bytecode, sizeof(bytecode), pc);
            cpu->pc = pc + 4;
            
            uint32_t result = cpu->registers[rx];
            fprintf(output_file, "0x%04X->SAR_R%d>>=%d=0x%08X>>%d=0x%08X\n", 
                    pc, rx, i5, old_value, i5, result);
            break;
        }
    } 
}

bool try_execute_jit_block(PicoProcessor* cpu, uint32_t pc, FILE* output_file) {
    uint32_t block_index = (pc / 4) % JIT_NUM_BLOCKS;
    JITBlock* block = &cpu->jit_blocks[block_index];
    
    block->execution_count++;
    
    uint32_t instruction = load_instruction(cpu->memory, pc);
    uint8_t opcode = get_opcode(instruction);
    
    compile_jit_block(cpu, pc, output_file);
    
    cpu->pc = pc + 4;
    return true;
}

bool hex_to_byte(const char* hex_str, uint8_t* result) {
    if (strlen(hex_str) != 4 || hex_str[0] != '0' || hex_str[1] != 'x') {
        return false;
    }
    int value = 0;
    for (int i = 2; i < 4; i++) {
        char c = hex_str[i];
        if (c >= '0' && c <= '9') {
            value = (value << 4) + (c - '0');
        } else if (c >= 'A' && c <= 'F') {
            value = (value << 4) + (c - 'A' + 10);
        } else if (c >= 'a' && c <= 'f') {
            value = (value << 4) + (c - 'a' + 10);
        } else {
            return false;
        }
    }
    *result = (uint8_t)value;
    return true;
}

bool is_hex_format(const char* filename) {
    FILE* file = fopen(filename, "r");
    if (!file) return false;
    
    char line[256];
    bool is_hex = false;
    
    if (fgets(line, sizeof(line), file)) {
        if (strstr(line, "0x") != NULL) {
            is_hex = true;
        }
    }
    
    fclose(file);
    return is_hex;
}

int load_program_from_hex_file(PicoProcessor* cpu, const char* filename) {
    FILE* file = fopen(filename, "r");
    if (!file) {
        return -1;
    }
    
    memset(cpu, 0, sizeof(PicoProcessor));
    
    char line[256];
    int memory_index = 0;
    int bytes_loaded = 0;
    
    while (fgets(line, sizeof(line), file) && memory_index < MEMORY_SIZE) {
        line[strcspn(line, "\r\n")] = 0;
        if (strlen(line) == 0) continue;
        
        char* token = strtok(line, " \t");
        while (token != NULL && memory_index < MEMORY_SIZE) {
            uint8_t byte_value;
            if (hex_to_byte(token, &byte_value)) {
                cpu->memory[memory_index++] = byte_value;
                bytes_loaded++;
            }
            token = strtok(NULL, " \t");
        }
    }
    
    fclose(file);
    
    if (bytes_loaded == 0) {
        return -1;
    }
    
    // Inicializar registradores
    for (int i = 0; i < NUM_REGISTERS; i++) {
        cpu->registers[i] = 0;
    }
    cpu->pc = 0;
    cpu->eflags = 0;
    
    return 0;
}

int load_program_from_binary_file(PicoProcessor* cpu, const char* filename) {
    FILE* file = fopen(filename, "rb");
    if (!file) {
        return -1;
    }
    
    memset(cpu, 0, sizeof(PicoProcessor));
    
    size_t bytes_read = fread(cpu->memory, 1, MEMORY_SIZE, file);
    fclose(file);
    
    if (bytes_read == 0) {
        return -1;
    }
    
    // Inicializar registradores
    for (int i = 0; i < NUM_REGISTERS; i++) {
        cpu->registers[i] = 0;
    }
    cpu->pc = 0;
    cpu->eflags = 0;
    
    return 0;
}

int load_program_from_file(PicoProcessor* cpu, const char* filename) {
    if (is_hex_format(filename)) {
        return load_program_from_hex_file(cpu, filename);
    } else {
        return load_program_from_binary_file(cpu, filename);
    }
}

int interpret_with_jit(PicoProcessor* cpu, FILE* output_file) {
    cpu->cycle_count = 0;
    memset(cpu->instruction_count, 0, sizeof(cpu->instruction_count));
    
    if (init_jit(cpu) != 0) {
        cpu->jit_memory = NULL;
    }
    
    while (cpu->pc < MEMORY_SIZE - 3) {
        uint32_t old_pc = cpu->pc;
        
        // Carregar instrução
        uint32_t instruction = load_instruction(cpu->memory, old_pc);
        uint8_t opcode = get_opcode(instruction);
        
        // Executar com JIT
        if (cpu->jit_memory && try_execute_jit_block(cpu, old_pc, output_file)) {
            fflush(stdout);
            
            // Verificar se foi um jump condicional que saiu da memória
            if (cpu->pc >= MEMORY_SIZE && last_conditional_jump_type > 0) {
                // Verificar se o jump condicional deveria ser tomado
                if (should_take_conditional_jump(cpu->eflags, last_conditional_jump_type)) {
                    // Jump deveria ser tomado, usar o target armazenado
                    cpu->pc = last_jump_target & 0xFFFF; // Mascarar para 16 bits
                    // Se o target também está fora da memória, terminar
                    if (cpu->pc >= MEMORY_SIZE) {
                        fprintf(output_file, "0x%04X->EXIT\n", cpu->pc);
                        break;
                    }
                } else {
                    // Jump não deveria ser tomado, continuar sequencialmente
                    cpu->pc = old_pc + 4;
                    fprintf(output_file, "0x%04X->CONDITIONAL_JUMP_NOT_TAKEN\n", old_pc);
                    
                    // Se a continuação sequencial também está fora da memória, terminar
                    if (cpu->pc >= MEMORY_SIZE) {
                        fprintf(output_file, "0x%04X->EXIT\n", cpu->pc);
                        break;
                    }
                }
                
                // Resetar o tipo de jump condicional
                last_conditional_jump_type = 0;
            } else if (cpu->pc >= MEMORY_SIZE) {
                // Jump incondicional ou outra instrução que saiu da memória
                fprintf(output_file, "0x%04X->EXIT\n", cpu->pc);
                break;
            }
        } else {
            printf("JIT FAILED at PC=0x%04X\n", old_pc);
            fflush(stdout);
            break;
        }
    }
    
    cleanup_jit(cpu);
    return 0;
}

void print_instruction_counters(PicoProcessor* cpu, FILE* output_file) {
    fprintf(output_file, "[");
    bool first = true;
    for (int i = 0; i < 16; i++) {
        if (!first) fprintf(output_file, ",");
        fprintf(output_file, "%02X:%d", i, cpu->instruction_count[i]);
        first = false;
    }
    fprintf(output_file, "]\n");
}

void print_final_registers(PicoProcessor* cpu, FILE* output_file) {
    fprintf(output_file, "[");
    for (int i = 0; i < NUM_REGISTERS; i++) {
        if (i > 0) fprintf(output_file, ",");
        fprintf(output_file, "R%d=0x%08X", i, cpu->registers[i]);
    }
    fprintf(output_file, "]\n");
}

int main(int argc, char* argv[]) {
    PicoProcessor cpu;
    
    const char* input_filename = "input.txt";
    const char* output_filename = "output.txt";
    
    if (argc >= 2) {
        input_filename = argv[1];
    }
    if (argc >= 3) {
        output_filename = argv[2];
    }
    
    if (load_program_from_file(&cpu, input_filename) != 0) {
        return 1;
    }
    
    FILE* output_file = fopen(output_filename, "w");
    if (!output_file) {
        return 1;
    }
    
    interpret_with_jit(&cpu, output_file);
    
    print_instruction_counters(&cpu, output_file);
    print_final_registers(&cpu, output_file);
    
    fclose(output_file);
    
    return 0;
}
