#pragma once

#include <iomanip>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <ios>
#include <memory>
#include <array>
#include <ostream>
#include <cstring>
#include <sstream>
#include <stdexcept>
#include <vector>
#include <fstream>
#include <iostream>

#include <unistd.h>
#include <fcntl.h>

#define MEMORY_SIZE 1024

typedef enum {
    OP_NOP  = 0x00,
    OP_ADD  = 0x01,
    OP_LEA  = 0x02,
    OP_JMP  = 0x03,
    OP_JLE  = 0x04,
    OP_PUSH = 0x05,
    OP_POP  = 0x06,
    OP_SYSOPEN  = 0x07,
    OP_SYSREAD  = 0x08,
    OP_SYSWRITE = 0x09
} opcode_t;

template<typename T>
class VirtualMachineInterface {
    public:
        virtual void parse(std::string&) = 0;
        virtual void dump() = 0;
        virtual void push(T, bool) = 0;
        virtual T pop() = 0;
        virtual int open() = 0;
        virtual int read() = 0;
        virtual int write() = 0;
        virtual int execute() = 0;
        virtual void add() = 0;
        virtual void jmp() = 0;
        virtual ~VirtualMachineInterface() = default;

    protected:
        std::vector<T> memory;
        std::vector<T> stack;
};

class VirtualMachine8 : public VirtualMachineInterface<uint8_t> {
    public:
        virtual void parse(std::string& path) override {
            std::ifstream file(path);

            if (!file) {
                std::cerr << "Failed to open the file." << std::endl;
                throw std::runtime_error("File not found!");
            }

            int cnt = 0;
            while (cnt < MEMORY_SIZE) {
                uint8_t c = static_cast<uint8_t>(file.get());
                if (file.eof()) {
                    break;
                }
                memory.push_back(c);
                // std::cout << std::hex << (uint32_t)c << " ";
                cnt += 1;
            }

            file.close();
            return;
        }

        virtual void dump(void) override {
            std::cout << "dump\n";
            
            size_t cnt = 0;
            for (int c : memory) {
                std::cout << std::setfill('0') 
                          << std::setw(2)
                          << std::hex 
                          << c << " ";
                if (cnt == 0x10) {
                    cnt = 0;
                    std::cout << "\n";
                    continue;
                }
                cnt += 1;
            }
            std::cout << std::endl;
            return;
        }

        virtual void push(uint8_t byte, bool from_memory) override {
            if (stack.size() == MEMORY_SIZE) {
                throw std::runtime_error("Stack is FULL!");
            }
            
            uint8_t datum = 0;
            if (from_memory) {
                datum = memory.at(pc + 1);
            } else {
                datum = byte;
            }
            stack.push_back(datum);
            return;
        }

        virtual uint8_t pop() override {
            if (stack.empty()) {
                throw std::runtime_error("Stack is EMPTY!");
            }
            uint8_t c = stack.back();
            stack.pop_back();
            return c;
        }

        virtual void add() override {
            if (stack.size() < 2) {
                throw std::runtime_error("Not enough elements!");
            }
            uint8_t a = pop();
            uint8_t b = pop();

            // std::cout << (uint32_t)a << "+" << (uint32_t)b << " = " << (uint32_t)(a + b) << "\n";
            stack.push_back(a + b);
        }

        virtual int open() override {
            uint8_t c = 0;
            std::string f {""};
            do {
                c = pop();
                f.push_back(c);
            } while (c > 0);
            // std::cout << f << "\n";
            
            fd = ::open(f.data(), O_RDONLY, O_EXCL);
            if (fd < 0 || fd > 0xff) {
                throw std::runtime_error("Could not open the requested file!");
            }

            return 0;
        }
        
        virtual int read() override {
            uint8_t c = 0;
            if ( 0 == ::read(fd, &c, 1) ) {
                return 0;
            }
            push(c, false);
            return 0;
        }
        
        virtual int write() override {
            uint8_t datum = pop();
            // std::cout << (uint32_t)datum << " ";
            putc(datum, stdout);
            return 0;
        }

        virtual void jmp() override {
            uint8_t offset = pop();
            if (pc < offset) {
                pc = -1;
            } else {
                pc -= offset;
            }
            return;
        }

        virtual int execute() override {
            // std::cout << "execute\n";

            pc = 0;

            // TODO: signature check

            while(pc < memory.size()) {
                opcode_t opcode = static_cast<opcode_t>(memory.at(pc));
                switch (opcode) {
                    case OP_NOP: { // nop
                        // std::cout << "nop\n";
                    }
                    break;

                    case OP_ADD: { // add
                        // std::cout << "add\n";
                        add();
                    }
                    break;

                    case OP_LEA: { // lea
                        // std::cout << "lea\n";
                    }
                    break;

                    case OP_JMP: { // jmp
                        // std::cout << "jmp\n";
                        jmp();
                    }
                    break;

                    case OP_JLE: { // jle
                        // std::cout << "jle\n";
                    }
                    break;

                    case OP_PUSH: { // push
                        // std::cout << "push\n";
                        push(0, true);
                        pc += 1;
                    }
                    break;

                    case OP_POP: { // pop
                        // std::cout << "pop\n";
                        pop();
                    }
                    break;

                    case OP_SYSOPEN: { // open
                        // std::cout << "open\n";
                        open();
                    }
                    break;

                    case OP_SYSREAD: { // read
                        // std::cout << "read\n";
                        read();
                    }
                    break;

                    case OP_SYSWRITE: { // write
                        // std::cout << "write\n";
                        write();
                    }
                    break;

                    default: { // nop
                        // std::cout << "nop\n";
                    }
                    break;
                }
                pc += 1;
            }


            return 0;
        }

    ~VirtualMachine8() {
        if (fd > 0) {
            close(fd);
        }
    }

    private:
        uint32_t pc;
        int fd;
};