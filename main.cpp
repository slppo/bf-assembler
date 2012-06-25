#include <Windows.h>
#include <string>
#include <stack>
#include <memory>
#include <iostream>
#include <fstream>

const std::string STD_LIB = 
#ifndef NDEBUG
  "msvcr100d.dll";
#else
  "msvcr100.dll";
#endif

typedef void (*bf_fn)();

class BrainFucktor
{
public:
  BrainFucktor(bf_fn func) : _func(func) { }
  ~BrainFucktor() { delete reinterpret_cast<void*>(_func); _func = 0; }
  void operator()() { _func(); }
private:
  bf_fn _func;
};

BrainFucktor Compile(const std::string &code);
std::string BrainfuckIgnore(const std::string &code);
unsigned short HiWord(unsigned int dword);
unsigned short LoWord(unsigned int dword);
unsigned char HiByte(unsigned short word);
unsigned char LoByte(unsigned short word);

int main()
{    
  std::ifstream ifs("test.b");
  if(!ifs)
    return 1;
  std::string code;
  while(!ifs.eof())
  {
    std::string line;
    std::getline(ifs, line);
    code += line;
  }
  Compile(code)();  
  std::cin.get();
  return 0;  
}

BrainFucktor Compile(const std::string &code)
{
  static const std::size_t BUFFER_SIZE = 16384; // size of allocated function; not of function data (that's fixed to 3000 bytes)
  static const unsigned char PROLOG[] = "\x55\x89\xe5\x81\xec\x90\x0c\x00\x00\x8d\x85\x40\xf4\xff\xff\x89"
    "\x85\x34\xf4\xff\xff\xc6\x85\x44\xff\xff\xff\x00\x68\xb7\x0b\x00\x00\x6a\x00\x8d\x85\x41\xf4\xff\xff"
    "\x48\x50\xe8";
  static const unsigned char INC_DATA[] = "\x8b\x85\x34\xf4\xff\xff\x8a\x08\xfe\xc1\x8b\x95\x34\xf4\xff\xff\x88\x0a";
  static const unsigned char DEC_DATA[] = "\x8b\x85\x34\xf4\xff\xff\x8a\x08\xfe\xc9\x8b\x95\x34\xf4\xff\xff\x88\x0a";
  static const unsigned char INC_DP[] = "\x8b\x85\x34\xf4\xff\xff\x40\x89\x85\x34\xf4\xff\xff";
  static const unsigned char DEC_DP[] = "\x8b\x85\x34\xf4\xff\xff\x48\x89\x85\x34\xf4\xff\xff";
  static const unsigned char PUTCHAR_PROLOG[] = "\x8b\x85\x34\xf4\xff\xff\x0f\xbe\x08\x51\xe8";
  static const unsigned char PUTCHAR_EPILOG[] = "\x83\xc4\x04\x8b\x85\x34\xf4\xff\xff";
  static const unsigned char GETCHAR_PROLOG[] = "\xe8";
  static const unsigned char GETCHAR_EPILOG[] = "\x8b\x8d\x34\xf4\xff\xff\x88\x01\x8b\x85\x34\xf4\xff\xff";
  static const unsigned char LOOP_START[] = "\x8b\x8d\x34\xf4\xff\xff\x0f\xbe\x08\x85\xc9\x0f\x84\x00\x00\x00\x00";  
  static const unsigned char EPILOG[] = "\x89\xec\x5d\xc3";

  std::string cleanedCode = BrainfuckIgnore(code);

  FARPROC memsetProc = GetProcAddress(GetModuleHandle(STD_LIB.c_str()), "memset");
  UINT_PTR memsetIlt = reinterpret_cast<UINT_PTR>(memsetProc);
  FARPROC putcharProc = GetProcAddress(GetModuleHandle(STD_LIB.c_str()), "putchar");
  UINT_PTR putcharIlt = reinterpret_cast<UINT_PTR>(putcharProc); 
  FARPROC getcharProc = GetProcAddress(GetModuleHandle(STD_LIB.c_str()), "getchar");
  UINT_PTR getcharIlt = reinterpret_cast<UINT_PTR>(getcharProc);

  void *buffer = operator new(BUFFER_SIZE);
  unsigned char *walker = reinterpret_cast<unsigned char*>(buffer);
  std::size_t idx = 0;

#define add_opcode(opcode) walker[idx++] = opcode
#define add_opcode_block(block) memcpy(walker + idx, (block), sizeof((block)) - 1); \
  idx += sizeof(block) - 1
#define add_dword(dword) add_opcode(LoByte(LoWord((dword)))); add_opcode(HiByte(LoWord((dword)))); \
  add_opcode(LoByte(HiWord((dword)))); add_opcode(HiByte(HiWord((dword))))
  
  add_opcode_block(PROLOG);
  
  UINT_PTR memsetLoc = (memsetIlt - reinterpret_cast<UINT_PTR>(buffer)) - idx - 0x04;
  add_dword(memsetLoc);
  add_opcode(0x83); add_opcode(0xc4); add_opcode(0x0c);

  std::stack<std::pair<unsigned int*, std::size_t>> loops;

  std::string::const_iterator end = cleanedCode.end();
  for(std::string::const_iterator it = cleanedCode.begin(); it != end; ++it)
  {
    switch(*it)
    {
    case '+': add_opcode_block(INC_DATA); break;
    case '-': add_opcode_block(DEC_DATA); break;
    case '>': add_opcode_block(INC_DP); break;
    case '<': add_opcode_block(DEC_DP); break;
    case '.':
      {
      add_opcode_block(PUTCHAR_PROLOG);
      UINT_PTR putcharLoc = (putcharIlt - reinterpret_cast<UINT_PTR>(buffer)) - idx - 0x04;
      add_dword(putcharLoc);
      add_opcode_block(PUTCHAR_EPILOG);
      }
      break;
    case ',':
      {
      add_opcode_block(GETCHAR_PROLOG);
      UINT_PTR getcharLoc = (getcharIlt - reinterpret_cast<UINT_PTR>(buffer)) - idx - 0x04;      
      add_dword(getcharLoc);
      add_opcode_block(GETCHAR_EPILOG);
      }
      break;
    case '[':            
      {      
      std::pair<unsigned int*, std::size_t> pair(static_cast<unsigned int*>(0), idx);
      add_opcode_block(LOOP_START);
      pair.first = reinterpret_cast<unsigned int*>(&walker[idx-4]);
      loops.push(pair);
      }
      break;
    case ']':
      {
      std::pair<unsigned int*, std::size_t> pair = loops.top();
      loops.pop();
      unsigned int offset = 0xFFFFFFFF - (idx - pair.second) - 4;
      add_opcode(0xe9); add_dword(offset);
      *pair.first = static_cast<unsigned int>(idx - pair.second) - sizeof(LOOP_START) + 1;
      }
      break;
    default: _asm int 3; // literally impossible with BrainfuckIgnore
    }
  }

  add_opcode_block(EPILOG);
#undef add_opcode
#undef add_opcode_block
#undef add_dword

  DWORD old;
  VirtualProtect(buffer, BUFFER_SIZE, PAGE_EXECUTE_READWRITE, &old);
  return reinterpret_cast<bf_fn>(buffer);
}

std::string BrainfuckIgnore(const std::string &code)
{
  std::string result;
  std::string::const_iterator end = code.end();
  for(std::string::const_iterator it = code.begin(); it != end; ++it)
  {
    if(*it == '+' || *it == '-' || *it == '>' || *it == '<' || *it == '[' || *it == ']' || *it == ',' || *it == '.')
      result += *it;
  }
  return result;
}

unsigned short HiWord(unsigned int dword)
{
  return static_cast<unsigned short>(dword >> 16);
}

unsigned short LoWord(unsigned int dword)
{
  return static_cast<unsigned short>(dword);
}

unsigned char HiByte(unsigned short word)
{
  return static_cast<unsigned char>(word >> 8);
}

unsigned char LoByte(unsigned short word)
{
  return static_cast<unsigned char>(word);
}