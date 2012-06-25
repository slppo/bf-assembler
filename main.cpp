#include <Windows.h>
#include <string>
#include <stack>

const std::string STD_LIB = 
#ifndef NDEBUG
  "msvcr100d.dll";
#else
  "msvcr100.dll";
#endif

typedef void (*bf_fn)();

bf_fn Compile(const std::string &code);
std::string BrainfuckIgnore(const std::string &code);

int main()
{    
  bf_fn func = Compile("++++++++++[>+++++++>++++++++++>+++>+<<<<-]>++.>+.+++++++..+++.>++.<<+++++++++++++++.>.+++.------.--------.>+.>.,");
  func();  
  delete reinterpret_cast<void*>(func);  
  return 0;
}

bf_fn Compile(const std::string &code)
{
  static const std::size_t BUFFER_SIZE = 2048;

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
  // PROLOG
  add_opcode(0x55); // push ebp
  add_opcode(0x89); add_opcode(0xE5); // mov ebp, esp  
  add_opcode(0x81); add_opcode(0xEC); add_opcode(0x90); add_opcode(0x0C); add_opcode(0x00); add_opcode(0x00); // sub esp, 0xc90  
  add_opcode(0x8D); add_opcode(0x85); add_opcode(0x40); add_opcode(0xF4); add_opcode(0xFF); add_opcode(0xFF); // lea eax, [ebp-0xbc0]
  add_opcode(0x89); add_opcode(0x85); add_opcode(0x34); add_opcode(0xF4); add_opcode(0xFF); add_opcode(0xFF); // mov dword ptr [ebp-0xbcc], eax

  add_opcode(0xc6); add_opcode(0x85); add_opcode(0x44); add_opcode(0xff); add_opcode(0xff); add_opcode(0xff); add_opcode(0x00); // mov byte ptr [ebp-0xbc], 0
  add_opcode(0x68); add_opcode(0xb7); add_opcode(0x0b); add_opcode(0x00); add_opcode(0x00); // push 0xbb7
  add_opcode(0x6a); add_opcode(0x00); // push 0
  add_opcode(0x8D); add_opcode(0x85); add_opcode(0x41); add_opcode(0xF4); add_opcode(0xFF); add_opcode(0xFF); // lea eax, [ebp-0xbbf]
  add_opcode(0x48); // dec eax
  add_opcode(0x50); // push eax
  add_opcode(0xe8); 
  
  UINT_PTR memsetLoc = (memsetIlt - reinterpret_cast<UINT_PTR>(buffer)) - idx - 0x04;

  add_opcode(LOBYTE(LOWORD(memsetLoc))); add_opcode(HIBYTE(LOWORD(memsetLoc))); 
  add_opcode(LOBYTE(HIWORD(memsetLoc))); add_opcode(HIBYTE(HIWORD(memsetLoc))); // call memset
  add_opcode(0x83); add_opcode(0xc4); add_opcode(0x0c); // add esp, 0x0c    
  // PROLOG

  std::stack<std::pair<unsigned int*, std::size_t>> loops;

  std::string::const_iterator end = cleanedCode.end();
  for(std::string::const_iterator it = cleanedCode.begin(); it != end; ++it)
  {
    switch(*it)
    {
    case '+':
      add_opcode(0x8B); add_opcode(0x85); add_opcode(0x34); add_opcode(0xF4); add_opcode(0xFF); add_opcode(0xFF); // mov eax, dword ptr [ebp-0xbcc]
      add_opcode(0x8A); add_opcode(0x08); // mov cl, byte ptr [eax]
      add_opcode(0xFE); add_opcode(0xC1); // inc cl
      add_opcode(0x8B); add_opcode(0x95); add_opcode(0x34); add_opcode(0xF4); add_opcode(0xFF); add_opcode(0xFF); // mov edx, dword ptr [ebp-0xbcc]
      add_opcode(0x88); add_opcode(0x0A); // mov byte ptr [edx], cl
      break;
    case '-':
      add_opcode(0x8B); add_opcode(0x85); add_opcode(0x34); add_opcode(0xF4); add_opcode(0xFF); add_opcode(0xFF); // mov eax, dword ptr [ebp-0xbcc]
      add_opcode(0x8A); add_opcode(0x08); // mov cl, byte ptr [eax]
      add_opcode(0xFE); add_opcode(0xC9); // dec cl
      add_opcode(0x8B); add_opcode(0x95); add_opcode(0x34); add_opcode(0xF4); add_opcode(0xFF); add_opcode(0xFF); // mov edx, dword ptr [ebp-0xbcc]
      add_opcode(0x88); add_opcode(0x0A); // mov byte ptr [edx], cl
      break;
    case '>':
      add_opcode(0x8B); add_opcode(0x85); add_opcode(0x34); add_opcode(0xF4); add_opcode(0xFF); add_opcode(0xFF); // mov eax, dword ptr [ebp-0xbcc]
      add_opcode(0x40); // inc eax
      add_opcode(0x89); add_opcode(0x85); add_opcode(0x34); add_opcode(0xF4); add_opcode(0xFF); add_opcode(0xFF); // mov dword ptr [ebp-0xbcc], eax
      break;
    case '<':
      add_opcode(0x8B); add_opcode(0x85); add_opcode(0x34); add_opcode(0xF4); add_opcode(0xFF); add_opcode(0xFF); // mov eax, dword ptr [ebp-0xbcc]
      add_opcode(0x48); // dec eax
      add_opcode(0x89); add_opcode(0x85); add_opcode(0x34); add_opcode(0xF4); add_opcode(0xFF); add_opcode(0xFF); // mov dword ptr [ebp-0xbcc], eax
      break;
    case '.':
      {
      add_opcode(0x8B); add_opcode(0x85); add_opcode(0x34); add_opcode(0xF4); add_opcode(0xFF); add_opcode(0xFF); // mov eax, dword ptr [ebp-0xbcc]
      add_opcode(0x0f); add_opcode(0xbe); add_opcode(0x08); // movsx ecx, byte ptr [eax]
      add_opcode(0x51); // push ecx

      add_opcode(0xe8);
      UINT_PTR putcharLoc = (putcharIlt - reinterpret_cast<UINT_PTR>(buffer)) - idx - 0x04;

      add_opcode(LOBYTE(LOWORD(putcharLoc))); add_opcode(HIBYTE(LOWORD(putcharLoc))); 
      add_opcode(LOBYTE(HIWORD(putcharLoc))); add_opcode(HIBYTE(HIWORD(putcharLoc))); // call putchar

      add_opcode(0x83); add_opcode(0xc4); add_opcode(0x04); // add esp, 4
      }
      break;
    case ',':
      {
      add_opcode(0xe8);      
      UINT_PTR getcharLoc = (getcharIlt - reinterpret_cast<UINT_PTR>(buffer)) - idx - 0x04;      

      add_opcode(LOBYTE(LOWORD(getcharLoc))); add_opcode(HIBYTE(LOWORD(getcharLoc))); 
      add_opcode(LOBYTE(HIWORD(getcharLoc))); add_opcode(HIBYTE(HIWORD(getcharLoc))); // call getchar
      add_opcode(0x8B); add_opcode(0x8d); add_opcode(0x34); add_opcode(0xf4); add_opcode(0xff); add_opcode(0xff); // mov ecx, dword ptr [ebp-0xbcc]
      add_opcode(0x88); add_opcode(0x01); // mov byte ptr [ecx], al
      }
      break;
    case '[':            
      {
      unsigned int *endLoop = 0;
      std::pair<unsigned int*, std::size_t> pair(endLoop, idx);
      add_opcode(0x8B); add_opcode(0x8d); add_opcode(0x34); add_opcode(0xf4); add_opcode(0xff); add_opcode(0xff); // mov ecx, dword ptr [ebp-0xbcc]
      add_opcode(0x0f); add_opcode(0xbe); add_opcode(0x08); // movsx ecx, byte ptr [eax]      
      add_opcode(0x85); add_opcode(0xc9); // test ecx, ecx
      add_opcode(0x0f); add_opcode(0x84); add_opcode(0x00); add_opcode(0x00); add_opcode(0x00); add_opcode(0x00); // je short ]
      pair.first = reinterpret_cast<unsigned int*>(&walker[idx-4]);
      loops.push(pair);
      }
      break;
    case ']':
      {
      std::pair<unsigned int*, std::size_t> pair = loops.top();
      loops.pop();
      unsigned int offset = 0xFFFFFFFF - (idx - pair.second) - 4;
      add_opcode(0xe9); add_opcode(LOBYTE(LOWORD(offset))); add_opcode(HIBYTE(LOWORD(offset))); add_opcode(LOBYTE(HIWORD(offset)));
        add_opcode(HIBYTE(HIWORD(offset))); // jmp short [
      *pair.first = static_cast<unsigned int>(idx - pair.second) - 17;
      }
      break;
    default: _asm int 3;
    }
  }

  // EPILOG
  add_opcode(0x89); 
  add_opcode(0xEC); // mov esp, ebp
  add_opcode(0x5D); // pop ebp
  add_opcode(0xC3); // ret
  // EPILOG
#undef add_opcode

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